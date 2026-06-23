"""
Auth module: password hashing, JWT creation/verification,
and FastAPI router with /auth/register and /auth/login endpoints.
"""

import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from models import SessionLocal, User, Alert, Log, AnalystReport

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-in-production-please")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# ── Helpers ───────────────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
router = APIRouter(prefix="/auth", tags=["auth"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _safe_password(password: str) -> str:
    """Truncate to 72 bytes (bcrypt hard limit) to prevent ValueError."""
    encoded = password.encode("utf-8")
    return encoded[:72].decode("utf-8", errors="ignore")


def hash_password(password: str) -> str:
    return pwd_context.hash(_safe_password(password))


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(_safe_password(plain), hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Decode the JWT, then **actively verify** the user still exists in the
    database.  A mathematically valid token for a deleted/missing user (a
    "Ghost Token") is rejected with 401 so the frontend can force a re-login."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # ── Ghost-Token guard ──────────────────────────────────────────────────
    # The JWT signature is valid, but the user it references may no longer
    # exist (e.g. the database was wiped, or the account was deleted).
    # Raise a *distinct* 401 so it is easy to spot in logs.
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is no longer valid — please log in again",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_user_by_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> User:
    """Authenticates log-shipping agents via the X-API-Key header instead of
    a JWT — agents aren't browser sessions and shouldn't need to log in."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    user = db.query(User).filter(User.api_key == x_api_key).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return user


def generate_api_key() -> str:
    """Generates a random API key for log-shipping agents, e.g. aegis_live_<32 hex chars>."""
    return f"aegis_live_{secrets.token_hex(16)}"


# ── Schemas ───────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: str
    username: str
    password: str
    full_name: Optional[str] = None

    @field_validator("password")
    @classmethod
    def password_length(cls, v: str) -> str:
        if len(v.encode("utf-8")) > 72:
            raise ValueError("Password must be 72 characters or fewer")
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# ── Routes ────────────────────────────────────────────────────────────────────
@router.post("/register", status_code=201)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    user = User(
        email=body.email,
        username=body.username,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
        plan="free",
        created_at=datetime.utcnow(),
        api_key=generate_api_key(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.email})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "plan": user.plan,
            "api_key": user.api_key,
        },
    }


@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.api_key:
        user.api_key = generate_api_key()
        db.commit()

    token = create_access_token({"sub": user.email})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "plan": user.plan,
            "api_key": user.api_key,
        },
    }


@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "plan": current_user.plan,
        "api_key": current_user.api_key,
        "created_at": current_user.created_at.isoformat(),
    }


@router.post("/regenerate-api-key")
def regenerate_api_key(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Invalidates the old key and issues a new one."""
    current_user.api_key = generate_api_key()
    db.commit()
    return {"api_key": current_user.api_key}


@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    current_user.hashed_password = hash_password(body.new_password)
    db.commit()
    return {"detail": "Password updated successfully"}


@router.delete("/me", status_code=200)
def delete_account(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Permanently delete the authenticated user and all data they own."""
    alert_ids = [a.id for a in db.query(Alert.id).filter(Alert.owner_id == current_user.id).all()]
    if alert_ids:
        db.query(AnalystReport).filter(AnalystReport.alert_id.in_(alert_ids)).delete(
            synchronize_session=False
        )
    db.query(Alert).filter(Alert.owner_id == current_user.id).delete(synchronize_session=False)
    db.query(Log).filter(Log.owner_id == current_user.id).delete(synchronize_session=False)
    db.delete(current_user)
    db.commit()
    return {"detail": "Account deleted successfully"}