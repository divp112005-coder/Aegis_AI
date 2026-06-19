from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey, Float, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./aegis.db")

# SQLite needs check_same_thread=False; PostgreSQL doesn't accept that kwarg
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    plan = Column(String, default="free")  # free / pro / enterprise
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    timestamp = Column(DateTime, index=True, nullable=False)
    source_ip = Column(String, index=True, nullable=False)
    username = Column(String, index=True, nullable=True)  # target account in the log line (e.g. "admin")
    event_type = Column(String, index=True, nullable=False)  # e.g. login_success, login_failed
    geo_location = Column(String, nullable=True)
    raw = Column(Text, nullable=True)  # raw JSON string of the full log line

    owner = relationship("User")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    created_at = Column(DateTime, nullable=False)
    alert_type = Column(String, index=True, nullable=False)  # e.g. brute_force, geo_anomaly
    source_ip = Column(String, index=True, nullable=False)
    username = Column(String, nullable=True)  # target account the alert is about (e.g. "admin")
    severity = Column(String, default="unknown")  # low/medium/high/critical
    status = Column(String, default="open")  # open/dismissed/approved
    details = Column(Text, nullable=True)  # JSON string with extra context (e.g. matched log ids)

    owner = relationship("User")
    report = relationship("AnalystReport", back_populates="alert", uselist=False)


class AnalystReport(Base):
    __tablename__ = "analyst_reports"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    created_at = Column(DateTime, nullable=False)
    summary = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)
    recommended_action = Column(Text, nullable=True)
    raw_response = Column(Text, nullable=True)  # full raw response from Groq

    alert = relationship("Alert", back_populates="report")


def init_db():
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_db()
    print("Tables created.")
