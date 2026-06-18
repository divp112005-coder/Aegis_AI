from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc

from models import SessionLocal, Log, Alert, AnalystReport, User, init_db
from auth import router as auth_router, get_current_user

app = FastAPI(title="Aegis AI", version="0.1.0")

app.include_router(auth_router)

# Allow the React frontend (running on a different port) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {"status": "ok", "service": "Aegis AI backend"}


@app.get("/logs")
def get_logs(
    limit: int = Query(100, le=1000),
    source_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = db.query(Log)
    if source_ip:
        query = query.filter(Log.source_ip == source_ip)
    if event_type:
        query = query.filter(Log.event_type == event_type)
    logs = query.order_by(desc(Log.timestamp)).limit(limit).all()
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat(),
            "source_ip": l.source_ip,
            "username": l.username,
            "event_type": l.event_type,
            "geo_location": l.geo_location,
        }
        for l in logs
    ]


@app.get("/alerts")
def get_alerts(
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = db.query(Alert)
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    alerts = query.order_by(desc(Alert.created_at)).all()
    return [
        {
            "id": a.id,
            "created_at": a.created_at.isoformat(),
            "alert_type": a.alert_type,
            "source_ip": a.source_ip,
            "username": a.username,
            "severity": a.severity,
            "status": a.status,
            "has_report": a.report is not None,
        }
        for a in alerts
    ]


@app.get("/alerts/{alert_id}")
def get_alert_detail(
    alert_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    report = None
    if alert.report:
        report = {
            "summary": alert.report.summary,
            "severity": alert.report.severity,
            "mitre_technique": alert.report.mitre_technique,
            "recommended_action": alert.report.recommended_action,
            "created_at": alert.report.created_at.isoformat(),
        }

    # Pull related logs for context (same source_ip)
    related_logs = (
        db.query(Log)
        .filter(Log.source_ip == alert.source_ip)
        .order_by(desc(Log.timestamp))
        .limit(20)
        .all()
    )

    return {
        "id": alert.id,
        "created_at": alert.created_at.isoformat(),
        "alert_type": alert.alert_type,
        "source_ip": alert.source_ip,
        "username": alert.username,
        "severity": alert.severity,
        "status": alert.status,
        "details": alert.details,
        "report": report,
        "related_logs": [
            {
                "id": l.id,
                "timestamp": l.timestamp.isoformat(),
                "username": l.username,
                "event_type": l.event_type,
                "geo_location": l.geo_location,
            }
            for l in related_logs
        ],
    }


@app.post("/alerts/{alert_id}/analyze")
def trigger_analysis(
    alert_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    from ai_analyst import analyze_alert
    analyze_alert(alert_id)

    db.refresh(alert)
    report = alert.report
    return {
        "alert_id": alert.id,
        "severity": alert.severity,
        "report": {
            "summary": report.summary,
            "severity": report.severity,
            "mitre_technique": report.mitre_technique,
            "recommended_action": report.recommended_action,
        } if report else None,
    }


@app.post("/alerts/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    new_status: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    if new_status not in ("open", "approved", "dismissed"):
        raise HTTPException(status_code=400, detail="Invalid status")
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = new_status
    db.commit()
    return {"id": alert.id, "status": alert.status}