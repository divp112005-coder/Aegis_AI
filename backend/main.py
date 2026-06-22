from datetime import datetime
from typing import Optional, List
import json

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel

from models import SessionLocal, Log, Alert, AnalystReport, User, BlockedIP, init_db
from auth import router as auth_router, get_current_user, get_user_by_api_key

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
    current_user: User = Depends(get_current_user),
):
    query = db.query(Log).filter(Log.owner_id == current_user.id)
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
            "dest_port": l.dest_port,
            "protocol": l.protocol,
            "application": l.application,
            "source": l.source,
        }
        for l in logs
    ]


@app.get("/alerts")
def get_alerts(
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Alert).filter(Alert.owner_id == current_user.id)
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


def _get_owned_alert(db: Session, alert_id: int, current_user: User) -> Alert:
    """Fetch an alert and 404 if it doesn't exist OR doesn't belong to the current user.
    Using 404 (not 403) for unowned alerts avoids leaking which alert IDs exist."""
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.owner_id == current_user.id)
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.delete("/alerts")
def clear_all_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Delete ALL alerts owned by the authenticated user, including their
    AI analyst reports (cascade). Useful for resetting the dashboard
    during development or after a demo run. Irreversible.
    """
    from models import AnalystReport
    # Delete analyst reports first (FK constraint: report.alert_id → alert.id)
    report_ids = (
        db.query(Alert.id)
        .filter(Alert.owner_id == current_user.id)
        .subquery()
    )
    db.query(AnalystReport).filter(AnalystReport.alert_id.in_(report_ids)).delete(
        synchronize_session="fetch"
    )
    deleted = (
        db.query(Alert)
        .filter(Alert.owner_id == current_user.id)
        .delete(synchronize_session="fetch")
    )
    db.commit()
    return {"deleted": deleted}


@app.get("/alerts/{alert_id}")
def get_alert_detail(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = _get_owned_alert(db, alert_id, current_user)

    report = None
    if alert.report:
        report = {
            "summary": alert.report.summary,
            "severity": alert.report.severity,
            "mitre_technique": alert.report.mitre_technique,
            "recommended_action": alert.report.recommended_action,
            "created_at": alert.report.created_at.isoformat(),
        }

    # Pull related logs for context (same source_ip, same owner)
    # Pull related logs for context. IP-centric alerts (brute_force) show activity
    # from that IP; account-centric alerts (geo_anomaly, off_hours_login,
    # privilege_escalation, impossible_travel) show that user's recent activity instead.
    log_query = db.query(Log).filter(Log.owner_id == current_user.id)
    if alert.alert_type == "brute_force" or not alert.username:
        log_query = log_query.filter(Log.source_ip == alert.source_ip)
    else:
        log_query = log_query.filter(Log.username == alert.username)

    related_logs = log_query.order_by(desc(Log.timestamp)).limit(20).all()

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
    current_user: User = Depends(get_current_user),
):
    alert = _get_owned_alert(db, alert_id, current_user)

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
    current_user: User = Depends(get_current_user),
):
    if new_status not in ("open", "approved", "dismissed"):
        raise HTTPException(status_code=400, detail="Invalid status")
    alert = _get_owned_alert(db, alert_id, current_user)
    alert.status = new_status
    db.commit()

    block_result = None

    if new_status == "approved":
        # Approve = simulated SOAR action: record the IP as "blocked" in our
        # own block-list table. This does NOT touch any real firewall or
        # network device — it's a demonstration of the human-in-the-loop
        # response workflow, not an actual network control.
        existing_block = (
            db.query(BlockedIP)
            .filter(
                BlockedIP.owner_id == current_user.id,
                BlockedIP.ip_address == alert.source_ip,
                BlockedIP.status == "blocked",
            )
            .first()
        )

        if existing_block:
            block_result = {"action": "already_blocked", "ip_address": alert.source_ip}
        else:
            blocked_ip = BlockedIP(
                owner_id=current_user.id,
                alert_id=alert.id,
                ip_address=alert.source_ip,
                status="blocked",
                firewall_rule_name=f"SIMULATED_{alert.source_ip}",
                blocked_at=datetime.utcnow(),
                error_message=None,
            )
            db.add(blocked_ip)
            db.commit()
            block_result = {"action": "blocked", "ip_address": alert.source_ip, "simulated": True}

    elif new_status == "dismissed":
        block_result = {"action": "ignored", "ip_address": alert.source_ip}

    return {"id": alert.id, "status": alert.status, "block_result": block_result}


@app.get("/blocked-ips")
def list_blocked_ips(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    blocks = (
        db.query(BlockedIP)
        .filter(BlockedIP.owner_id == current_user.id)
        .order_by(desc(BlockedIP.blocked_at))
        .all()
    )
    return [
        {
            "id": b.id,
            "alert_id": b.alert_id,
            "ip_address": b.ip_address,
            "status": b.status,
            "blocked_at": b.blocked_at.isoformat(),
            "unblocked_at": b.unblocked_at.isoformat() if b.unblocked_at else None,
        }
        for b in blocks
    ]


@app.post("/blocked-ips/{block_id}/unblock")
def unblock_ip_endpoint(
    block_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    block = (
        db.query(BlockedIP)
        .filter(BlockedIP.id == block_id, BlockedIP.owner_id == current_user.id)
        .first()
    )
    if not block:
        raise HTTPException(status_code=404, detail="Blocked IP record not found")
    if block.status != "blocked":
        raise HTTPException(status_code=400, detail=f"IP is not currently blocked (status={block.status})")

    # Simulated unblock — just flips the DB record, no real network action.
    block.status = "unblocked"
    block.unblocked_at = datetime.utcnow()
    db.commit()
    return {"id": block.id, "status": block.status}


# ── Demo seed ────────────────────────────────────────────────────────────────
from pydantic import BaseModel as PydanticModel

class SeedRequest(PydanticModel):
    include_attack: bool = True


@app.post("/demo/seed")
def seed_demo_data(
    body: SeedRequest = SeedRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate sample log data (and trigger the detector) for the current user.
    Each call adds a fresh batch of normal traffic plus ONE randomly chosen
    attack scenario (brute_force, geo_anomaly, off_hours_login,
    privilege_escalation, or impossible_travel) — safe to call repeatedly
    to build up a varied alert feed.
    """
    from log_generator import generate_normal_batch, generate_random_scenario

    # 1. Generate logs attributed to this user
    normal_count = 25
    generate_normal_batch(db, current_user.id, count=normal_count)

    scenario_triggered = None
    if body.include_attack:
        scenario_triggered = generate_random_scenario(db, current_user.id)

    # 2. Run all 5 detection rules immediately for this user so alerts appear
    try:
        from detector import check_brute_force_for_user
        check_brute_force_for_user(db, current_user.id)
    except Exception:
        pass  # detector is best-effort; logs are still saved

    # 3. Count resulting alerts for the response
    alert_count = db.query(Alert).filter(Alert.owner_id == current_user.id).count()

    return {
        "logs_created": normal_count,
        "attack_simulated": body.include_attack,
        "scenario_type": scenario_triggered,
        "total_alerts": alert_count,
    }


# ── Real log ingestion ──────────────────────────────────────────────────────
# Authenticated via X-API-Key header (not user JWT), since log-shipping agents
# are unattended processes, not browser sessions. See /auth/me for a user's key.

class IngestEvent(BaseModel):
    timestamp: Optional[str] = None  # ISO 8601; defaults to "now" if omitted
    source_ip: str
    username: Optional[str] = None
    event_type: str  # login_success | login_failed | file_access | privilege_change | logout
    raw: Optional[dict] = None  # original unparsed event, stored for audit/debugging

VALID_EVENT_TYPES = {
    "login_success", "login_failed", "file_access",
    "privilege_change", "logout",
    "network_connection", "network_connection_blocked",
    "packet_capture",  # experimental: scapy-based packet-level monitoring
}


class IngestBatch(BaseModel):
    events: List[IngestEvent]
    source: str = "real"  # free-text label, e.g. "windows_event_log", "auth_log"


def _geo_for_ip(ip: str) -> str:
    from log_generator import geo_for_ip
    return geo_for_ip(ip)


@app.post("/ingest/logs")
def ingest_logs(
    body: IngestBatch,
    db: Session = Depends(get_db),
    agent_user: User = Depends(get_user_by_api_key),
):
    """
    Real log ingestion endpoint for agents (e.g. the Windows Event Log
    tailer in agent/windows_event_tailer.py). Accepts a batch of normalized
    events and writes them as Log rows owned by the API-key's user.
    """
    if not body.events:
        raise HTTPException(status_code=400, detail="events list cannot be empty")
    if len(body.events) > 500:
        raise HTTPException(status_code=400, detail="Max 500 events per batch")

    inserted = 0
    skipped = []

    for i, event in enumerate(body.events):
        if event.event_type not in VALID_EVENT_TYPES:
            skipped.append({"index": i, "reason": f"invalid event_type: {event.event_type}"})
            continue

        try:
            ts = datetime.fromisoformat(event.timestamp) if event.timestamp else datetime.utcnow()
        except ValueError:
            skipped.append({"index": i, "reason": f"invalid timestamp: {event.timestamp}"})
            continue

        raw_dict = event.raw or {}
        log = Log(
            owner_id=agent_user.id,
            timestamp=ts,
            source_ip=event.source_ip,
            username=event.username,
            event_type=event.event_type,
            geo_location=_geo_for_ip(event.source_ip),
            raw=json.dumps(raw_dict) if raw_dict else None,
            source=body.source,
            # Network-specific fields — populated for network connection and
            # packet_capture events. The agent puts these in the raw dict
            # under standardised keys.
            dest_port=raw_dict.get("dest_port") if event.event_type in ("network_connection", "network_connection_blocked", "packet_capture") else None,
            protocol=raw_dict.get("protocol") if event.event_type in ("network_connection", "network_connection_blocked", "packet_capture") else None,
            application=raw_dict.get("application") if event.event_type in ("network_connection", "network_connection_blocked", "packet_capture") else None,
        )
        db.add(log)
        inserted += 1

    db.commit()

    return {
        "inserted": inserted,
        "skipped": skipped,
        "owner": agent_user.username,
    }
