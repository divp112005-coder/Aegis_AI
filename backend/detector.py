"""
Detector job: runs periodically and checks for 5 threat patterns,
PER USER (owner_id), creating an Alert scoped to that user when found:

  1. brute_force          - 5+ failed logins from one IP in 1 minute
  2. geo_anomaly           - login_success from a country not seen before for that user
  3. off_hours_login       - login_success between 00:00-05:00 UTC
  4. privilege_escalation  - privilege_change within 5 min of a login_success
  5. impossible_travel     - same user, login_success from 2 different countries within 10 min
"""

import time
from datetime import datetime, timedelta

from sqlalchemy import func

from models import SessionLocal, Log, Alert, User, init_db

FAILED_LOGIN_THRESHOLD = 5
LOOKBACK_MINUTES = 1
DEDUPE_WINDOW_MINUTES = 5  # don't re-alert on the same IP/type within this window

GEO_LOOKBACK_DAYS = 30          # how far back to check "known" countries for geo_anomaly
TRAVEL_WINDOW_MINUTES = 10      # max gap for impossible_travel
PRIV_ESCALATION_WINDOW_MINUTES = 5
SCAN_WINDOW_MINUTES = 2         # general lookback window for the newer rules each cycle


def _alert_already_exists(session, owner_id, alert_type, source_ip, username=None):
    dedupe_cutoff = datetime.utcnow() - timedelta(minutes=DEDUPE_WINDOW_MINUTES)
    q = session.query(Alert).filter(
        Alert.owner_id == owner_id,
        Alert.alert_type == alert_type,
        Alert.source_ip == source_ip,
        Alert.created_at >= dedupe_cutoff,
    )
    if username:
        q = q.filter(Alert.username == username)
    return q.first() is not None


def _create_alert(session, owner_id, alert_type, source_ip, username, details: str, severity="medium"):
    alert = Alert(
        owner_id=owner_id,
        created_at=datetime.utcnow(),
        alert_type=alert_type,
        source_ip=source_ip,
        username=username,
        severity=severity,
        status="open",
        details=details,
    )
    session.add(alert)
    session.commit()
    print(f"[ALERT CREATED] owner_id={owner_id} type={alert_type} ip={source_ip} user={username}")

    try:
        from ai_analyst import analyze_alert
        analyze_alert(alert.id)
    except Exception as e:
        print(f"[AI ANALYST ERROR] {e}")


# ── Rule 1: Brute force ──────────────────────────────────────────────────────

def check_brute_force(session, owner_id: int):
    cutoff = datetime.utcnow() - timedelta(minutes=LOOKBACK_MINUTES)
    results = (
        session.query(Log.source_ip, Log.username, func.count(Log.id).label("fail_count"))
        .filter(Log.owner_id == owner_id, Log.event_type == "login_failed", Log.timestamp >= cutoff)
        .group_by(Log.source_ip, Log.username)
        .having(func.count(Log.id) >= FAILED_LOGIN_THRESHOLD)
        .all()
    )
    for source_ip, username, fail_count in results:
        if _alert_already_exists(session, owner_id, "brute_force", source_ip, username):
            continue
        _create_alert(
            session, owner_id, "brute_force", source_ip, username,
            details=f'{{"fail_count": {fail_count}, "window_minutes": {LOOKBACK_MINUTES}}}',
        )


# ── Rule 2: Geo anomaly ──────────────────────────────────────────────────────

def check_geo_anomaly(session, owner_id: int):
    cutoff = datetime.utcnow() - timedelta(minutes=SCAN_WINDOW_MINUTES)
    history_cutoff = datetime.utcnow() - timedelta(days=GEO_LOOKBACK_DAYS)

    recent_logins = (
        session.query(Log)
        .filter(
            Log.owner_id == owner_id,
            Log.event_type == "login_success",
            Log.timestamp >= cutoff,
        )
        .all()
    )

    for log in recent_logins:
        if not log.username or not log.geo_location or log.geo_location == "Internal-Office":
            continue  # internal logins are never geo-anomalous in this simple model

        known_geo = (
            session.query(Log.geo_location)
            .filter(
                Log.owner_id == owner_id,
                Log.username == log.username,
                Log.event_type == "login_success",
                Log.timestamp >= history_cutoff,
                Log.timestamp < log.timestamp,
                Log.geo_location == log.geo_location,
            )
            .first()
        )
        if known_geo:
            continue  # this user has used this location before, not anomalous

        if _alert_already_exists(session, owner_id, "geo_anomaly", log.source_ip, log.username):
            continue

        _create_alert(
            session, owner_id, "geo_anomaly", log.source_ip, log.username,
            details=f'{{"geo_location": "{log.geo_location}"}}',
        )


# ── Rule 3: Off-hours login ──────────────────────────────────────────────────

def check_off_hours_login(session, owner_id: int):
    cutoff = datetime.utcnow() - timedelta(minutes=SCAN_WINDOW_MINUTES)
    recent_logins = (
        session.query(Log)
        .filter(
            Log.owner_id == owner_id,
            Log.event_type == "login_success",
            Log.timestamp >= cutoff,
        )
        .all()
    )
    for log in recent_logins:
        if log.timestamp.hour not in (0, 1, 2, 3, 4):
            continue
        if _alert_already_exists(session, owner_id, "off_hours_login", log.source_ip, log.username):
            continue
        _create_alert(
            session, owner_id, "off_hours_login", log.source_ip, log.username,
            details=f'{{"login_hour_utc": {log.timestamp.hour}}}',
        )


# ── Rule 4: Privilege escalation ─────────────────────────────────────────────

def check_privilege_escalation(session, owner_id: int):
    cutoff = datetime.utcnow() - timedelta(minutes=SCAN_WINDOW_MINUTES)
    priv_changes = (
        session.query(Log)
        .filter(
            Log.owner_id == owner_id,
            Log.event_type == "privilege_change",
            Log.timestamp >= cutoff,
        )
        .all()
    )
    for change in priv_changes:
        window_start = change.timestamp - timedelta(minutes=PRIV_ESCALATION_WINDOW_MINUTES)
        recent_login = (
            session.query(Log)
            .filter(
                Log.owner_id == owner_id,
                Log.username == change.username,
                Log.event_type == "login_success",
                Log.timestamp >= window_start,
                Log.timestamp <= change.timestamp,
            )
            .first()
        )
        if not recent_login:
            continue
        if _alert_already_exists(session, owner_id, "privilege_escalation", change.source_ip, change.username):
            continue
        _create_alert(
            session, owner_id, "privilege_escalation", change.source_ip, change.username,
            details=f'{{"login_at": "{recent_login.timestamp.isoformat()}", "escalation_at": "{change.timestamp.isoformat()}"}}',
        )


# ── Rule 5: Impossible travel ────────────────────────────────────────────────

def check_impossible_travel(session, owner_id: int):
    cutoff = datetime.utcnow() - timedelta(minutes=SCAN_WINDOW_MINUTES)
    recent_logins = (
        session.query(Log)
        .filter(
            Log.owner_id == owner_id,
            Log.event_type == "login_success",
            Log.timestamp >= cutoff,
        )
        .order_by(Log.timestamp)
        .all()
    )

    by_user = {}
    for log in recent_logins:
        if not log.username:
            continue
        by_user.setdefault(log.username, []).append(log)

    for username, logs in by_user.items():
        for i in range(len(logs) - 1):
            a, b = logs[i], logs[i + 1]
            if a.geo_location == b.geo_location:
                continue
            if a.geo_location == "Internal-Office" or b.geo_location == "Internal-Office":
                continue
            gap = (b.timestamp - a.timestamp).total_seconds() / 60
            if gap > TRAVEL_WINDOW_MINUTES:
                continue
            if _alert_already_exists(session, owner_id, "impossible_travel", b.source_ip, username):
                continue
            _create_alert(
                session, owner_id, "impossible_travel", b.source_ip, username,
                details=f'{{"from": "{a.geo_location}", "to": "{b.geo_location}", "gap_minutes": {round(gap, 1)}}}',
            )


# ── Orchestration ────────────────────────────────────────────────────────────

def check_brute_force_for_user(session, owner_id: int):
    """Kept for backward compatibility with main.py's /demo/seed endpoint,
    which calls this name directly. Now runs all 5 rules for that user."""
    check_brute_force(session, owner_id)
    check_geo_anomaly(session, owner_id)
    check_off_hours_login(session, owner_id)
    check_privilege_escalation(session, owner_id)
    check_impossible_travel(session, owner_id)


def run_detection_cycle(session):
    """Run all detection rules for every active user in the system."""
    user_ids = [u.id for u in session.query(User.id).all()]
    for owner_id in user_ids:
        check_brute_force_for_user(session, owner_id)


def run_loop(interval=10):
    init_db()
    print(f"Detector running every {interval}s across all users (5 rule types). Ctrl+C to stop.")
    try:
        while True:
            session = SessionLocal()
            try:
                run_detection_cycle(session)
            finally:
                session.close()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    run_loop()
