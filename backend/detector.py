"""
Detector job: runs periodically, checks for brute-force patterns
(5+ failed logins from the same source IP within the last minute)
PER USER (owner_id), and creates an Alert scoped to that user if one
doesn't already exist for that IP recently.
"""

import time
from datetime import datetime, timedelta

from sqlalchemy import func

from models import SessionLocal, Log, Alert, User, init_db

FAILED_LOGIN_THRESHOLD = 5
LOOKBACK_MINUTES = 1
DEDUPE_WINDOW_MINUTES = 5  # don't re-alert on the same IP within this window


def check_brute_force_for_user(session, owner_id: int):
    cutoff = datetime.utcnow() - timedelta(minutes=LOOKBACK_MINUTES)

    # Count failed logins per source_ip in the lookback window, scoped to this user's logs
    results = (
        session.query(Log.source_ip, Log.username, func.count(Log.id).label("fail_count"))
        .filter(
            Log.owner_id == owner_id,
            Log.event_type == "login_failed",
            Log.timestamp >= cutoff,
        )
        .group_by(Log.source_ip, Log.username)
        .having(func.count(Log.id) >= FAILED_LOGIN_THRESHOLD)
        .all()
    )

    for source_ip, username, fail_count in results:
        dedupe_cutoff = datetime.utcnow() - timedelta(minutes=DEDUPE_WINDOW_MINUTES)
        existing = (
            session.query(Alert)
            .filter(
                Alert.owner_id == owner_id,
                Alert.source_ip == source_ip,
                Alert.alert_type == "brute_force",
                Alert.created_at >= dedupe_cutoff,
            )
            .first()
        )
        if existing:
            continue  # already alerted recently, skip

        alert = Alert(
            owner_id=owner_id,
            created_at=datetime.utcnow(),
            alert_type="brute_force",
            source_ip=source_ip,
            username=username,
            severity="medium",  # placeholder until AI analyst assigns one
            status="open",
            details=f'{{"fail_count": {fail_count}, "window_minutes": {LOOKBACK_MINUTES}}}',
        )
        session.add(alert)
        session.commit()
        print(f"[ALERT CREATED] owner_id={owner_id} brute_force from {source_ip} (user={username}, fails={fail_count})")

        # Trigger AI analysis - import here to avoid circular import issues
        try:
            from ai_analyst import analyze_alert
            analyze_alert(alert.id)
        except Exception as e:
            print(f"[AI ANALYST ERROR] {e}")


def run_detection_cycle(session):
    """Run detection for every active user in the system."""
    user_ids = [u.id for u in session.query(User.id).all()]
    for owner_id in user_ids:
        check_brute_force_for_user(session, owner_id)


def run_loop(interval=10):
    init_db()
    print(f"Detector running every {interval}s across all users. Ctrl+C to stop.")
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
