"""
Detector job: runs periodically and checks for 10 threat patterns,
PER USER (owner_id), creating an Alert scoped to that user when found:

  Auth/identity rules:
  1. brute_force          - 5+ failed logins from one IP in 1 minute
  2. geo_anomaly           - login_success from a country not seen before for that user
  3. off_hours_login       - login_success between 00:00-05:00 UTC
  4. privilege_escalation  - privilege_change within 5 min of a login_success (external IP only)
  5. impossible_travel     - same user, login_success from 2 different countries within 10 min

  Network rules (require windows_event_tailer with 5156/5157 events enabled):
  6. port_scan             - one IP hits 10+ distinct destination ports within 2 minutes
  7. suspicious_port       - connection to a known-bad port (Metasploit defaults, RAT ports, etc.)
  8. connection_volume     - one source IP makes 50+ distinct outbound connections in 5 minutes

  Packet-capture rules (require packet_monitor.py / scapy-based agent):
  9. syn_flood             - abnormally high TCP SYN count from one source IP in 1 minute (>100)
  10. dns_tunneling        - abnormally high DNS query count from one source IP in 1 minute (>50)
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

# Network rule thresholds
PORT_SCAN_DISTINCT_PORTS = 10       # distinct destination ports from one IP within the window
PORT_SCAN_WINDOW_MINUTES = 2
CONNECTION_VOLUME_THRESHOLD = 50    # distinct outbound connections from one IP within the window
CONNECTION_VOLUME_WINDOW_MINUTES = 5

# Packet-capture rule thresholds (scapy agent)
SYN_FLOOD_THRESHOLD = 100           # TCP SYN packets from one IP within 1 minute
DNS_TUNNEL_THRESHOLD = 50           # DNS queries from one IP within 1 minute
PACKET_WINDOW_MINUTES = 1

SUSPICIOUS_PORTS = {
    4444,   # Metasploit default listener
    31337,  # classic "elite" backdoor port
    1337,   # common RAT/backdoor
    6666, 6667,  # IRC-based C2
    12345,  # NetBus RAT
    54321,  # common reverse shell
    8081,   # alternative HTTP often used for exfil
    9001,   # Tor default / common C2
    3389,   # RDP - suspicious if outbound from a workstation
    5900,   # VNC
    23,     # Telnet - unencrypted, rarely legitimate today
}


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

    # AI analysis is intentionally NOT triggered automatically here.
    # It runs on-demand only: POST /alerts/{id}/analyze in the frontend
    # (the "Run Analysis" button in the alert detail drawer). This avoids
    # exhausting the Groq free-tier rate limit during repeated test runs.


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
    """
    Flags a privilege_change shortly after a login_success for the same
    account — but only when the source IP is external (not localhost / not
    an internal office IP). Windows Event ID 4672 ("special privileges
    assigned") fires on nearly every routine interactive logon — including
    the machine's own normal logons by SYSTEM and the device owner — so
    using it as a signal on its own, without the external-IP gate, produces
    constant false positives on a single test machine.

    In a real deployment this rule is most meaningful for network/remote
    logons (Logon Type 3/10) from outside the trusted network escalating
    privileges shortly after authenticating — that's the actual compromise
    pattern this rule is meant to catch.
    """
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

        is_external_ip = change.source_ip != "127.0.0.1" and change.geo_location not in (None, "Internal-Office", "Unknown")

        # Only alert when the source IP is external — the meaningful risk
        # factor for this rule. Local/loopback privilege assignment (SYSTEM,
        # the device owner's own account, etc.) is normal Windows background
        # activity, not an attack signal.
        if not is_external_ip:
            continue

        if _alert_already_exists(session, owner_id, "privilege_escalation", change.source_ip, change.username):
            continue
        _create_alert(
            session, owner_id, "privilege_escalation", change.source_ip, change.username,
            details=f'{{"login_at": "{recent_login.timestamp.isoformat()}", "escalation_at": "{change.timestamp.isoformat()}", "external_ip": {str(is_external_ip).lower()}}}',
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


# ── Rule 6: Port scan ────────────────────────────────────────────────────────

def check_port_scan(session, owner_id: int):
    """
    Flags a source IP that connects to many distinct destination ports within
    a short window — classic pattern for network reconnaissance / port scanning.
    Only operates on network_connection events (Windows 5156 via the agent).
    """
    cutoff = datetime.utcnow() - timedelta(minutes=PORT_SCAN_WINDOW_MINUTES)
    results = (
        session.query(Log.source_ip, func.count(Log.dest_port.distinct()).label("port_count"))
        .filter(
            Log.owner_id == owner_id,
            Log.event_type == "network_connection",
            Log.dest_port.isnot(None),
            Log.timestamp >= cutoff,
        )
        .group_by(Log.source_ip)
        .having(func.count(Log.dest_port.distinct()) >= PORT_SCAN_DISTINCT_PORTS)
        .all()
    )
    for source_ip, port_count in results:
        if source_ip in ("127.0.0.1", "0.0.0.0"):
            continue
        if _alert_already_exists(session, owner_id, "port_scan", source_ip):
            continue
        _create_alert(
            session, owner_id, "port_scan", source_ip, None,
            details=f'{{"distinct_ports_scanned": {port_count}, "window_minutes": {PORT_SCAN_WINDOW_MINUTES}}}',
            severity="high",
        )


# ── Rule 7: Suspicious port connection ───────────────────────────────────────

def check_suspicious_port(session, owner_id: int):
    """
    Flags any connection (inbound or outbound) to a port commonly associated
    with malware, RATs, Metasploit listeners, or other attack tooling.
    These are worth investigating regardless of other context.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=SCAN_WINDOW_MINUTES)
    recent_connections = (
        session.query(Log)
        .filter(
            Log.owner_id == owner_id,
            Log.event_type.in_(["network_connection", "network_connection_blocked"]),
            Log.dest_port.in_(list(SUSPICIOUS_PORTS)),
            Log.timestamp >= cutoff,
        )
        .all()
    )
    for log in recent_connections:
        if _alert_already_exists(session, owner_id, "suspicious_port", log.source_ip):
            continue
        _create_alert(
            session, owner_id, "suspicious_port", log.source_ip, None,
            details=f'{{"dest_port": {log.dest_port}, "application": "{log.application or "unknown"}", "event_type": "{log.event_type}"}}',
            severity="high",
        )


# ── Rule 8: Connection volume anomaly ─────────────────────────────────────────

def check_connection_volume(session, owner_id: int):
    """
    Flags a source IP that makes an abnormally high number of distinct outbound
    connections in a short window — possible C2 beaconing, data exfiltration,
    or worm-like lateral movement scanning.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=CONNECTION_VOLUME_WINDOW_MINUTES)
    results = (
        session.query(Log.source_ip, func.count(Log.id).label("conn_count"))
        .filter(
            Log.owner_id == owner_id,
            Log.event_type == "network_connection",
            Log.timestamp >= cutoff,
        )
        .group_by(Log.source_ip)
        .having(func.count(Log.id) >= CONNECTION_VOLUME_THRESHOLD)
        .all()
    )
    for source_ip, conn_count in results:
        if source_ip in ("127.0.0.1", "0.0.0.0"):
            continue
        if _alert_already_exists(session, owner_id, "connection_volume", source_ip):
            continue
        _create_alert(
            session, owner_id, "connection_volume", source_ip, None,
            details=f'{{"connection_count": {conn_count}, "window_minutes": {CONNECTION_VOLUME_WINDOW_MINUTES}}}',
            severity="medium",
        )


# ── Rule 9: SYN flood ────────────────────────────────────────────────────────

def check_syn_flood(session, owner_id: int):
    """
    Flags a source IP that sends an abnormally high number of TCP packets
    (identified by protocol="TCP") from the packet_capture stream within a
    1-minute window — consistent with a SYN flood / DoS attack pattern.

    Maps to MITRE T1498 (Network Denial of Service).
    """
    cutoff = datetime.utcnow() - timedelta(minutes=PACKET_WINDOW_MINUTES)
    results = (
        session.query(Log.source_ip, func.count(Log.id).label("pkt_count"))
        .filter(
            Log.owner_id == owner_id,
            Log.event_type == "packet_capture",
            Log.protocol == "TCP",
            Log.timestamp >= cutoff,
        )
        .group_by(Log.source_ip)
        .having(func.count(Log.id) >= SYN_FLOOD_THRESHOLD)
        .all()
    )
    for source_ip, pkt_count in results:
        if source_ip in ("127.0.0.1", "0.0.0.0", "::1"):
            continue
        if _alert_already_exists(session, owner_id, "syn_flood", source_ip):
            continue
        _create_alert(
            session, owner_id, "syn_flood", source_ip, None,
            details=f'{{"packet_count": {pkt_count}, "protocol": "TCP", "window_minutes": {PACKET_WINDOW_MINUTES}}}',
            severity="high",
        )


# ── Rule 10: DNS tunneling heuristic ─────────────────────────────────────────

def check_dns_tunneling(session, owner_id: int):
    """
    Flags a source IP that makes an abnormally high volume of DNS requests
    (dest_port == 53) within a 1-minute window — a common heuristic for
    DNS tunneling or DNS-based C2 communication.

    Maps to MITRE T1071.004 (Application Layer Protocol: DNS).
    """
    cutoff = datetime.utcnow() - timedelta(minutes=PACKET_WINDOW_MINUTES)
    results = (
        session.query(Log.source_ip, func.count(Log.id).label("dns_count"))
        .filter(
            Log.owner_id == owner_id,
            Log.event_type == "packet_capture",
            Log.dest_port == 53,
            Log.timestamp >= cutoff,
        )
        .group_by(Log.source_ip)
        .having(func.count(Log.id) >= DNS_TUNNEL_THRESHOLD)
        .all()
    )
    for source_ip, dns_count in results:
        if source_ip in ("127.0.0.1", "0.0.0.0", "::1"):
            continue
        if _alert_already_exists(session, owner_id, "dns_tunneling", source_ip):
            continue
        _create_alert(
            session, owner_id, "dns_tunneling", source_ip, None,
            details=f'{{"dns_query_count": {dns_count}, "dest_port": 53, "window_minutes": {PACKET_WINDOW_MINUTES}}}',
            severity="high",
        )


# ── Orchestration ────────────────────────────────────────────────────────────

def check_brute_force_for_user(session, owner_id: int):
    """Kept for backward compatibility with main.py's /demo/seed endpoint,
    which calls this name directly. Now runs all 10 rules for that user."""
    check_brute_force(session, owner_id)
    check_geo_anomaly(session, owner_id)
    check_off_hours_login(session, owner_id)
    check_privilege_escalation(session, owner_id)
    check_impossible_travel(session, owner_id)
    check_port_scan(session, owner_id)
    check_suspicious_port(session, owner_id)
    check_connection_volume(session, owner_id)
    check_syn_flood(session, owner_id)
    check_dns_tunneling(session, owner_id)


def run_detection_cycle(session):
    """Run all detection rules for every active user in the system."""
    user_ids = [u.id for u in session.query(User.id).all()]
    for owner_id in user_ids:
        check_brute_force_for_user(session, owner_id)


def run_loop(interval=10):
    init_db()
    print(f"Detector running every {interval}s across all users (10 rule types: 5 auth + 3 network + 2 packet). Ctrl+C to stop.")
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