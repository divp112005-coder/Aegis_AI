"""
Generates fake security logs and inserts them into the database,
attributed to a specific Aegis AI platform user (owner_id).

Includes scenario generators for 5 detection rule types:
  - brute_force         (many failed logins from one IP)
  - geo_anomaly          (login from a country the user has never logged in from)
  - off_hours_login      (successful login at an unusual local hour)
  - privilege_escalation (privilege_change event shortly after a fresh login)
  - impossible_travel    (same user logs in from two distant countries within minutes)

Run modes:
  python log_generator.py --user-id 1                       -> normal batch
  python log_generator.py --user-id 1 --attack               -> normal batch + ONE random attack scenario
  python log_generator.py --user-id 1 --scenario brute_force -> normal batch + a specific scenario
  python log_generator.py --user-id 1 --loop                 -> continuously generates logs every few seconds
"""

import argparse
import json
import random
import time
from datetime import datetime, timedelta

from models import SessionLocal, Log, User, init_db

USERS = ["alice", "bob", "carol", "dave", "eve", "admin", "svc_backup"]
PRIVILEGED_USERS = ["admin", "svc_backup"]
EVENT_TYPES = ["login_success", "login_failed", "file_access", "privilege_change", "logout"]

# Pool of "normal" IPs (simulate office / VPN ranges)
NORMAL_IPS = [f"10.0.{i}.{j}" for i in range(1, 4) for j in range(1, 20)]

# Pool of "suspicious" external IPs used for attack simulation — grouped by region
# so impossible-travel scenarios can pick two IPs from far-apart regions.
ATTACK_IPS_BY_REGION = {
    "Russia": ["185.220.101.7", "185.220.101.45"],
    "Netherlands": ["45.155.205.233", "45.155.205.112"],
    "Romania": ["194.61.24.102", "194.61.24.88"],
    "Vietnam": ["103.45.246.18", "103.45.246.91"],
    "Brazil": ["177.130.45.9"],
    "Nigeria": ["105.112.34.201"],
}
ALL_ATTACK_IPS = [ip for ips in ATTACK_IPS_BY_REGION.values() for ip in ips]

GEO_MAP = {
    "10.0": "Internal-Office",
    "185.220": "Russia",
    "45.155": "Netherlands",
    "194.61": "Romania",
    "103.45": "Vietnam",
    "177.130": "Brazil",
    "105.112": "Nigeria",
}

SCENARIO_TYPES = ["brute_force", "geo_anomaly", "off_hours_login", "privilege_escalation", "impossible_travel"]


def geo_for_ip(ip: str) -> str:
    prefix = ".".join(ip.split(".")[:2])
    return GEO_MAP.get(prefix, "Unknown")


def make_log(owner_id, timestamp, source_ip, username, event_type) -> Log:
    geo = geo_for_ip(source_ip)
    raw = {
        "timestamp": timestamp.isoformat(),
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "geo_location": geo,
    }
    return Log(
        owner_id=owner_id,
        timestamp=timestamp,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        geo_location=geo,
        raw=json.dumps(raw),
    )


# ── Normal traffic ──────────────────────────────────────────────────────────

def generate_normal_batch(session, owner_id, count=20):
    now = datetime.utcnow()
    logs = []
    for _ in range(count):
        ts = now - timedelta(seconds=random.randint(0, 300))
        ip = random.choice(NORMAL_IPS)
        user = random.choice(USERS)
        event = random.choices(EVENT_TYPES, weights=[60, 10, 15, 5, 10], k=1)[0]
        logs.append(make_log(owner_id, ts, ip, user, event))
    session.add_all(logs)
    session.commit()
    print(f"Inserted {len(logs)} normal logs for owner_id={owner_id}.")


# ── Scenario 1: Brute force ─────────────────────────────────────────────────

def generate_attack_burst(session, owner_id, count=None, target_user=None):
    """Many login_failed from one external IP in a short window.
    Varies fail count (3-15) and target user so severity isn't always identical."""
    now = datetime.utcnow()
    count = count or random.randint(3, 15)
    target_user = target_user or random.choice(USERS)
    # Mix in normal IPs sometimes — an internal account being brute-forced
    # (e.g. compromised VPN) reads differently than a foreign IP attacker.
    attacker_ip = random.choice(ALL_ATTACK_IPS) if random.random() < 0.8 else random.choice(NORMAL_IPS)

    logs = []
    for i in range(count):
        ts = now - timedelta(seconds=random.randint(0, 50))
        logs.append(make_log(owner_id, ts, attacker_ip, target_user, "login_failed"))
    session.add_all(logs)
    session.commit()
    print(f"[brute_force] {len(logs)} failed logins from {attacker_ip} targeting '{target_user}' (owner_id={owner_id}).")


# ── Scenario 2: Geo anomaly ─────────────────────────────────────────────────

def generate_geo_anomaly(session, owner_id, target_user=None):
    """A successful login from a foreign IP the user has never used before —
    no failed attempts, which is what makes this different from brute force."""
    now = datetime.utcnow()
    target_user = target_user or random.choice(USERS)
    region = random.choice(list(ATTACK_IPS_BY_REGION.keys()))
    ip = random.choice(ATTACK_IPS_BY_REGION[region])

    logs = [make_log(owner_id, now - timedelta(seconds=5), ip, target_user, "login_success")]
    session.add_all(logs)
    session.commit()
    print(f"[geo_anomaly] login_success for '{target_user}' from unusual location {region} ({ip}) (owner_id={owner_id}).")


# ── Scenario 3: Off-hours login ─────────────────────────────────────────────

def generate_off_hours_login(session, owner_id, target_user=None):
    """A successful login timestamped between 1-4 AM local-equivalent hours —
    unusual activity time for a normal employee."""
    target_user = target_user or random.choice(USERS)
    ip = random.choice(NORMAL_IPS)  # internal IP, but odd hour — different signal than geo/brute force

    today = datetime.utcnow().date()
    odd_hour = random.choice([1, 2, 3, 4])
    ts = datetime.combine(today, datetime.min.time()) + timedelta(hours=odd_hour, minutes=random.randint(0, 59))

    logs = [make_log(owner_id, ts, ip, target_user, "login_success")]
    session.add_all(logs)
    session.commit()
    print(f"[off_hours_login] login_success for '{target_user}' at {ts.strftime('%H:%M')} UTC from {ip} (owner_id={owner_id}).")


# ── Scenario 4: Privilege escalation ────────────────────────────────────────

def generate_privilege_escalation(session, owner_id, target_user=None):
    """A login_success immediately followed by a privilege_change event —
    classic pattern for account takeover -> escalation."""
    now = datetime.utcnow()
    target_user = target_user or random.choice([u for u in USERS if u not in PRIVILEGED_USERS])
    ip = random.choice(ALL_ATTACK_IPS) if random.random() < 0.5 else random.choice(NORMAL_IPS)

    logs = [
        make_log(owner_id, now - timedelta(seconds=90), ip, target_user, "login_success"),
        make_log(owner_id, now - timedelta(seconds=30), ip, target_user, "privilege_change"),
    ]
    session.add_all(logs)
    session.commit()
    print(f"[privilege_escalation] '{target_user}' login -> privilege_change from {ip} (owner_id={owner_id}).")


# ── Scenario 5: Impossible travel ───────────────────────────────────────────

def generate_impossible_travel(session, owner_id, target_user=None):
    """Same user logs in successfully from two geographically distant
    countries within a few minutes — physically impossible travel time."""
    now = datetime.utcnow()
    target_user = target_user or random.choice(USERS)

    region_a, region_b = random.sample(list(ATTACK_IPS_BY_REGION.keys()), 2)
    ip_a = random.choice(ATTACK_IPS_BY_REGION[region_a])
    ip_b = random.choice(ATTACK_IPS_BY_REGION[region_b])

    logs = [
        make_log(owner_id, now - timedelta(minutes=4), ip_a, target_user, "login_success"),
        make_log(owner_id, now, ip_b, target_user, "login_success"),
    ]
    session.add_all(logs)
    session.commit()
    print(f"[impossible_travel] '{target_user}' logged in from {region_a} then {region_b} 4 min apart (owner_id={owner_id}).")


SCENARIO_FUNCS = {
    "brute_force": generate_attack_burst,
    "geo_anomaly": generate_geo_anomaly,
    "off_hours_login": generate_off_hours_login,
    "privilege_escalation": generate_privilege_escalation,
    "impossible_travel": generate_impossible_travel,
}


def generate_random_scenario(session, owner_id):
    scenario = random.choice(SCENARIO_TYPES)
    SCENARIO_FUNCS[scenario](session, owner_id)
    return scenario


def validate_user(session, user_id: int):
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise SystemExit(
            f"No user found with id={user_id}. "
            f"Register a user first via POST /auth/register, then check their id via /auth/me."
        )
    return user


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--user-id", type=int, required=True, help="Aegis AI user id to attribute these logs to")
    parser.add_argument("--attack", action="store_true", help="include ONE random attack scenario")
    parser.add_argument("--scenario", choices=SCENARIO_TYPES, help="trigger a specific scenario type")
    parser.add_argument("--loop", action="store_true", help="run continuously")
    parser.add_argument("--interval", type=int, default=15, help="seconds between batches in loop mode")
    args = parser.parse_args()

    init_db()
    session = SessionLocal()

    user = validate_user(session, args.user_id)
    print(f"Generating logs for user: {user.username} ({user.email})")

    if args.loop:
        print("Starting log generation loop. Ctrl+C to stop.")
        try:
            while True:
                generate_normal_batch(session, args.user_id, count=random.randint(5, 15))
                if random.random() < 0.25:
                    generate_random_scenario(session, args.user_id)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("Stopped.")
    else:
        generate_normal_batch(session, args.user_id)
        if args.scenario:
            SCENARIO_FUNCS[args.scenario](session, args.user_id)
        elif args.attack:
            generate_random_scenario(session, args.user_id)

    session.close()


if __name__ == "__main__":
    main()
