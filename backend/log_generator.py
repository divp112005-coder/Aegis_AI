"""
Generates fake security logs and inserts them into the database.

Run modes:
  python log_generator.py              -> generates one batch of "normal" traffic
  python log_generator.py --attack     -> generates one batch including a brute-force burst
  python log_generator.py --loop       -> continuously generates logs every few seconds
"""

import argparse
import json
import random
import time
from datetime import datetime, timedelta

from models import SessionLocal, Log, init_db

USERS = ["alice", "bob", "carol", "dave", "eve", "admin", "svc_backup"]
EVENT_TYPES = ["login_success", "login_failed", "file_access", "privilege_change", "logout"]

# Pool of "normal" IPs (simulate office / VPN ranges)
NORMAL_IPS = [f"10.0.{i}.{j}" for i in range(1, 4) for j in range(1, 20)]

# Pool of "suspicious" external IPs used for attack simulation
ATTACK_IPS = ["185.220.101.7", "45.155.205.233", "194.61.24.102", "103.45.246.18"]

GEO_MAP = {
    "10.0": "Internal-Office",
    "185.220": "Russia",
    "45.155": "Netherlands",
    "194.61": "Romania",
    "103.45": "Vietnam",
}


def geo_for_ip(ip: str) -> str:
    prefix = ".".join(ip.split(".")[:2])
    return GEO_MAP.get(prefix, "Unknown")


def make_log(timestamp, source_ip, username, event_type) -> Log:
    geo = geo_for_ip(source_ip)
    raw = {
        "timestamp": timestamp.isoformat(),
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "geo_location": geo,
    }
    return Log(
        timestamp=timestamp,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        geo_location=geo,
        raw=json.dumps(raw),
    )


def generate_normal_batch(session, count=20):
    now = datetime.utcnow()
    logs = []
    for _ in range(count):
        ts = now - timedelta(seconds=random.randint(0, 300))
        ip = random.choice(NORMAL_IPS)
        user = random.choice(USERS)
        event = random.choices(
            EVENT_TYPES, weights=[60, 10, 15, 5, 10], k=1
        )[0]
        logs.append(make_log(ts, ip, user, event))
    session.add_all(logs)
    session.commit()
    print(f"Inserted {len(logs)} normal logs.")


def generate_attack_burst(session, count=6, target_user="admin"):
    """Simulate a brute-force burst: many login_failed from one external IP in a short window."""
    now = datetime.utcnow()
    attacker_ip = random.choice(ATTACK_IPS)
    logs = []
    for i in range(count):
        ts = now - timedelta(seconds=random.randint(0, 50))
        logs.append(make_log(ts, attacker_ip, target_user, "login_failed"))
    session.add_all(logs)
    session.commit()
    print(f"Inserted {len(logs)} attack logs from {attacker_ip} targeting '{target_user}'.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack", action="store_true", help="include a brute-force burst")
    parser.add_argument("--loop", action="store_true", help="run continuously")
    parser.add_argument("--interval", type=int, default=15, help="seconds between batches in loop mode")
    args = parser.parse_args()

    init_db()
    session = SessionLocal()

    if args.loop:
        print("Starting log generation loop. Ctrl+C to stop.")
        try:
            while True:
                generate_normal_batch(session, count=random.randint(5, 15))
                # Randomly inject an attack burst ~20% of the time
                if random.random() < 0.2:
                    generate_attack_burst(session)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("Stopped.")
    else:
        generate_normal_batch(session)
        if args.attack:
            generate_attack_burst(session)

    session.close()


if __name__ == "__main__":
    main()
