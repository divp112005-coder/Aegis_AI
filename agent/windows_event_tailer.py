"""
windows_event_tailer.py — A lightweight log-shipping agent for Aegis AI.

Reads NEW events from the local Windows Security Event Log and POSTs them
to your Aegis AI backend's /ingest/logs endpoint, normalized into Aegis AI's
log schema. This is the real-data counterpart to log_generator.py's
simulated logs.

Mapped Event IDs:
  4624  -> login_success
  4625  -> login_failed
  4672  -> privilege_change   (special/admin privileges assigned at logon)
  4634, 4647 -> logout

Requirements:
    pip install pywin32 requests

Usage:
    python windows_event_tailer.py --api-key <your_api_key> [--api-url http://127.0.0.1:8000] [--interval 15]

Get your API key from the Aegis AI dashboard -> Settings -> API Key,
or via GET /auth/me while logged in.

NOTE: Reading the Security event log on Windows typically requires the
agent to run as Administrator, since that log is access-restricted by
default. If you get "Access is denied" errors, re-run your terminal
as Administrator.
"""

import argparse
import time
import json
from datetime import datetime, timezone

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
except ImportError:
    raise SystemExit(
        "pywin32 is required for this agent. Install it with:\n"
        "    pip install pywin32\n"
        "This agent only runs on Windows."
    )

import requests

EVENT_ID_MAP = {
    4624: "login_success",
    4625: "login_failed",
    4672: "privilege_change",
    4634: "logout",
    4647: "logout",
}

LOG_TYPE = "Security"
SERVER = "localhost"


def _extract_username(event) -> str:
    """Best-effort extraction of the target account name from event StringInserts.
    Security event layouts vary by Event ID; this covers the common 4624/4625/4672 shape
    where the target account name is typically the 5th insert string (index 5)."""
    inserts = event.StringInserts
    if not inserts:
        return "unknown"
    # Common layout: [SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId,
    #                 TargetUserSid, TargetUserName, ...]
    if len(inserts) > 5 and inserts[5]:
        return inserts[5]
    return inserts[1] if len(inserts) > 1 and inserts[1] else "unknown"


def _extract_source_ip(event) -> str:
    """Attempts to find an IP address among the event's insert strings.
    4624/4625 typically include the source network address (often '-' for local logons)."""
    inserts = event.StringInserts or []
    for s in inserts:
        if s and s.count(".") == 3 and all(part.isdigit() for part in s.split(".") if part):
            return s
    return "127.0.0.1"  # local/interactive logon with no remote address


def read_new_events(handle, last_record_number: int, debug=False):
    """
    Reads all events newer than last_record_number from the Security log.

    Strategy: read backwards from the most recent event in batches. For each
    batch, collect every event whose RecordNumber > last_record_number AND
    whose EventID is one we care about. We only stop once we hit a record
    at or below last_record_number (since backwards-read returns newest
    first, anything at or below that point means we've caught up).

    Returns (events_oldest_to_newest, new_last_record_number).
    """
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    collected = []
    newest_seen = last_record_number
    caught_up = False
    batch_num = 0

    while not caught_up:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        batch_num += 1
        if debug:
            print(f"  [debug] batch #{batch_num}: ReadEventLog returned {len(events) if events else 0} raw event(s)")

        if not events:
            break  # no more events in the log at all

        for event in events:
            raw_id = event.EventID
            masked_id = raw_id & 0xFFFF
            if debug and batch_num == 1:
                print(f"  [debug] record={event.RecordNumber} raw_event_id={raw_id} masked_id={masked_id} "
                      f"source={event.SourceName} time={event.TimeGenerated}")

            if event.RecordNumber <= last_record_number:
                caught_up = True
                break  # don't process this or anything older — already seen

            newest_seen = max(newest_seen, event.RecordNumber)

            if masked_id in EVENT_ID_MAP:
                collected.append(event)

        if batch_num > 50:
            if debug:
                print("  [debug] safety stop: 50 batches read without catching up")
            break

    # collected is newest-first (backwards read); reverse so we ship oldest-first
    collected.reverse()
    return collected, newest_seen


def event_to_payload(event) -> dict:
    event_id = event.EventID & 0xFFFF
    event_type = EVENT_ID_MAP[event_id]
    ts = event.TimeGenerated.replace(tzinfo=None)  # pywin32 gives local time

    return {
        "timestamp": ts.isoformat(),
        "source_ip": _extract_source_ip(event),
        "username": _extract_username(event),
        "event_type": event_type,
        "raw": {
            "event_id": event_id,
            "source_name": event.SourceName,
            "computer_name": event.ComputerName,
            "string_inserts": event.StringInserts,
        },
    }


def ship_batch(api_url: str, api_key: str, events: list, source_label: str):
    if not events:
        return
    resp = requests.post(
        f"{api_url}/ingest/logs",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        json={"events": events, "source": source_label},
        timeout=10,
    )
    if resp.status_code != 200:
        print(f"[INGEST ERROR] {resp.status_code}: {resp.text}")
    else:
        data = resp.json()
        print(f"[INGEST OK] inserted={data['inserted']} skipped={len(data['skipped'])}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-key", required=True, help="Your Aegis AI API key (Settings -> API Key)")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000", help="Aegis AI backend base URL")
    parser.add_argument("--interval", type=int, default=15, help="Seconds between polls")
    parser.add_argument("--debug", action="store_true", help="Print detailed per-event diagnostics on the first batch each poll")
    args = parser.parse_args()

    print(f"Connecting to {LOG_TYPE} event log on {SERVER}...")
    handle = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)

    # Start from the current end of the log so we only ship NEW events going forward.
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    initial = win32evtlog.ReadEventLog(handle, flags, 0)
    last_record_number = max((e.RecordNumber for e in initial), default=0)
    win32evtlog.CloseEventLog(handle)

    print(f"Tailing from record #{last_record_number}. Polling every {args.interval}s. Ctrl+C to stop.")
    print(f"Shipping to {args.api_url}/ingest/logs")

    try:
        while True:
            # Reopen the handle fresh each poll — Windows event log handles can
            # return stale/cached results if kept open across long-running reads,
            # so the reliable pattern is open -> read -> close every cycle.
            handle = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)
            try:
                new_events, last_record_number = read_new_events(handle, last_record_number, debug=args.debug)
            finally:
                win32evtlog.CloseEventLog(handle)

            print(f"[poll] checked up to record #{last_record_number} — {len(new_events)} relevant event(s) found.")
            if new_events:
                payloads = [event_to_payload(e) for e in new_events]
                print(f"Found {len(payloads)} new relevant security event(s).")
                ship_batch(args.api_url, args.api_key, payloads, source_label="windows_event_log")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    main()