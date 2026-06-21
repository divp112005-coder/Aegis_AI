"""
diagnose_handle.py — isolates whether OpenEventLog/ReadEventLog work at all
right now, outside of the polling loop. Run this directly to see the raw
error with full detail.
"""

import win32evtlog
import pywintypes

SERVER = "localhost"
LOG_TYPE = "Security"

print("Step 1: Opening event log...")
try:
    handle = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)
    print(f"  OK — handle = {handle}")
except pywintypes.error as e:
    print(f"  FAILED to open: {e}")
    raise SystemExit(1)

print("Step 2: Reading events immediately after open...")
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
try:
    events = win32evtlog.ReadEventLog(handle, flags, 0)
    print(f"  OK — got {len(events)} events")
    if events:
        e = events[0]
        print(f"  First event: record={e.RecordNumber} id={e.EventID & 0xFFFF} time={e.TimeGenerated}")
except pywintypes.error as e:
    print(f"  FAILED to read: {e}")

print("Step 3: Reading AGAIN on the same handle (no close/reopen)...")
try:
    events2 = win32evtlog.ReadEventLog(handle, flags, 0)
    print(f"  OK — got {len(events2)} events")
except pywintypes.error as e:
    print(f"  FAILED to read (2nd call): {e}")

print("Step 4: Closing handle...")
try:
    win32evtlog.CloseEventLog(handle)
    print("  OK — closed")
except pywintypes.error as e:
    print(f"  FAILED to close: {e}")

print("\nDone.")
