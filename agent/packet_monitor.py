"""
packet_monitor.py — Experimental packet-level monitoring agent for Aegis AI.

Passively sniffs live network traffic on a chosen interface using scapy,
extracts basic packet metadata (src/dst IP, port, protocol, TCP flags),
and ships batches of captured events to the Aegis AI backend.

Captured metadata ONLY — no payload / packet content is ever collected.

Detection signals fed to the backend:
  - SYN flood heuristic  (high TCP SYN packet rate from a single source)
  - DNS tunneling heuristic (high DNS query rate from a single source)

Requirements:
    pip install scapy requests

    On Windows, scapy also requires Npcap (https://npcap.com) to be
    installed for raw packet capture.

    Packet capture typically requires Administrator privileges.

Usage:
    python packet_monitor.py --api-key <your_api_key> [options]

    Options:
        --iface     Network interface to sniff (e.g. "Ethernet", "Wi-Fi").
                    Omit to use scapy's default interface.
        --api-url   Aegis AI backend URL (default: http://127.0.0.1:8000)
        --interval  Seconds between batch shipments (default: 15)
        --debug     Print per-packet diagnostics to stdout

Get your API key from the Aegis AI dashboard -> Settings -> API Key,
or via GET /auth/me while logged in.

NOTE: Raw packet capture requires Administrator / root privileges and
Npcap (Windows) or libpcap (Linux/macOS) to be installed.
"""

import argparse
import time
import json
import threading
from datetime import datetime, timezone
from collections import deque

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, DNS
except ImportError:
    raise SystemExit(
        "scapy is required for this agent. Install it with:\n"
        "    pip install scapy\n"
        "On Windows you also need Npcap: https://npcap.com"
    )

import requests

# ── Protocol number to name mapping ──────────────────────────────────────────
_PROTO_MAP = {
    6:  "TCP",
    17: "UDP",
    1:  "ICMP",
}

# Maximum events to hold in the in-memory buffer between shipment cycles.
# If the buffer fills up before shipment, the oldest events are dropped to
# avoid unbounded memory growth under heavy traffic.
MAX_BUFFER_SIZE = 5000

# ── Shared state ──────────────────────────────────────────────────────────────
_event_buffer: deque = deque(maxlen=MAX_BUFFER_SIZE)
_buffer_lock = threading.Lock()
_args = None  # populated in main()


# ── Packet handler ────────────────────────────────────────────────────────────

def _proto_name(pkt) -> str:
    """Derive a human-readable protocol label for the packet."""
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(IP):
        return _PROTO_MAP.get(pkt[IP].proto, f"IP/{pkt[IP].proto}")
    return "OTHER"


def _tcp_flags(pkt) -> str | None:
    """Return a compact TCP flag string (e.g. 'S', 'SA', 'FA') or None."""
    if not pkt.haslayer(TCP):
        return None
    flags = pkt[TCP].flags
    # scapy represents flags as a FlagValue; str() gives the letter codes
    return str(flags) if flags else None


def packet_handler(pkt):
    """
    Called by scapy for every captured packet.
    Extracts metadata only — payload bytes are never read or stored.
    """
    global _args

    # We only care about IP packets (v4 or v6 outer layer)
    if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
        return

    try:
        # Source / destination IPs
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        else:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        # Destination port (TCP / UDP layer)
        dest_port = None
        if pkt.haslayer(TCP):
            dest_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dest_port = pkt[UDP].dport

        protocol = _proto_name(pkt)
        tcp_flags = _tcp_flags(pkt)

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": src_ip,
            "username": None,  # packet-level capture has no user context
            "event_type": "packet_capture",
            "raw": {
                "dest_ip": dst_ip,
                "dest_port": dest_port,
                "protocol": protocol,
                "tcp_flags": tcp_flags,
            },
        }

        with _buffer_lock:
            _event_buffer.append(event)

        if _args and _args.debug:
            flags_str = f" flags={tcp_flags}" if tcp_flags else ""
            port_str = f":{dest_port}" if dest_port else ""
            print(f"[PKT] {src_ip} -> {dst_ip}{port_str} {protocol}{flags_str}")

    except Exception as exc:
        # Never let a single bad packet crash the sniff loop
        if _args and _args.debug:
            print(f"[WARN] packet_handler error: {exc}")


# ── Batch shipment ────────────────────────────────────────────────────────────

def ship_batch(api_url: str, api_key: str, events: list):
    """POST a batch of packet metadata events to the Aegis AI ingest endpoint."""
    if not events:
        return
    try:
        resp = requests.post(
            f"{api_url}/ingest/logs",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            json={"events": events, "source": "packet_monitor"},
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"[INGEST ERROR] {resp.status_code}: {resp.text}")
        else:
            data = resp.json()
            print(f"[INGEST OK] inserted={data['inserted']} skipped={len(data['skipped'])}")
    except requests.exceptions.RequestException as exc:
        print(f"[WARN] Network error shipping batch, will retry next cycle: {exc}")


def shipper_loop(api_url: str, api_key: str, interval: int):
    """
    Background thread: wakes every `interval` seconds, drains the event
    buffer, and ships everything accumulated since the last cycle.
    """
    while True:
        time.sleep(interval)

        with _buffer_lock:
            if not _event_buffer:
                continue
            batch = list(_event_buffer)
            _event_buffer.clear()

        print(f"[SHIPPER] Shipping {len(batch)} packet event(s)...")
        ship_batch(api_url, api_key, batch)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global _args

    parser = argparse.ArgumentParser(
        description="Aegis AI packet monitor — passively captures network metadata and ships to backend."
    )
    parser.add_argument(
        "--api-key", required=True,
        help="Your Aegis AI API key (Settings -> API Key)"
    )
    parser.add_argument(
        "--api-url", default="http://127.0.0.1:8000",
        help="Aegis AI backend base URL"
    )
    parser.add_argument(
        "--iface", default=None,
        help="Network interface to sniff (e.g. 'Ethernet', 'Wi-Fi'). "
             "Omit to use scapy's default interface."
    )
    parser.add_argument(
        "--interval", type=int, default=15,
        help="Seconds between batch shipments to the backend (default: 15)"
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Print per-packet metadata to stdout"
    )
    _args = parser.parse_args()

    iface_label = _args.iface if _args.iface else "<default>"
    print(f"Aegis AI Packet Monitor starting.")
    print(f"  Interface : {iface_label}")
    print(f"  Backend   : {_args.api_url}/ingest/logs")
    print(f"  Interval  : {_args.interval}s")
    print(f"  Debug     : {_args.debug}")
    print("Press Ctrl+C to stop.")
    print()

    # Start the background shipper thread
    t = threading.Thread(
        target=shipper_loop,
        args=(_args.api_url, _args.api_key, _args.interval),
        daemon=True,
    )
    t.start()

    # Start passive sniffing (blocking call — runs until Ctrl+C)
    try:
        sniff(
            iface=_args.iface,   # None → scapy picks the default interface
            prn=packet_handler,
            store=False,         # Never store full packets in memory
            filter="ip or ip6",  # BPF pre-filter: only IP-layer packets
        )
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except PermissionError:
        raise SystemExit(
            "[ERROR] Permission denied. Raw packet capture requires Administrator "
            "privileges. Re-run this script as Administrator."
        )


if __name__ == "__main__":
    main()
