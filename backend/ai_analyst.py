"""
AI Analyst: takes an alert, gathers related logs, sends them to Groq
(OpenAI-compatible API), and stores the structured response
as an AnalystReport.
"""

import os
import json
from datetime import datetime

from dotenv import load_dotenv
from openai import OpenAI

from models import SessionLocal, Alert, Log, AnalystReport

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_MODEL = "llama-3.3-70b-versatile"  # solid default; swap for other Groq-hosted models as needed

client = OpenAI(api_key=GROQ_API_KEY, base_url=GROQ_BASE_URL)


SYSTEM_PROMPT = """You are a SOC (Security Operations Center) analyst AI working inside Aegis AI, \
a SIEM platform. You will be given an alert and a list of related raw logs. \
Analyze the situation and respond ONLY with a valid JSON object (no markdown, no preamble) \
with exactly these fields:

{
  "summary": "2-4 sentence plain-English summary of what happened",
  "severity": "low | medium | high | critical",
  "mitre_technique": "MITRE ATT&CK technique ID and name",
  "recommended_action": "1-3 sentence specific recommended action for the analyst"
}

The alert will have one of these alert_type values — use the matching guidance for severity \
and MITRE mapping:

- "brute_force": Many failed logins from one source. Map to T1110 - Brute Force. Severity scales \
  with attempt count, whether the target account is privileged (e.g. admin, svc_backup), and whether \
  the source IP geolocation is foreign vs internal office. A login_success mixed in with failures \
  suggests a possible compromise and should raise severity to high/critical.

- "geo_anomaly": A successful login from a country/location this user has never used before. Map to \
  T1078 - Valid Accounts (or T1586 if credential reuse seems likely). Severity depends on how far the \
  new location is from the user's normal pattern and whether the account is privileged.

- "off_hours_login": A successful login at an unusual hour (e.g. 1-4 AM). Map to T1078 - Valid Accounts. \
  Generally lower severity (low/medium) unless combined with other risk factors like a privileged \
  account or unfamiliar IP, since off-hours access alone can have innocent explanations.

- "privilege_escalation": A privilege_change event occurring shortly after a login_success for the same \
  user. Map to T1078.003 or T1098 - Account Manipulation. This is a high-signal pattern — severity should \
  generally be high or critical, especially if the source IP is external/foreign.

- "impossible_travel": The same user has login_success events from two geographically distant locations \
  within a short time window (physically impossible to travel between in that time). Map to T1078 - Valid \
  Accounts. Strongly suggests credential compromise or session/token theft — severity should generally be \
  high or critical.

- "port_scan": A single source IP connected to an unusually large number of distinct destination ports \
  in a short time window — classic network reconnaissance behavior. Map to T1046 - Network Service \
  Discovery. Severity is high if the source is external; medium if internal (could be a misconfigured \
  scanner, security tool, or compromised internal host). The details field includes distinct_ports_scanned \
  and window_minutes for context.

- "suspicious_port": A network connection was made to or from a port strongly associated with malware, \
  remote access trojans (RATs), or common pentest/attack tooling (e.g. 4444 Metasploit, 31337 classic \
  backdoor, 3389 RDP outbound, 23 Telnet). Map to T1071 - Application Layer Protocol or T1219 - Remote \
  Access Software depending on the port. Severity should be high by default — any connection to these \
  ports warrants investigation. The details field includes dest_port and application (the process that \
  made the connection) for context.

- "connection_volume": A single source IP made an abnormally high number of network connections within \
  a short window — possible C2 beacon traffic, data exfiltration, or worm-like lateral movement scanning. \
  Map to T1071 - Application Layer Protocol (for C2) or T1048 - Exfiltration Over Alternative Protocol. \
  Severity scales with volume and whether the destination IPs are external. The details field includes \
  connection_count and window_minutes.

Always ground your reasoning in the specific details and related logs provided rather than generic advice."""


def build_prompt(alert: Alert, related_logs: list[Log]) -> str:
    alert_info = {
        "alert_type": alert.alert_type,
        "source_ip": alert.source_ip,
        "username": alert.username,
        "created_at": alert.created_at.isoformat(),
        "details": alert.details,
    }

    logs_info = [
        {
            "timestamp": log.timestamp.isoformat(),
            "username": log.username,
            "event_type": log.event_type,
            "geo_location": log.geo_location,
            **({"dest_port": log.dest_port, "protocol": log.protocol, "application": log.application}
               if log.event_type in ("network_connection", "network_connection_blocked") else {}),
        }
        for log in related_logs
    ]

    return (
        f"ALERT:\n{json.dumps(alert_info, indent=2)}\n\n"
        f"RELATED LOGS (most recent {len(logs_info)}, same source IP):\n"
        f"{json.dumps(logs_info, indent=2)}"
    )


def analyze_alert(alert_id: int):
    session = SessionLocal()
    try:
        alert = session.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            print(f"[AI ANALYST] Alert {alert_id} not found.")
            return

        # Skip if already analyzed
        if alert.report is not None:
            print(f"[AI ANALYST] Alert {alert_id} already has a report. Skipping.")
            return

        # Scope related logs to this alert's owner (critical for tenant isolation)
        # and choose the most relevant lookup key per alert type — IP-based attacks
        # are best explained by other activity from that IP, while account-centric
        # patterns (geo anomaly, off-hours, privilege escalation, impossible travel)
        # are best explained by that user's recent activity across IPs.
        log_query = session.query(Log).filter(Log.owner_id == alert.owner_id)

        if alert.alert_type in ("brute_force", "port_scan", "suspicious_port", "connection_volume"):
            log_query = log_query.filter(Log.source_ip == alert.source_ip)
        elif alert.username:
            log_query = log_query.filter(Log.username == alert.username)
        else:
            log_query = log_query.filter(Log.source_ip == alert.source_ip)

        related_logs = log_query.order_by(Log.timestamp.desc()).limit(20).all()

        prompt = build_prompt(alert, related_logs)

        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )

        raw_text = response.choices[0].message.content.strip()

        # Strip accidental markdown code fences if the model adds them
        if raw_text.startswith("```"):
            raw_text = raw_text.strip("`")
            if raw_text.startswith("json"):
                raw_text = raw_text[4:].strip()

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            print(f"[AI ANALYST] Failed to parse JSON response:\n{raw_text}")
            parsed = {
                "summary": "AI response could not be parsed as JSON.",
                "severity": "unknown",
                "mitre_technique": "unknown",
                "recommended_action": "Review raw_response field manually.",
            }

        report = AnalystReport(
            alert_id=alert.id,
            created_at=datetime.utcnow(),
            summary=parsed.get("summary"),
            severity=parsed.get("severity"),
            mitre_technique=parsed.get("mitre_technique"),
            recommended_action=parsed.get("recommended_action"),
            raw_response=raw_text,
        )
        session.add(report)

        # Update alert's severity to match AI assessment
        if parsed.get("severity"):
            alert.severity = parsed["severity"]

        session.commit()
        print(f"[AI ANALYST] Report created for alert {alert.id} (severity={alert.severity})")

    except Exception as e:
        print(f"[AI ANALYST] Error analyzing alert {alert_id}: {e}")
    finally:
        session.close()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ai_analyst.py <alert_id>")
    else:
        analyze_alert(int(sys.argv[1]))
