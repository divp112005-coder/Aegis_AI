"""
AI Analyst: takes an alert, gathers related logs, sends them to Grok
(xAI's API, OpenAI-compatible), and stores the structured response
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
  "mitre_technique": "MITRE ATT&CK technique ID and name, e.g. 'T1110 - Brute Force'",
  "recommended_action": "1-3 sentence specific recommended action for the analyst"
}

Base your severity on factors like: number of attempts, whether the target account is privileged \
(e.g. admin), whether the source IP geolocation looks suspicious (foreign country vs internal office), \
and whether any login_success appears alongside the failures (which would indicate a possible compromise)."""


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

        related_logs = (
            session.query(Log)
            .filter(Log.source_ip == alert.source_ip)
            .order_by(Log.timestamp.desc())
            .limit(20)
            .all()
        )

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
