# Aegis AI — Intelligent SIEM Platform

> AI-powered Security Information and Event Management (SIEM) system with autonomous alert triage, brute-force detection, and LLM-generated analyst reports.

---

## Overview

Aegis AI is a full-stack hosted SIEM platform that combines real-time log ingestion, rule-based threat detection, and an AI analyst agent powered by Groq (LLaMA 3.3 70B) to automatically investigate and triage security alerts.

Built as a portfolio project demonstrating the intersection of AI and cybersecurity — the core thesis: reduce analyst fatigue by automating the first-pass investigation of security alerts.

---

## Architecture

```
Log Sources → FastAPI Backend → PostgreSQL
                    ↓
            Detection Engine (APScheduler)
                    ↓ alert created
            AI Analyst Agent (Groq / LLaMA 3.3)
                    ↓ report saved
            React Dashboard (Vite)
```

---

## Features

- **Log Ingestion** — Structured JSON log pipeline with fields for source IP, username, event type, and geolocation
- **Brute-Force Detector** — Scheduled job runs every 10 seconds, flags any IP with 5+ failed logins in the last 60 seconds
- **AI Analyst Agent** — On alert creation, automatically pulls related logs, builds a context prompt, and sends to Groq API; response includes:
  - Plain-English summary
  - Severity assessment (low / medium / high / critical)
  - MITRE ATT&CK technique mapping
  - Recommended action
- **Human-in-the-Loop** — Analysts can approve or dismiss alerts directly from the dashboard
- **REST API** — FastAPI backend with endpoints for logs, alerts, alert detail, AI analysis trigger, and status updates
- **React Dashboard** — Real-time alert table with 5-second auto-refresh, click-to-expand detail panel with full AI report

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, SQLAlchemy |
| Database | PostgreSQL (Docker) |
| AI Agent | Groq API (LLaMA 3.3 70B Versatile) |
| Detection | APScheduler, SQLAlchemy queries |
| Frontend | React, Vite, Axios |
| Infrastructure | Docker, Docker Compose |

---

## Project Structure

```
Aegis_AI/
├── backend/
│   ├── main.py            # FastAPI app and REST endpoints
│   ├── models.py          # SQLAlchemy ORM models (Log, Alert, AnalystReport)
│   ├── log_generator.py   # Fake log generator with attack simulation mode
│   ├── detector.py        # Brute-force detection job
│   ├── ai_analyst.py      # Groq API integration and report generation
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.jsx
│       ├── components/
│       │   ├── AlertTable.jsx
│       │   └── AlertDetail.jsx
├── docker-compose.yml
└── README.md
```

---

## Getting Started

### Prerequisites
- Python 3.11+
- Node.js 20+
- Docker + Docker Compose
- Groq API key ([console.groq.com](https://console.groq.com))

### Setup

**1. Clone the repo**
```bash
git clone https://github.com/divp112005-coder/Aegis_AI.git
cd Aegis_AI
```

**2. Start PostgreSQL**
```bash
docker compose up -d
```

**3. Set up the backend**
```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux
pip install -r requirements.txt
```

**4. Configure environment**
```bash
cp .env.example .env
# Edit .env and add your GROQ_API_KEY
```

**5. Generate sample logs**
```bash
python log_generator.py --attack
```

**6. Start the API**
```bash
uvicorn main:app --reload
```

**7. Start the detector** (new terminal)
```bash
python detector.py
```

**8. Start the frontend** (new terminal)
```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173)

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/logs` | Fetch logs (filterable by IP, event type) |
| GET | `/alerts` | List all alerts |
| GET | `/alerts/{id}` | Alert detail with related logs and AI report |
| POST | `/alerts/{id}/analyze` | Trigger AI analysis for an alert |
| POST | `/alerts/{id}/status` | Update alert status (open/approved/dismissed) |

Interactive docs available at [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Sample AI Analyst Output

```json
{
  "summary": "Multiple failed login attempts detected for the admin account from a Netherlands-based IP (45.155.205.233), with 6 attempts within a 1-minute window. The foreign geolocation raises suspicion. No successful logins were detected alongside the failures.",
  "severity": "high",
  "mitre_technique": "T1110 - Brute Force",
  "recommended_action": "Block source IP 45.155.205.233 immediately. Enable MFA on the admin account. Monitor for any lateral movement or privilege escalation attempts."
}
```

---

## Roadmap

- [ ] Real log agent (Filebeat / Wazuh integration)
- [ ] Additional detection rules (geo-anomaly, off-hours login, privilege escalation)
- [ ] Multi-tenancy support
- [ ] Alert correlation across multiple source IPs
- [ ] Automated response playbooks (block IP via firewall API)
- [ ] Kafka-based streaming log pipeline

---





## License

MIT
