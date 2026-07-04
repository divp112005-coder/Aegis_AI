# Aegis AI — Intelligent SIEM Platform

> AI-powered Security Information and Event Management (SIEM) system with autonomous alert triage, advanced multi-source threat detection, lightweight collection agents, and LLM-generated analyst reports.

---

## Overview

Aegis AI is a full-stack, multi-tenant SIEM platform that combines real-time log ingestion, 10 advanced threat-detection rules, lightweight endpoints shipping event data from local systems, and an AI analyst agent powered by Groq (LLaMA 3.3 70B) to automatically investigate and triage security alerts.

Built as a portfolio project demonstrating the intersection of AI and cybersecurity, its core thesis is to reduce security analyst fatigue by automating the first-pass investigation and response of security alerts, combined with a human-in-the-loop SOAR response workflow.

---

## Architecture

```
                                          +----------------------------------+
                                          |        Local Log Agents          |
                                          |  (Event Tailer & Packet Sniffer) |
                                          +-------------------+--------------+
                                                              |
                                                     HTTPS Ingestion Batch
                                                     (Auth via X-API-Key)
                                                              |
                                                              v
+------------------------+      SQLAlchemy        +-----------+-----------+
|                        |<-----------------------|                       |
|   PostgreSQL Database  |                        |    FastAPI Backend    |
|   (Alembic Migrations) |----------------------->|    (REST API & Auth)  |
+------------------------+                        +-----+-----------+-----+
                                                        |           ^
                                                        |           | JWT
                                          APScheduler   |           | Request
                                          Rules Engine  v           v
                                          +-------------+-----+  +--+------------+
                                          |  AI Analyst Agent |  |  React Web    |
                                          |  (Groq LLaMA 3.3) |  |  Dashboard    |
                                          +-------------------+  +---------------+
```

---

## Key Enhancements (Since Last Update)

- **JWT Authentication & Multi-Tenancy:** Added full user registration, login, and profile services. All logs, alerts, and configurations are securely isolated by user accounts (`owner_id`).
- **SaaS Plan & API Key Infrastructure:** Implemented tiers (`free`, `pro`, `enterprise`) and API key generation. Agents authenticate autonomously via the `X-API-Key` header, allowing remote unattended deployment.
- **Advanced 10-Rule Detection Engine:** Expanded detection scope from basic brute force to 10 correlation rules spanning host authentication anomalies, network port scanning, and packet-level heuristics.
- **Log Collection Agents (`agent/`):**
  - **Windows Event Log Tailer:** Read-time parser for local security events (IDs 4624, 4625, 4672, 4634/4647, 5156/5157) with intelligent local filtering to reduce chatty traffic.
  - **Network Packet Monitor:** Passive sniffer using `scapy` to capture metadata (no payloads) and feed SYN flood and DNS tunneling detectors.
- **Human-in-the-Loop SOAR Actions:** Approving an alert triggers automated (simulated) firewall blacklisting. Includes a dedicated IP management module to view, track, and unblock IPs.
- **On-Demand AI Analyst Reports:** Optimized Groq API limits by moving analysis from auto-trigger to on-demand trigger ("Run Analysis" button inside the UI drawer).
- **Alembic Database Migrations:** Integrated database schema evolution tracking using Alembic.
- **Aesthetic Premium UI:** Redesigned React interface using frosted glassmorphic styling, smooth micro-interactions, responsive charts, and full Dark Mode support.

---

## The 10 Detection Rules

The backend detection engine runs periodically, evaluating incoming events for the following threat models:

| Rule Name | Category | Threshold / Condition |
|-----------|----------|-----------------------|
| **1. Brute Force** | Identity | 5+ failed logins (`login_failed`) from a single IP in 1 minute. |
| **2. Geolocation Anomaly** | Identity | Successful login from a country not observed for that user in the last 30 days. |
| **3. Off-Hours Login** | Identity | Successful login occurring between 00:00 and 05:00 UTC. |
| **4. Privilege Escalation** | Identity | A special privilege change (`privilege_change`, Event ID 4672) from an external IP within 5 minutes of login. |
| **5. Impossible Travel** | Identity | Logins from two different geolocations within a 10-minute window. |
| **6. Port Scan** | Network | One source IP hitting 10+ distinct destination ports within 2 minutes. |
| **7. Suspicious Port** | Network | Direct outbound connection to known-bad / malicious ports (e.g., Metasploit, Tor, RDP, Trojan C2s). |
| **8. Connection Volume** | Network | One source IP spawning 50+ outbound connections in 5 minutes. |
| **9. SYN Flood Heuristic** | Packet Sniff | >100 TCP SYN packets from a single source IP in 1 minute. |
| **10. DNS Tunneling Heuristic** | Packet Sniff | >50 DNS query packets from a single source IP in 1 minute. |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python, FastAPI, SQLAlchemy ORM, Uvicorn, JWT Auth (`python-jose`, `passlib`) |
| **Database** | PostgreSQL, Alembic (Migrations) |
| **Log Agents** | PyWin32 (Windows Log parser), Scapy (Raw Packet Sniffer), Requests |
| **AI Analyst** | Groq API SDK (LLaMA 3.3 70B Versatile model) |
| **Rules Engine** | APScheduler, custom SQLAlchemy aggregation queries |
| **Frontend** | React, Vite, CSS (Glassmorphism & Custom Themes), Axios |
| **Infrastructure** | Docker, Docker Compose, Windows Batch Launcher |

---

## Project Structure

```
Aegis_AI/
├── agent/                 # Lightweight local collection agents
│   ├── windows_event_tailer.py  # Security event log shipper
│   ├── packet_monitor.py        # Scapy-based network packet monitor
│   ├── requirements.txt         # Agent python dependencies
│   └── diagnose_handle.py       # Win32 handler diagnostic utilities
├── backend/               # FastAPI REST API & Detection Engine
│   ├── main.py            # API routing, ingestion, and CORS setup
│   ├── auth.py            # JWT authentication, hashing, and API key verification
│   ├── models.py          # SQLAlchemy models (User, Log, Alert, BlockedIP)
│   ├── ai_analyst.py      # Groq AI prompt generation and schema formatting
│   ├── detector.py        # The 10-rule threat detection logic
│   ├── log_generator.py   # Seed script simulating multi-stage attacks
│   ├── alembic/           # Alembic database migrations history
│   ├── alembic.ini        # Alembic configuration
│   └── requirements.txt   # Backend python dependencies
├── frontend/              # React/Vite User Interface
│   ├── src/
│   │   ├── App.jsx        # Routing configuration
│   │   ├── context/
│   │   │   └── AuthContext.jsx  # Auth state and JWT handling
│   │   ├── pages/
│   │   │   ├── Auth.jsx        # Glassmorphic Login/Signup page
│   │   │   ├── Dashboard.jsx   # Real-time alert feed & drawer
│   │   │   ├── Settings.jsx    # API Key, profile, and seed controls
│   │   │   ├── Docs.jsx        # Interactive document catalog
│   │   │   └── Pricing.jsx     # Tier upgrade layout
│   │   └── components/
│   │       ├── AlertTable.jsx  # Tabular UI for alert feed
│   │       └── AlertDetail.jsx # Interactive side-drawer with on-demand AI reports
├── start_aegis.bat        # Multi-process Windows batch launcher
├── docker-compose.yml     # PostgreSQL service definition
└── README.md
```

---

## Getting Started

### Prerequisites
- **Python 3.11+**
- **Node.js 20+**
- **Docker + Docker Compose**
- **Groq API key** ([console.groq.com](https://console.groq.com))
- **Npcap** (Windows only - required if running the Packet Monitor agent: [npcap.com](https://npcap.com))

### Quick Start (Windows)
Aegis AI includes a launcher script that boots the database, runs migrations, spins up all backend/frontend applications, and attaches the local collectors.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/divp112005-coder/Aegis_AI.git
   cd Aegis_AI
   ```
2. **Create the environment file** in the `backend/` directory:
   ```bash
   cp backend/.env.example backend/.env
   # Edit backend/.env to include your GROQ_API_KEY
   ```
3. **Run the launcher:**
   Double-click `start_aegis.bat` or run it from a command prompt:
   ```cmd
   start_aegis.bat
   ```
   *Note: Windows Event Log and Packet Monitor require Administrator access. You will see UAC prompts asking for permission to run these tools.*

---

### Manual Setup (Step-by-Step)

If you prefer to start components individually or are running on Linux/macOS:

#### 1. Database & Migrations
Ensure Docker is running, then start PostgreSQL:
```bash
docker compose up -d
```
Navigate to the `backend/` directory, set up your Python virtual environment, install requirements, and apply the migrations:
```bash
cd backend
python -m venv venv
# Activate on Windows:
venv\Scripts\activate
# Activate on macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
alembic upgrade head
```

#### 2. Run Backend & Rules Engine
```bash
# In backend virtual env
uvicorn main:app --reload --port 8000
```
In a new terminal window, start the detector scheduler:
```bash
# In backend virtual env
python detector.py
```

#### 3. Run Frontend
Navigate to the `frontend/` directory, install dependencies, and start the development server:
```bash
cd frontend
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

#### 4. Run the Collection Agents
Locate your **API Key** on the Aegis AI Web Dashboard under `Settings -> API Key`.

**To run the Windows Security Event Log Agent:**
Open an **Administrator command prompt/terminal** and run:
```bash
cd agent
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python windows_event_tailer.py --api-key <YOUR_API_KEY>
```

**To run the Packet Sniffer Agent (requires Npcap):**
Open an **Administrator command prompt/terminal** and run:
```bash
# In agent virtual env
python packet_monitor.py --api-key <YOUR_API_KEY>
```

---

## API Reference

### Authentication Services
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register a new user account |
| POST | `/auth/token` | Log in and obtain a JWT bearer token |
| GET | `/auth/me` | Fetch active user profile, subscription plan, and API key |

### Alert & Threat Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/alerts` | List alerts for the active user (supports status filters) |
| GET | `/alerts/{id}` | Retrieve details, related logs, and any AI analysis reports |
| POST | `/alerts/{id}/analyze` | Trigger on-demand AI analysis via Groq |
| POST | `/alerts/{id}/status` | Update alert status (`open`, `approved`, `dismissed`) |
| DELETE | `/alerts` | Purge all alerts for the authenticated user |

### Firewall Response (SOAR)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/blocked-ips` | List current active blocked IPs |
| POST | `/blocked-ips/{id}/unblock` | Unblock a previously blacklisted IP address |

### Log Services
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/logs` | Retrieve ingested logs (supports IP & event type filter) |
| POST | `/ingest/logs` | Real log ingestion endpoint (secured via `X-API-Key` header) |
| POST | `/demo/seed` | Seed logs containing random threat simulation batches |

Interactive Swagger documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).

---

## Sample AI Analyst Output

Below is an example of an on-demand generated report returned by the Groq AI Analyst:

```json
{
  "summary": "Multiple failed login attempts detected for account 'Administrator' from an external IP (198.51.100.42) followed immediately by a successful login. An anomalous geographic origin (Ukraine) was flagged as it does not match the user's historical login baseline. This strongly suggests a successful credential stuffing or brute-force attack.",
  "severity": "critical",
  "mitre_technique": "T1110.001 - Brute Force: Password Guessing",
  "recommended_action": "1. Approve the alert to trigger simulated firewall blocking for 198.51.100.42.\n2. Force password reset and revoke active sessions for the Administrator account.\n3. Validate whether multi-factor authentication (MFA) was bypassed or is unconfigured."
}
```

---

## License

MIT
