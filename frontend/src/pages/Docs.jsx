import { useState, useEffect, useRef } from 'react';
import Navbar from '../components/Navbar';
import './Docs.css';

const SECTIONS = [
  { id: 'overview',        label: 'Overview',              icon: '⬡' },
  { id: 'quickstart',      label: 'Quick Start',           icon: <span className="nav-dot" /> },
  { id: 'api-reference',   label: 'API Reference',         icon: <span className="nav-dot" /> },
  { id: 'detection-rules', label: 'Detection Rules',       icon: <span className="nav-dot" /> },
  { id: 'api-keys',        label: 'API Keys & Ingestion',  icon: <span className="nav-dot" /> },
  { id: 'ai-analyst',      label: 'AI Analyst',            icon: <span className="nav-dot" /> },
  { id: 'faq',             label: 'FAQ',                   icon: <span className="nav-dot" /> },
];

const API_ENDPOINTS = [
  // ── Auth ──────────────────────────────────────────────────────────
  {
    method: 'POST',
    path: '/auth/register',
    auth: false,
    authMethod: null,
    description: 'Create a new account. Returns a JWT access token and a unique API key on success.',
    params: [
      { name: 'username', type: 'string', required: true,  desc: 'Desired username (body JSON)' },
      { name: 'password', type: 'string', required: true,  desc: 'Account password (body JSON)' },
    ],
    response: '{ "access_token": "eyJ...", "token_type": "bearer", "api_key": "aegis_live_..." }',
  },
  {
    method: 'POST',
    path: '/auth/login',
    auth: false,
    authMethod: null,
    description: 'Authenticate and receive a JWT access token plus your account API key.',
    params: [
      { name: 'username', type: 'string', required: true, desc: 'Account username (body JSON)' },
      { name: 'password', type: 'string', required: true, desc: 'Account password (body JSON)' },
    ],
    response: '{ "access_token": "eyJ...", "token_type": "bearer", "api_key": "aegis_live_..." }',
  },
  {
    method: 'GET',
    path: '/auth/me',
    auth: true,
    authMethod: 'JWT',
    description: 'Returns the current authenticated user\'s profile, including their API key.',
    params: [],
    response: '{ "id": 1, "username": "analyst", "api_key": "aegis_live_..." }',
  },
  {
    method: 'POST',
    path: '/auth/regenerate-api-key',
    auth: true,
    authMethod: 'JWT',
    description: 'Invalidates the current API key and issues a new cryptographically-random one. Any agents using the old key must be reconfigured.',
    params: [],
    response: '{ "api_key": "aegis_live_..." }',
  },
  {
    method: 'POST',
    path: '/auth/change-password',
    auth: true,
    authMethod: 'JWT',
    description: 'Change the account password. Requires the current password for verification.',
    params: [
      { name: 'current_password', type: 'string', required: true, desc: 'Existing password (body JSON)' },
      { name: 'new_password',     type: 'string', required: true, desc: 'New password (body JSON)' },
    ],
    response: '{ "message": "Password updated successfully" }',
  },
  {
    method: 'DELETE',
    path: '/auth/me',
    auth: true,
    authMethod: 'JWT',
    description: 'Permanently deletes the authenticated account and all data owned by it (logs, alerts, blocked IPs). Irreversible.',
    params: [],
    response: '{ "message": "Account deleted" }',
  },
  // ── Logs ──────────────────────────────────────────────────────────
  {
    method: 'GET',
    path: '/logs',
    auth: true,
    authMethod: 'JWT',
    description: 'List log entries belonging to the authenticated user. Filterable by source_ip and event_type.',
    params: [
      { name: 'source_ip',   type: 'string', required: false, desc: 'Filter by source IP address' },
      { name: 'event_type',  type: 'string', required: false, desc: 'Filter by event type (e.g. login_failed)' },
      { name: 'limit',       type: 'int',    required: false, desc: 'Results per page (default: 50)' },
    ],
    response: '{ "logs": [...], "total": 1024 }',
  },
  // ── Alerts ────────────────────────────────────────────────────────
  {
    method: 'GET',
    path: '/alerts',
    auth: true,
    authMethod: 'JWT',
    description: 'List all security alerts for the authenticated user, ordered by timestamp descending. Filterable by status.',
    params: [
      { name: 'status', type: 'string', required: false, desc: 'Filter by status: open | approved | dismissed' },
      { name: 'limit',  type: 'int',    required: false, desc: 'Results per page (default: 20)' },
    ],
    response: '{ "alerts": [...], "total": 38 }',
  },
  {
    method: 'GET',
    path: '/alerts/{id}',
    auth: true,
    authMethod: 'JWT',
    description: 'Retrieve full details of a single alert, including the AI analyst report, related log entries, and MITRE ATT&CK mapping.',
    params: [
      { name: 'id', type: 'int', required: true, desc: 'Alert ID (path parameter)' },
    ],
    response: '{ "id": 42, "type": "brute_force", "severity": "high", "analysis": { ... }, "mitre": "T1110" }',
  },
  {
    method: 'POST',
    path: '/alerts/{id}/analyze',
    auth: true,
    authMethod: 'JWT',
    description: 'Trigger the AI analyst to (re-)analyze an alert. The Groq LLaMA 3.3 70B model generates a structured report.',
    params: [
      { name: 'id', type: 'int', required: true, desc: 'Alert ID (path parameter)' },
    ],
    response: '{ "status": "queued", "alert_id": 42 }',
  },
  {
    method: 'POST',
    path: '/alerts/{id}/status',
    auth: true,
    authMethod: 'JWT',
    description: 'Approve or dismiss an alert. Approving records a simulated IP block entry — no real firewall or network device is modified.',
    params: [
      { name: 'id',     type: 'int',    required: true,  desc: 'Alert ID (path parameter)' },
      { name: 'action', type: 'string', required: true,  desc: '"approve" or "dismiss" (body JSON)' },
      { name: 'reason', type: 'string', required: false, desc: 'Optional reason / notes (body JSON)' },
    ],
    response: '{ "status": "approved", "alert_id": 42, "simulated_block_created": true }',
  },
  // ── Blocked IPs ───────────────────────────────────────────────────
  {
    method: 'GET',
    path: '/blocked-ips',
    auth: true,
    authMethod: 'JWT',
    description: 'List simulated IP block records for the authenticated user. These are records only — no firewall rules are created.',
    params: [],
    response: '{ "blocked_ips": [...] }',
  },
  {
    method: 'POST',
    path: '/blocked-ips/{id}/unblock',
    auth: true,
    authMethod: 'JWT',
    description: 'Remove a simulated IP block record. As with blocking, this does not interact with any real network device.',
    params: [
      { name: 'id', type: 'int', required: true, desc: 'Block record ID (path parameter)' },
    ],
    response: '{ "message": "Unblocked" }',
  },
  // ── Demo & Ingest ─────────────────────────────────────────────────
  {
    method: 'POST',
    path: '/demo/seed',
    auth: true,
    authMethod: 'JWT',
    description: 'Generate a batch of sample log data for the authenticated user and trigger one random attack scenario (brute force, geo anomaly, etc.) through the full detection + AI pipeline.',
    params: [],
    response: '{ "logs_created": 120, "scenario": "brute_force", "alert_id": 55 }',
  },
  {
    method: 'POST',
    path: '/ingest/logs',
    auth: true,
    authMethod: 'API_KEY',
    description: 'Real log ingestion endpoint for unattended agents. Accepts a batch of normalized log events and runs them through the same detection and AI pipeline as demo data. Authenticated via X-API-Key header — not JWT.',
    params: [
      { name: 'events', type: 'array', required: true, desc: 'Array of normalized log event objects (body JSON)' },
    ],
    response: '{ "ingested": 15, "alerts_triggered": 1 }',
  },
];

const FAQ_ITEMS = [
  {
    q: 'How does the detection engine work?',
    a: 'Aegis AI runs a detection loop every 10 seconds, scanning incoming log entries against 5 built-in rules. When a rule fires (e.g. ≥ 5 failed logins from the same IP in 60 s), an alert is created and queued for AI analysis via Groq.',
  },
  {
    q: 'What AI model powers the analyst?',
    a: "Groq's LLaMA 3.3 70B Versatile model, accessed via Groq's OpenAI-compatible API. The model receives a structured prompt with alert metadata, matched log lines, and source IP context, and returns a JSON report with severity, MITRE mapping, and a recommended action.",
  },
  {
    q: 'Is the IP blocking real?',
    a: 'No. Approving an alert records a simulated block entry in the database for demonstration purposes. No firewall rule, ACL, or network device is modified at any point.',
  },
  {
    q: 'Can I ingest my own real logs?',
    a: 'Yes. Use the POST /ingest/logs endpoint with your account API key (X-API-Key header). The included Windows Event Log tailing agent (agent/windows_event_tailer.py) is one ready-to-use client — it reads real Windows Security Event Log entries and ships them through the same detection and AI pipeline as demo data.',
  },
  {
    q: 'How do I get my API key?',
    a: 'Your API key is issued automatically when you register. You can view it on the Settings page or via GET /auth/me. If you need to rotate it, use POST /auth/regenerate-api-key — this invalidates the old key immediately.',
  },
  {
    q: 'Is this a production-hardened commercial product?',
    a: 'No. Aegis AI is a portfolio and demonstration platform. It is built with real technology (FastAPI, PostgreSQL, Groq inference, JWT auth, per-user data isolation) and accepts real log data, but it is not operated as a hardened commercial SIEM.',
  },
  {
    q: 'What is the Experimental Packet Monitoring feature?',
    a: 'Packet monitoring is an opt-in, experimental capability powered by the scapy Python library. It passively sniffs live traffic on a chosen network interface and extracts basic metadata — source/destination IP, protocol (TCP/UDP/DNS), destination port, and TCP flags. No payload data or packet content is ever captured or stored, so there is no privacy-sensitive deep packet inspection. On Windows, it additionally requires Npcap (https://npcap.com) to be installed and must be run as Administrator for raw socket access. The captured metadata feeds two heuristic detection rules: SYN flood (T1498) and DNS tunneling (T1071.004).',
  },
];

function CodeBlock({ code, language = 'bash' }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  return (
    <div className="code-block glass">
      <div className="code-block-header">
        <span className="code-lang">{language}</span>
        <button className="copy-btn" onClick={copy}>
          {copied ? '✓ Copied' : '⎘ Copy'}
        </button>
      </div>
      <pre className="code-pre"><code>{code}</code></pre>
    </div>
  );
}

function MethodBadge({ method }) {
  return <span className={`method-badge method-${method.toLowerCase()}`}>{method}</span>;
}

function AuthMethodBadge({ authMethod }) {
  if (!authMethod) return null;
  if (authMethod === 'API_KEY') {
    return (
      <span className="auth-badge auth-badge-apikey">
        🔑 X-API-Key
      </span>
    );
  }
  return (
    <span className="auth-badge">
      🔒 JWT Bearer
    </span>
  );
}

function FaqItem({ q, a }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`faq-item glass ${open ? 'faq-open' : ''}`}>
      <button className="faq-question" onClick={() => setOpen(!open)}>
        <span>{q}</span>
        <span className="faq-chevron">▼</span>
      </button>
      <div className="faq-answer-wrapper">
        <div className="faq-answer-inner">
          <p className="faq-answer">{a}</p>
        </div>
      </div>
    </div>
  );
}

export default function Docs() {
  const [activeSection, setActiveSection] = useState('overview');
  const contentRef = useRef(null);

  // Highlight sidebar link on scroll
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id);
          }
        });
      },
      { rootMargin: '-30% 0px -60% 0px', threshold: 0 }
    );
    SECTIONS.forEach(({ id }) => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, []);

  const scrollTo = (id) => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <>
      <div className="orb orb-cyan" style={{ position: 'fixed' }} />
      <div className="orb orb-purple" style={{ position: 'fixed' }} />
      <Navbar />
      <div className="page docs-page">

      <div className="docs-layout">
        {/* ── Left Sidebar ─────────────────────────────────── */}
        <aside className="docs-sidebar glass">
          <div className="sidebar-header">
            <span className="sidebar-icon gradient-text">⬡</span>
            <span className="sidebar-title">Documentation</span>
          </div>
          <p className="sidebar-version">v1.0 · REST API</p>
          <nav className="sidebar-nav">
            {SECTIONS.map(({ id, label, icon }) => (
              <button
                key={id}
                className={`sidebar-link ${activeSection === id ? 'active' : ''}`}
                onClick={() => scrollTo(id)}
              >
                <span className="sidebar-link-icon">{icon}</span>
                {label}
              </button>
            ))}
          </nav>
          <div className="sidebar-footer glass-glow">
            <span className="status-dot" />
            <span>API Status: <strong className="gradient-text">Operational</strong></span>
          </div>
        </aside>

        {/* ── Main Content ──────────────────────────────────── */}
        <main className="docs-content" ref={contentRef}>

          {/* ── Overview ─── */}
          <section id="overview" className="docs-section">
            <div className="section-eyebrow">
              <span className="eyebrow-dot" />
              Introduction
            </div>
            <h1 className="docs-h1">
              Aegis AI <span className="gradient-text">Documentation</span>
            </h1>
            <p className="docs-lead">
              Aegis AI is a multi-tenant SIEM platform with an AI analyst agent. It combines a
              real-time log detection engine with a LLaMA 3.3 70B analyst that automatically
              triages, explains, and recommends actions for every alert — so your team can make
              fast, confident decisions.
            </p>

            <div className="info-cards">
              <div className="info-card glass-glow">
                <div className="info-card-icon">⬡</div>
                <div>
                  <strong>Multi-tenant</strong>
                  <p>Full per-user data isolation — every account sees only its own logs and alerts</p>
                </div>
              </div>
              <div className="info-card glass-glow">
                <div className="info-card-icon">⬡</div>
                <div>
                  <strong>Groq LLaMA 3.3 70B</strong>
                  <p>Every alert gets a structured AI analysis report</p>
                </div>
              </div>
              <div className="info-card glass-glow">
                <div className="info-card-icon">⬡</div>
                <div>
                  <strong>Real log ingestion</strong>
                  <p>Accepts both simulated demo data and live Windows Event Log entries</p>
                </div>
              </div>
              <div className="info-card glass-glow">
                <div className="info-card-icon">⬡</div>
                <div>
                  <strong>MITRE ATT&CK</strong>
                  <p>All 5 detection rules are mapped to ATT&CK techniques</p>
                </div>
              </div>
            </div>

            <div className="architecture-note glass">
              <span className="arch-icon">⬡</span>
              <div>
                <strong>Architecture at a glance</strong>
                <p>
                  FastAPI + PostgreSQL backend · React + Vite frontend · JWT authentication
                  with full per-user data isolation · Groq AI inference (LLaMA 3.3 70B) ·
                  Docker Compose deployment · Windows Event Log tailing agent for real data ingestion
                </p>
              </div>
            </div>
          </section>

          <div className="docs-divider" />

          {/* ── Quick Start ─── */}
          <section id="quickstart" className="docs-section">
            <div className="section-eyebrow">
              <span className="eyebrow-dot" />
              Quick Start
            </div>
            <h2 className="docs-h2">Get up and running in minutes</h2>
            <p className="docs-body">
              Aegis AI ships as a Docker Compose stack. Clone the repository, add your Groq API key,
              and you're live.
            </p>

            <h3 className="docs-h3">1 · Clone &amp; configure</h3>
            <CodeBlock language="bash" code={`git clone https://github.com/divp112005-coder/Aegis_AI.git
cd Aegis_AI

# Copy the environment template and fill in your keys
cp backend/.env.example backend/.env`} />

            <h3 className="docs-h3">2 · Add your Groq API key</h3>
            <p className="docs-body">Open <code className="inline-code">backend/.env</code> and set:</p>
            <CodeBlock language="env" code={`GROQ_API_KEY=gsk_your_key_here
SECRET_KEY=change_me_to_a_random_string
DATABASE_URL=postgresql://aegis:aegis@db:5432/aegis`} />

            <h3 className="docs-h3">3 · Start with Docker Compose</h3>
            <CodeBlock language="bash" code={`docker compose up --build

# Frontend  → http://localhost:5173
# Backend   → http://localhost:8000
# API docs  → http://localhost:8000/docs`} />

            <h3 className="docs-h3">4 · Authenticate via the API</h3>
            <CodeBlock language="bash" code={`# Register a new account — returns JWT + API key
curl -X POST http://127.0.0.1:8000/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{"username": "analyst", "password": "s3cur3!"}'

# → {"access_token": "eyJ...", "token_type": "bearer", "api_key": "aegis_live_..."}

# Use the JWT for dashboard / browser requests
export TOKEN="eyJ..."
curl http://127.0.0.1:8000/alerts \\
  -H "Authorization: Bearer $TOKEN"`} />
          </section>

          <div className="docs-divider" />

          {/* ── API Reference ─── */}
          <section id="api-reference" className="docs-section">
            <div className="section-eyebrow">
              <span className="eyebrow-dot" />
              API Reference
            </div>
            <h2 className="docs-h2">REST API</h2>

            {/* Auth methods note */}
            <div className="auth-methods-note glass-glow">
              <span className="auth-note-icon">🔐</span>
              <div>
                <strong>Two authentication methods</strong>
                <ul className="auth-methods-list">
                  <li>
                    <code className="inline-code">Authorization: Bearer &lt;token&gt;</code>
                    {' '}— <strong>JWT</strong> issued at login/register. Used by the browser dashboard for all interactive requests.
                  </li>
                  <li>
                    <code className="inline-code">X-API-Key: aegis_live_...</code>
                    {' '}— <strong>API key</strong> issued alongside the JWT. Used by unattended log-shipping agents (e.g. the Windows Event Log tailer) that run without a browser session. Only required for <code className="inline-code">POST /ingest/logs</code>.
                  </li>
                </ul>
                <p className="auth-note-footer">These are separate credentials serving different purposes — you do not need to choose one over the other.</p>
              </div>
            </div>

            <div className="api-base-url glass">
              <span className="api-base-label">Base URL</span>
              <code className="api-base-code">http://127.0.0.1:8000</code>
            </div>

            <div className="endpoints-list">
              {API_ENDPOINTS.map((ep, i) => (
                <div key={i} className="endpoint-card glass">
                  <div className="endpoint-header">
                    <MethodBadge method={ep.method} />
                    <code className="endpoint-path">{ep.path}</code>
                    {ep.auth && <AuthMethodBadge authMethod={ep.authMethod} />}
                  </div>

                  <p className="endpoint-desc">{ep.description}</p>

                  {ep.params.length > 0 && (
                    <div className="params-table-wrap">
                      <table className="params-table">
                        <thead>
                          <tr>
                            <th>Parameter</th>
                            <th>Type</th>
                            <th>Required</th>
                            <th>Description</th>
                          </tr>
                        </thead>
                        <tbody>
                          {ep.params.map((p, j) => (
                            <tr key={j}>
                              <td><code className="param-name">{p.name}</code></td>
                              <td><span className="param-type">{p.type}</span></td>
                              <td>
                                <span className={`param-req ${p.required ? 'req-yes' : 'req-no'}`}>
                                  {p.required ? 'Yes' : 'No'}
                                </span>
                              </td>
                              <td className="param-desc-cell">{p.desc}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  <div className="endpoint-response">
                    <span className="response-label">Sample response</span>
                    <CodeBlock language="json" code={ep.response} />
                  </div>
                </div>
              ))}
            </div>
          </section>

          <div className="docs-divider" />

          {/* ── Detection Rules ─── */}
          <section id="detection-rules" className="docs-section">
            <div className="section-eyebrow">
              <span className="eyebrow-dot" />
              Detection Rules
            </div>
            <h2 className="docs-h2">How alerts are generated</h2>
            <p className="docs-body">
              The detection engine runs every 10 seconds and evaluates all incoming log entries
              against 5 built-in rules. When a rule fires, an alert is created and immediately
              queued for AI analysis.
            </p>

            <div className="rules-grid">
              {[
                {
                  name: 'Brute Force',
                  tag: 'T1110',
                  color: 'red',
                  icon: '🔨',
                  desc: '5 or more failed login events from the same source IP within a 1-minute window.',
                  threshold: '≥ 5 failures / 60 s',
                },
                {
                  name: 'Geo Anomaly',
                  tag: 'T1078',
                  color: 'amber',
                  icon: '🌍',
                  desc: 'Successful login from a country or region not seen for that user in the past 30 days.',
                  threshold: 'New location / 30-day baseline',
                },
                {
                  name: 'Off-Hours Login',
                  tag: 'T1078',
                  color: 'lavender',
                  icon: '🕑',
                  desc: 'Successful login occurring between 00:00–05:00 UTC, regardless of prior activity.',
                  threshold: 'Login 00:00–05:00 UTC',
                },
                {
                  name: 'Privilege Escalation',
                  tag: 'T1078.003 / T1098',
                  color: 'rose',
                  icon: '⬆️',
                  desc: 'A privilege change event shortly after login, originating from a non-local (external) IP address.',
                  threshold: 'Privilege change + external IP',
                },
                {
                  name: 'Impossible Travel',
                  tag: 'T1078',
                  color: 'teal',
                  icon: '✈️',
                  desc: 'The same user account logs in from two geographically distant locations within 10 minutes — physically impossible to travel between.',
                  threshold: 'Same user, 2 distant logins / 10 min',
                },
                {
                  name: 'SYN Flood',
                  tag: 'T1498',
                  color: 'red',
                  icon: '🌊',
                  desc: 'High volume of TCP packets from a single source IP, consistent with a volumetric SYN flood / Network Denial of Service attack. Requires the scapy packet monitor agent.',
                  threshold: '≥ 100 packets / 60 s',
                  experimental: true,
                },
                {
                  name: 'DNS Tunneling',
                  tag: 'T1071.004',
                  color: 'amber',
                  icon: '🕵️',
                  desc: 'High frequency of DNS requests to port 53 from a single source, indicating potential data exfiltration or C2 communication hidden inside DNS traffic. Requires the scapy packet monitor agent.',
                  threshold: '≥ 50 queries / 60 s',
                  experimental: true,
                },
              ].map((rule) => (
                <div key={rule.name} className="rule-card glass-glow">
                  <div className="rule-header">
                    <span className="rule-icon">{rule.icon}</span>
                    <div>
                      <div className="rule-name">
                        {rule.name}
                        {rule.experimental && (
                          <span style={{
                            marginLeft: '0.5rem',
                            fontSize: '0.62rem',
                            fontWeight: 700,
                            letterSpacing: '0.06em',
                            padding: '0.15rem 0.45rem',
                            borderRadius: '4px',
                            background: 'rgba(139,92,246,0.15)',
                            color: '#a78bfa',
                            border: '1px solid rgba(139,92,246,0.3)',
                            verticalAlign: 'middle',
                            textTransform: 'uppercase',
                          }}>Experimental</span>
                        )}
                      </div>
                      <div className={`rule-mitre mitre-${rule.color}`}>{rule.tag}</div>
                    </div>
                  </div>
                  <p className="rule-desc">{rule.desc}</p>
                  <div className="rule-threshold glass">
                    <span className="threshold-label">Condition</span>
                    <code className="threshold-value">{rule.threshold}</code>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <div className="docs-divider" />

          {/* ── API Keys & Real Data Ingestion ─── */}
          <section id="api-keys" className="docs-section">
            <div className="section-eyebrow">
              <span className="eyebrow-dot" />
              API Keys &amp; Real Data Ingestion
            </div>
            <h2 className="docs-h2">Shipping real logs to Aegis AI</h2>
            <p className="docs-body">
              Every account is issued a unique, cryptographically-random API key at registration.
              This key follows the format <code className="inline-code">aegis_live_</code> + 32 hex
              characters and is viewable (and regenerable) on the Settings page.
            </p>

            <div className="info-cards" style={{ marginBottom: '1.5rem' }}>
              <div className="info-card glass-glow">
                <div className="info-card-icon">🔑</div>
                <div>
                  <strong>Agents only</strong>
                  <p>The API key is for log-shipping agents. It is never used for browser login — that uses the JWT.</p>
                </div>
              </div>
              <div className="info-card glass-glow">
                <div className="info-card-icon">🔄</div>
                <div>
                  <strong>Rotatable</strong>
                  <p>Regenerate at any time from Settings or via POST /auth/regenerate-api-key. The old key is invalidated immediately.</p>
                </div>
              </div>
              <div className="info-card glass-glow">
                <div className="info-card-icon">🪟</div>
                <div>
                  <strong>Windows Event Log agent</strong>
                  <p>A ready-to-use Python agent that tails the Windows Security Event Log and ships events in real time.</p>
                </div>
              </div>
            </div>

            <h3 className="docs-h3">Running the Windows Event Log agent</h3>
            <p className="docs-body">
              The included agent (<code className="inline-code">agent/windows_event_tailer.py</code>) reads
              real Windows Security Event Log entries — logon, logoff, and privilege change events —
              normalizes them, and posts them to <code className="inline-code">POST /ingest/logs</code> using
              your account's API key. The ingested events pass through the same 5-rule detection engine
              and Groq AI pipeline as demo data.
            </p>
            <CodeBlock language="bash" code={`# Run on the Windows machine you want to monitor
python agent/windows_event_tailer.py --api-key aegis_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# The agent will continuously tail the Security Event Log
# and ship normalized events to the Aegis AI backend.`} />

            <h3 className="docs-h3">What the agent sends</h3>
            <CodeBlock language="json" code={`// Example normalized event payload (one item in the "events" array)
{
  "event_id": 4625,
  "event_type": "login_failed",
  "source_ip": "192.168.1.50",
  "username": "administrator",
  "timestamp": "2026-06-21T10:15:30Z",
  "hostname": "WORKSTATION-01",
  "raw": "An account failed to log on..."
}`} />

            <div className="ai-note glass-glow">
              <span className="ai-note-icon">⬡</span>
              <div>
                <strong>Same pipeline, real data</strong>
                <p>
                  Log events ingested via the agent are stored under your account and processed
                  identically to demo data — the same detection rules run, the same AI model
                  analyzes triggered alerts, and the same dashboard surfaces results.
                </p>
              </div>
            </div>
          </section>

          <div className="docs-divider" />

          {/* ── AI Analyst ─── */}
          <section id="ai-analyst" className="docs-section">
            <div className="section-eyebrow">
              <span className="eyebrow-dot" />
              AI Analyst
            </div>
            <h2 className="docs-h2">The autonomous AI agent</h2>
            <p className="docs-body">
              When an alert is created (or re-analyzed via <code className="inline-code">POST /alerts/{'{id}'}/analyze</code>),
              Aegis AI submits a structured prompt to LLaMA 3.3 70B via the Groq API. The model
              returns a JSON-structured report that is stored alongside the alert and displayed in the dashboard.
            </p>

            <div className="ai-pipeline glass">
              {[
                { step: '1', label: 'Log Ingestion',          icon: '📥', sub: 'real or simulated' },
                { step: '2', label: 'Detection Engine',       icon: '🔍', sub: '5 rules, 10 s interval' },
                { step: '3', label: 'Groq LLaMA 3.3 70B',    icon: '🤖', sub: 'AI analysis' },
                { step: '4', label: 'Structured Report',      icon: '📊', sub: 'severity, MITRE, action' },
                { step: '5', label: 'Dashboard',              icon: '👤', sub: 'analyst reviews' },
              ].map((s, i, arr) => (
                <div key={s.step} className="pipeline-step">
                  <div className="pipeline-node">
                    <span className="pipeline-icon">{s.icon}</span>
                    <span className="pipeline-label">{s.label}</span>
                    {s.sub && <span className="pipeline-sub">{s.sub}</span>}
                  </div>
                  {i < arr.length - 1 && <span className="pipeline-arrow">→</span>}
                </div>
              ))}
            </div>

            <h3 className="docs-h3">Sample AI report structure</h3>
            <CodeBlock language="json" code={`{
  "summary": "Multiple failed login attempts detected from 45.155.205.233 (NL) targeting the 'admin' account. Pattern consistent with automated credential stuffing.",
  "severity": "HIGH",
  "mitre": {
    "technique": "T1110",
    "name": "Brute Force",
    "tactic": "Credential Access"
  },
  "context": {
    "source_ip": "45.155.205.233",
    "geo": "Netherlands",
    "target_account": "admin",
    "attempt_count": 6,
    "window_seconds": 52
  },
  "recommended_action": "Block 45.155.205.233 at the firewall level and enable MFA on the admin account.",
  "analyst_notes": "Foreign IP with no prior legitimate access history. Privileged account targeted."
}`} />

            <div className="ai-note glass-glow">
              <span className="ai-note-icon">⬡</span>
              <div>
                <strong>Human-in-the-loop by design</strong>
                <p>
                  The AI <em>recommends</em> — your analyst decides. Every alert requires explicit
                  approval or dismissal before any action is recorded. Approving an alert creates a
                  simulated block record; no automated firewall change occurs.
                </p>
              </div>
            </div>
          </section>

          <div className="docs-divider" />

          {/* ── FAQ ─── */}
          <section id="faq" className="docs-section">
            <div className="section-eyebrow">
              <span className="eyebrow-dot" />
              FAQ
            </div>
            <h2 className="docs-h2">Frequently asked questions</h2>
            <div className="faq-list">
              {FAQ_ITEMS.map((item, i) => (
                <FaqItem key={i} q={item.q} a={item.a} />
              ))}
            </div>

            <div className="docs-cta glass-strong">
              <span className="cta-icon">⬡</span>
              <div>
                <strong>Still have questions?</strong>
                <p>Open an issue on GitHub or start a discussion — we respond within 24 hours.</p>
              </div>
              <a
                href="https://github.com/divp112005-coder/Aegis_AI/issues"
                target="_blank"
                rel="noreferrer"
                className="btn btn-primary"
              >
                Open GitHub Issue →
              </a>
            </div>
          </section>

          {/* ── Footer ─── */}
          <footer className="footer">
            <div className="footer-brand">
              <span className="brand-icon">⬡</span>
              <span className="gradient-text" style={{ fontWeight: 700 }}>Aegis AI</span>
            </div>
            <p className="footer-copy">© 2026 Aegis AI. Built with FastAPI, PostgreSQL, React, and LLaMA 3.3 70B.</p>
            <div className="footer-links">
              <a href="/docs">Docs</a>
              <a href="/pricing">Pricing</a>
              <a href="https://github.com/divp112005-coder/Aegis_AI" target="_blank" rel="noreferrer">GitHub</a>
            </div>
          </footer>
        </main>
      </div>
      </div>
    </>
  );
}
