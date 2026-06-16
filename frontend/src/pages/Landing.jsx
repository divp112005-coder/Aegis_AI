import { Link } from 'react-router-dom';
import Navbar from '../components/Navbar';
import './Landing.css';

const FEATURES = [
  { icon: '⚡', title: 'Real-Time Detection', desc: 'Brute-force, anomaly, and threat pattern detection running every 10 seconds across all your log sources.' },
  { icon: '🤖', title: 'AI Analyst Agent', desc: 'LLaMA 3.3 70B automatically investigates every alert — summary, MITRE ATT&CK mapping, and recommended action.' },
  { icon: '🛡️', title: 'Human-in-the-Loop', desc: 'AI recommends, you decide. Approve or dismiss alerts with full context before any action is taken.' },
  { icon: '📊', title: 'Live Dashboard', desc: 'Real-time alert feed with severity heatmaps, related log timelines, and full analyst reports on click.' },
  { icon: '🔗', title: 'REST API', desc: 'Integrate with your existing stack. Full API access with JWT auth, filterable log queries, and webhook support.' },
  { icon: '🗺️', title: 'MITRE ATT&CK', desc: 'Every alert is automatically tagged with the relevant ATT&CK technique ID — no manual mapping needed.' },
];

const STATS = [
  { value: '< 10s', label: 'Detection latency' },
  { value: '99.9%', label: 'API uptime' },
  { value: 'LLaMA 3.3', label: 'AI model' },
  { value: 'T1110', label: 'ATT&CK coverage' },
];

export default function Landing() {
  return (
    <div className="page landing">
      <div className="orb orb-cyan" />
      <div className="orb orb-purple" />
      <div className="orb orb-pink" />
      <Navbar />

      {/* Hero */}
      <section className="hero">
        <div className="hero-badge glass">
          <span className="badge-dot" />
          AI-Powered Security Operations
        </div>
        <h1 className="hero-title">
          Your SOC,<br />
          <span className="gradient-text">Supercharged by AI</span>
        </h1>
        <p className="hero-sub">
          Aegis AI combines real-time threat detection with autonomous AI investigation.
          Stop drowning in alerts — let the AI triage, explain, and recommend while you make the call.
        </p>
        <div className="hero-actions">
          <Link to="/auth?mode=signup" className="btn btn-primary btn-lg">
            Start Free Trial →
          </Link>
          <Link to="/docs" className="btn btn-ghost btn-lg">
            View Docs
          </Link>
        </div>

        {/* Mock terminal */}
        <div className="hero-terminal glass-strong">
          <div className="terminal-bar">
            <span className="t-dot red" /><span className="t-dot amber" /><span className="t-dot green" />
            <span className="terminal-title">aegis-ai / live feed</span>
          </div>
          <div className="terminal-body">
            <p><span className="t-time">15:47:04</span> <span className="t-alert">[ALERT]</span> brute_force detected — <span className="t-ip">45.155.205.233</span> → admin (6 attempts/60s)</p>
            <p><span className="t-time">15:47:05</span> <span className="t-ai">[AI]</span> Analyzing alert #1... MITRE T1110 — Brute Force</p>
            <p><span className="t-time">15:47:06</span> <span className="t-ai">[AI]</span> Severity: <span className="t-high">HIGH</span> — Foreign IP (Netherlands), privileged target</p>
            <p><span className="t-time">15:47:06</span> <span className="t-ai">[AI]</span> Recommended: Block 45.155.205.233, enable MFA on admin</p>
            <p><span className="t-time">15:47:09</span> <span className="t-ok">[ANALYST]</span> Alert approved — IP blocked via firewall rule</p>
            <p className="t-cursor">█</p>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section className="stats-section">
        {STATS.map((s) => (
          <div key={s.label} className="stat-card glass">
            <div className="stat-value gradient-text">{s.value}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </section>

      {/* Features */}
      <section className="features-section">
        <h2 className="section-title">Everything your SOC needs</h2>
        <p className="section-sub">Built for security teams that want AI as an analyst, not a black box.</p>
        <div className="features-grid">
          {FEATURES.map((f) => (
            <div key={f.title} className="feature-card glass-glow">
              <div className="feature-icon">{f.icon}</div>
              <h3>{f.title}</h3>
              <p>{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="cta-section">
        <div className="cta-card glass-strong">
          <h2>Start protecting your infrastructure today</h2>
          <p>Free tier includes 1,000 log events/day and full AI analysis. No credit card required.</p>
          <Link to="/auth?mode=signup" className="btn btn-primary btn-lg">
            Create Free Account →
          </Link>
        </div>
      </section>

      <footer className="footer">
        <div className="footer-brand">
          <span className="brand-icon">⬡</span>
          <span className="gradient-text" style={{ fontWeight: 700 }}>Aegis AI</span>
        </div>
        <p className="footer-copy">© 2026 Aegis AI. Built with FastAPI, React, and LLaMA 3.3.</p>
        <div className="footer-links">
          <Link to="/docs">Docs</Link>
          <Link to="/pricing">Pricing</Link>
          <a href="https://github.com/divp112005-coder/Aegis_AI" target="_blank" rel="noreferrer">GitHub</a>
        </div>
      </footer>
    </div>
  );
}
