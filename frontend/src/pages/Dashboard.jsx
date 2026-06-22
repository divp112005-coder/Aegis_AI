import { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import Navbar from '../components/Navbar';
import './Dashboard.css';

const API_BASE = 'http://127.0.0.1:8000';

/* ── Network alert classification ───────────────────────────────────── */
const NETWORK_ALERT_TYPES = new Set(['port_scan', 'suspicious_port', 'connection_volume']);
const SUSPICIOUS_PORTS    = new Set([4444, 31337, 1337, 6666, 6667, 12345, 54321, 8081, 9001, 3389, 5900, 23]);

const isNetworkAlert = (type) => NETWORK_ALERT_TYPES.has(type);

/* Helper: just the filename from a Windows path */
const basename = (p) => (p ? p.split('\\').pop() : null);

/* ── Alert-type icon badge ───────────────────────────────────────────── */
function AlertTypeIcon({ alertType }) {
  if (!alertType) return null;
  const icon = isNetworkAlert(alertType) ? '🌐' : '🔐';
  return <span className="alert-type-icon" title={alertType}>{icon}</span>;
}

/* ── Details JSON panel ─────────────────────────────────────────────── */
const DETAIL_FIELD_LABELS = {
  distinct_ports_scanned: 'Ports Scanned',
  dest_port:              'Destination Port',
  connection_count:       'Connection Count',
  application:            'Application',
  window_minutes:         'Detection Window',
  protocol:               'Protocol',
  remote_ip:              'Remote IP',
};

function AlertDetailsSection({ details, alertType }) {
  if (!details) return null;
  let parsed = {};
  try { parsed = typeof details === 'string' ? JSON.parse(details) : details; } catch { return null; }
  const entries = Object.entries(parsed);
  if (entries.length === 0) return null;

  return (
    <div className="detail-section">
      <h4 className="section-label">Detection Details</h4>
      <div className="detail-kv-list">
        {entries.map(([k, v]) => {
          const label = DETAIL_FIELD_LABELS[k] || k.replace(/_/g, ' ');
          let display = v;
          if (k === 'application' && v) display = basename(String(v));
          if (k === 'window_minutes' && v != null) display = `${v} min`;
          return (
            <div key={k} className="detail-kv-row">
              <span className="detail-kv-label">{label}</span>
              <span className={`detail-kv-val${k === 'dest_port' || k === 'protocol' ? ' mono' : ''}`}>
                {k === 'dest_port' && SUSPICIOUS_PORTS.has(Number(v))
                  ? <span className="port-suspicious">{String(display ?? '—')}</span>
                  : String(display ?? '—')}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}


const SEVERITY_COLORS = {
  critical: '#B84060',
  high:     '#C4613A',
  medium:   '#A07830',
  low:      '#4A9E7E',
  unknown:  '#9B7A8C',
};

const SEVERITY_BG = {
  critical: 'rgba(184,64,96,0.12)',
  high:     'rgba(196,97,58,0.12)',
  medium:   'rgba(160,120,48,0.12)',
  low:      'rgba(74,158,126,0.12)',
  unknown:  'rgba(155,122,140,0.10)',
};

function SeverityBadge({ severity }) {
  const s = (severity || 'unknown').toLowerCase();
  return (
    <span
      className="severity-badge"
      style={{
        color: SEVERITY_COLORS[s] || SEVERITY_COLORS.unknown,
        background: SEVERITY_BG[s] || SEVERITY_BG.unknown,
        border: `1px solid ${SEVERITY_COLORS[s] || SEVERITY_COLORS.unknown}40`,
      }}
    >
      {severity}
    </span>
  );
}

function StatusBadge({ status }) {
  return <span className={`status-badge status-${status}`}>{status}</span>;
}

/* ── Toast Notification ─────────────────────────────────────────────── */
function Toast({ toasts, onDismiss }) {
  return (
    <div className="toast-container">
      {toasts.map((t) => (
        <div key={t.id} className={`toast toast-${t.type}`}>
          <div className="toast-body">
            <span className="toast-icon">{t.icon}</span>
            <div className="toast-text">
              <span className="toast-message">{t.message}</span>
              {t.simulated && (
                <span className="simulated-badge">SIMULATED</span>
              )}
            </div>
          </div>
          <button className="toast-close" onClick={() => onDismiss(t.id)}>×</button>
        </div>
      ))}
    </div>
  );
}

/* ── Blocked IPs Panel ──────────────────────────────────────────────── */
function BlockedIPsPanel({ token }) {
  const [blocks, setBlocks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [unblocking, setUnblocking] = useState(null);

  const fetchBlocks = useCallback(async () => {
    if (!token) return;
    try {
      setError('');
      const res = await fetch(`${API_BASE}/blocked-ips`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Failed to fetch blocked IPs');
      const data = await res.json();
      setBlocks(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchBlocks();
  }, [fetchBlocks]);

  const handleUnblock = async (blockId) => {
    setUnblocking(blockId);
    try {
      const res = await fetch(`${API_BASE}/blocked-ips/${blockId}/unblock`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || 'Unblock failed');
      }
      await fetchBlocks();
    } catch (err) {
      setError(err.message);
    } finally {
      setUnblocking(null);
    }
  };

  const blockedCount   = blocks.filter((b) => b.status === 'blocked').length;
  const unblockedCount = blocks.filter((b) => b.status === 'unblocked').length;

  return (
    <div className="blocked-ips-panel glass">
      {/* Header */}
      <div className="blocked-ips-header">
        <div className="blocked-ips-title-group">
          <span className="blocked-ips-icon">🛡️</span>
          <div>
            <h3 className="blocked-ips-title">Blocked IPs</h3>
            <p className="blocked-ips-sub">Simulated firewall block-list</p>
          </div>
        </div>
        <div className="blocked-ips-meta">
          <span className="simulated-badge simulated-badge-lg">SIMULATED</span>
          <button
            className="btn-outline btn btn-refresh"
            onClick={fetchBlocks}
            title="Refresh list"
          >
            ↺ Refresh
          </button>
        </div>
      </div>

      {/* Stats strip */}
      <div className="blocked-ips-stats">
        <div className="bip-stat">
          <span className="bip-stat-num" style={{ color: '#B84060' }}>{blockedCount}</span>
          <span className="bip-stat-lbl">Currently Blocked</span>
        </div>
        <div className="bip-stat">
          <span className="bip-stat-num" style={{ color: '#9B7A8C' }}>{unblockedCount}</span>
          <span className="bip-stat-lbl">Unblocked</span>
        </div>
        <div className="bip-stat">
          <span className="bip-stat-num" style={{ color: 'var(--rose)' }}>{blocks.length}</span>
          <span className="bip-stat-lbl">Total Records</span>
        </div>
      </div>

      {error && <div className="bip-error">⚠ {error}</div>}

      {loading ? (
        <div className="bip-loading">
          <div className="spinner" />
          <span>Loading blocked IPs…</span>
        </div>
      ) : blocks.length === 0 ? (
        <div className="bip-empty">
          <span className="bip-empty-icon">🔓</span>
          <p>No blocked IPs yet.</p>
          <p className="bip-empty-hint">Approve an alert to simulate blocking its source IP.</p>
        </div>
      ) : (
        <div className="bip-table-wrapper">
          <table className="bip-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Alert</th>
                <th>Status</th>
                <th>Blocked At</th>
                <th>Unblocked At</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {blocks.map((b) => (
                <tr key={b.id} className={`bip-row bip-row-${b.status}`}>
                  <td className="bip-ip">{b.ip_address}</td>
                  <td className="bip-alert-id">
                    {b.alert_id ? <span className="bip-alert-link">#{b.alert_id}</span> : '—'}
                  </td>
                  <td>
                    <span className={`bip-status-badge bip-status-${b.status}`}>
                      {b.status === 'blocked' ? '🔒 blocked' : '🔓 unblocked'}
                    </span>
                  </td>
                  <td className="bip-ts">
                    {b.blocked_at
                      ? new Date(b.blocked_at).toLocaleString()
                      : '—'}
                  </td>
                  <td className="bip-ts">
                    {b.unblocked_at
                      ? new Date(b.unblocked_at).toLocaleString()
                      : '—'}
                  </td>
                  <td>
                    {b.status === 'blocked' ? (
                      <button
                        className="btn-action btn-unblock"
                        disabled={unblocking === b.id}
                        onClick={() => handleUnblock(b.id)}
                      >
                        {unblocking === b.id ? (
                          <><span className="btn-spinner" /> Unblocking…</>
                        ) : (
                          '🔓 Unblock'
                        )}
                      </button>
                    ) : (
                      <span className="bip-unblocked-label">Unblocked</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="bip-disclaimer">
        ⚠ All actions are simulated — no real firewall or network device is modified.
      </p>
    </div>
  );
}

/* ── Alert Detail Panel ─────────────────────────────────────────────── */
function AlertDetailPanel({ alertId, token, onClose, onStatusChange, onBlockResult }) {
  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [actionLoading, setActionLoading] = useState('');
  const [error, setError] = useState('');

  const fetchDetail = useCallback(async () => {
    if (!alertId) return;
    try {
      const res = await fetch(`${API_BASE}/alerts/${alertId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Failed to fetch alert detail');
      const data = await res.json();
      setAlert(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [alertId, token]);

  useEffect(() => {
    setLoading(true);
    setError('');
    setAlert(null);
    fetchDetail();
  }, [fetchDetail]);

  const handleStatus = async (newStatus) => {
    setActionLoading(newStatus);
    try {
      const res = await fetch(`${API_BASE}/alerts/${alertId}/status?new_status=${newStatus}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
      if (!res.ok) throw new Error('Status update failed');
      const updated = await res.json();
      setAlert((prev) => ({ ...prev, status: updated.status }));
      onStatusChange && onStatusChange(alertId, updated.status);
      // Surface block_result as a toast
      if (updated.block_result && onBlockResult) {
        onBlockResult(updated.block_result, newStatus);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setActionLoading('');
    }
  };

  const handleAnalyze = async () => {
    setAnalyzing(true);
    setError('');
    try {
      await fetch(`${API_BASE}/alerts/${alertId}/analyze`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      await fetchDetail();
    } catch (err) {
      setError('Analysis failed');
    } finally {
      setAnalyzing(false);
    }
  };

  const report = alert?.report;

  return (
    <div className="detail-panel glass-strong">
      <div className="detail-panel-header">
        <div className="detail-title-group">
          <span className="detail-icon">🛡️</span>
          <div>
            <h2 className="detail-title">Alert #{alertId}</h2>
            {alert && <p className="detail-type">{alert.alert_type?.replace(/_/g, ' ')}</p>}
          </div>
        </div>
        <button className="detail-close" onClick={onClose} aria-label="Close">×</button>
      </div>

      {loading && (
        <div className="detail-loading">
          <div className="spinner" />
          <span>Loading alert…</span>
        </div>
      )}

      {error && <div className="detail-error">⚠ {error}</div>}

      {!loading && alert && (
        <>
          {/* Overview */}
          <div className="detail-section">
            <h4 className="section-label">Overview</h4>
            <dl className="detail-dl">
              <dt>Created</dt>
              <dd>{new Date(alert.created_at).toLocaleString()}</dd>
              <dt>Source IP</dt>
              <dd className="mono">{alert.source_ip}</dd>
              <dt>Target User</dt>
              <dd>{alert.username || '—'}</dd>
              <dt>Severity</dt>
              <dd><SeverityBadge severity={alert.severity} /></dd>
              <dt>Status</dt>
              <dd><StatusBadge status={alert.status} /></dd>
            </dl>
          </div>

          {/* Actions */}
          <div className="detail-section detail-actions-section">
            <h4 className="section-label">Actions</h4>
            <div className="detail-actions">
              <button
                className="btn-action btn-approve"
                onClick={() => handleStatus('approved')}
                disabled={!!actionLoading || alert.status === 'approved'}
              >
                {actionLoading === 'approved' ? '…' : '✓ Approve & Block IP'}
              </button>
              <button
                className="btn-action btn-dismiss"
                onClick={() => handleStatus('dismissed')}
                disabled={!!actionLoading || alert.status === 'dismissed'}
              >
                {actionLoading === 'dismissed' ? '…' : '✕ Dismiss'}
              </button>
            </div>
            <p className="action-hint">
              <span className="simulated-badge">SIMULATED</span>{' '}
              Approve records IP in a simulated block-list — no real firewall change.
            </p>
          </div>

          {/* AI Report */}
          {report ? (
            <div className="detail-section report-section">
              <h4 className="section-label">
                <span>🤖</span> AI Analyst Report
              </h4>

              <div className="report-field">
                <label>Summary</label>
                <p>{report.summary}</p>
              </div>

              <div className="report-row">
                <div className="report-field">
                  <label>Severity Assessment</label>
                  <SeverityBadge severity={report.severity} />
                </div>
                <div className="report-field">
                  <label>MITRE ATT&amp;CK Technique</label>
                  <span className="mitre-tag">{report.mitre_technique}</span>
                </div>
              </div>

              <div className="report-field">
                <label>Recommended Action</label>
                <p>{report.recommended_action}</p>
              </div>

              <p className="report-time">
                Generated: {new Date(report.created_at).toLocaleString()}
              </p>
            </div>
          ) : (
            <div className="detail-section no-report-section">
              <div className="no-report-inner">
                <span className="no-report-icon">🔬</span>
                <p>No AI analysis yet for this alert.</p>
                <button
                  className="btn-analyze"
                  onClick={handleAnalyze}
                  disabled={analyzing}
                >
                  {analyzing ? (
                    <><span className="btn-spinner" /> Analyzing…</>
                  ) : (
                    <><span>⚡</span> Run Analysis</>
                  )}
                </button>
              </div>
            </div>
          )}

          {/* Detection Details (parsed JSON) */}
          <AlertDetailsSection details={alert.details} alertType={alert.alert_type} />

          {/* Related Logs */}
          {alert.related_logs && alert.related_logs.length > 0 && (
            <div className="detail-section logs-section">
              <h4 className="section-label">
                Related Logs
                <span className="log-count">{alert.related_logs.length}</span>
              </h4>
              <div className="logs-list">
                {alert.related_logs.slice(0, 15).map((log) => (
                  isNetworkAlert(alert.alert_type) ? (
                    /* Network alert columns: timestamp, event_type, dest_port, protocol, application */
                    <div key={log.id} className="log-item log-item-network">
                      <span className="log-time">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </span>
                      <span className="log-event">{log.event_type}</span>
                      <span className={`log-port${SUSPICIOUS_PORTS.has(Number(log.dest_port)) ? ' log-port-suspicious' : ''}`}>
                        {log.dest_port ?? '—'}
                      </span>
                      <span className="log-proto">{log.protocol ?? '—'}</span>
                      <span className="log-app" title={log.application}>
                        {basename(log.application) ?? '—'}
                      </span>
                    </div>
                  ) : (
                    /* Auth alert columns: timestamp, username, event_type, geo_location */
                    <div key={log.id} className="log-item">
                      <span className="log-time">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </span>
                      <span className="log-user">{log.username ?? '—'}</span>
                      <span className="log-event">{log.event_type}</span>
                      <span className="log-geo">{log.geo_location}</span>
                    </div>
                  )
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ── Dashboard Page ─────────────────────────────────────────────────── */
let toastCounter = 0;

export default function Dashboard() {
  const { user, token, logout } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [fetchError, setFetchError] = useState('');
  const [selectedId, setSelectedId] = useState(null);
  const [filter, setFilter] = useState('all');
  const [seedStatus, setSeedStatus] = useState('idle'); // 'idle' | 'loading' | 'done' | 'error'
  const [seedResult, setSeedResult] = useState(null);
  const [activeTab, setActiveTab] = useState('alerts'); // 'alerts' | 'blocked-ips'
  const [toasts, setToasts] = useState([]);
  const intervalRef = useRef(null);

  /* ── Toast helpers ─────────────────────────────────────────────── */
  const pushToast = useCallback((toast) => {
    const id = ++toastCounter;
    setToasts((prev) => [...prev, { id, ...toast }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 5500);
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  /* ── Block result handler ──────────────────────────────────────── */
  const handleBlockResult = useCallback((blockResult, newStatus) => {
    if (!blockResult) return;
    const { action, ip_address } = blockResult;

    if (newStatus === 'approved') {
      if (action === 'blocked') {
        pushToast({
          type: 'success',
          icon: '🛡️',
          message: `IP ${ip_address} blocked (simulated)`,
          simulated: true,
        });
      } else if (action === 'already_blocked') {
        pushToast({
          type: 'info',
          icon: '🔒',
          message: `IP ${ip_address} was already blocked`,
          simulated: true,
        });
      }
    } else if (newStatus === 'dismissed') {
      pushToast({
        type: 'dismiss',
        icon: '✕',
        message: `Alert dismissed — ${ip_address} not blocked`,
        simulated: false,
      });
    }
  }, [pushToast]);

  const fetchAlerts = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch(`${API_BASE}/alerts`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Failed to fetch alerts');
      const data = await res.json();
      setAlerts(Array.isArray(data) ? data : data.alerts || []);
      setFetchError('');
    } catch (err) {
      setFetchError(err.message);
    }
  }, [token]);

  const seedDemoData = async () => {
    if (!token || seedStatus === 'loading') return;
    setSeedStatus('loading');
    setSeedResult(null);
    try {
      const res = await fetch(`${API_BASE}/demo/seed`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ include_attack: true }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || 'Seed failed');
      }
      const result = await res.json();
      setSeedResult(result);
      setSeedStatus('done');
      // Refresh immediately then let the interval take over
      await fetchAlerts();
      setTimeout(() => setSeedStatus('idle'), 4000);
    } catch (err) {
      setSeedStatus('error');
      setTimeout(() => setSeedStatus('idle'), 3000);
    }
  };

  // Initial fetch + 5s auto-refresh
  useEffect(() => {
    fetchAlerts();
    intervalRef.current = setInterval(fetchAlerts, 5000);
    return () => clearInterval(intervalRef.current);
  }, [fetchAlerts]);

  const handleStatusChange = (id, status) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status } : a))
    );
  };

  const filteredAlerts = alerts.filter((a) => {
    if (filter === 'all') return true;
    return a.severity?.toLowerCase() === filter || a.status === filter;
  });

  const criticalCount = alerts.filter((a) => a.severity?.toLowerCase() === 'critical').length;
  const openCount     = alerts.filter((a) => a.status === 'open').length;
  const highCount     = alerts.filter((a) => a.severity?.toLowerCase() === 'high').length;
  const blockedCount  = alerts.filter((a) => a.status === 'approved').length;

  return (
    <>
      <div className="orb orb-cyan" style={{ position: 'fixed' }} />
      <div className="orb orb-purple" style={{ position: 'fixed' }} />

      {/* Toast container */}
      <Toast toasts={toasts} onDismiss={dismissToast} />

      {/* Global Navbar — same as all other pages */}
      <Navbar />

      <div className="page dashboard-page">
      <div className="dashboard-content">
        {/* Header */}
        <header className="dash-header">
          <div className="dash-welcome">
            <h1 className="dash-title">
              Welcome back, <span className="gradient-text">{user?.username}</span>
            </h1>
            <p className="dash-sub">Real-time threat monitoring · Auto-refresh every 5s</p>
          </div>
          <div className="dash-header-right">
            {/* Generate Sample Data button */}
            <button
              className={`btn seed-btn${
                seedStatus === 'loading' ? ' seed-loading' :
                seedStatus === 'done'    ? ' seed-done'    :
                seedStatus === 'error'   ? ' seed-error'   : ''
              }`}
              onClick={seedDemoData}
              disabled={seedStatus === 'loading'}
              title="Populate your dashboard with sample logs and attack simulations"
            >
              {seedStatus === 'loading' ? (
                <><span className="btn-spinner seed-spinner" />Generating…</>
              ) : seedStatus === 'done' ? (
                <>✓ {seedResult?.logs_created} logs added</>
              ) : seedStatus === 'error' ? (
                <>⚠ Seed failed</>
              ) : (
                <>⚡ Generate Sample Data</>
              )}
            </button>
            <div className="dash-live">
              <span className="live-dot" />
              <span className="live-label">LIVE</span>
            </div>
          </div>
        </header>

        {/* Stats row */}
        <div className="stats-row">
          <div className="stat-pill glass">
            <span className="stat-num" style={{ color: '#B84060' }}>{criticalCount}</span>
            <span className="stat-lbl">Critical</span>
          </div>
          <div className="stat-pill glass">
            <span className="stat-num" style={{ color: '#C4613A' }}>{highCount}</span>
            <span className="stat-lbl">High</span>
          </div>
          <div className="stat-pill glass">
            <span className="stat-num" style={{ color: '#A07830' }}>{openCount}</span>
            <span className="stat-lbl">Open</span>
          </div>
          <div className="stat-pill glass">
            <span className="stat-num" style={{ color: '#4A9E7E' }}>{alerts.length}</span>
            <span className="stat-lbl">Total</span>
          </div>
        </div>

        {fetchError && (
          <div className="fetch-error glass">
            <span>⚠</span> {fetchError}
          </div>
        )}

        {/* Tab bar */}
        <div className="dash-tab-bar glass">
          <button
            id="tab-alerts"
            className={`dash-tab ${activeTab === 'alerts' ? 'active' : ''}`}
            onClick={() => setActiveTab('alerts')}
          >
            <span>⚡</span> Alert Feed
            {openCount > 0 && <span className="tab-count">{openCount}</span>}
          </button>
          <button
            id="tab-blocked-ips"
            className={`dash-tab ${activeTab === 'blocked-ips' ? 'active' : ''}`}
            onClick={() => setActiveTab('blocked-ips')}
          >
            <span>🛡️</span> Blocked IPs
            {blockedCount > 0 && <span className="tab-count tab-count-green">{blockedCount}</span>}
          </button>
        </div>

        {/* ── Alert Feed Tab ── */}
        {activeTab === 'alerts' && (
          <div className={`dash-layout ${selectedId ? 'with-detail' : ''}`}>
            {/* Alert Table */}
            <section className="table-section">
              <div className="table-toolbar glass">
                <div className="toolbar-left">
                  <span className="toolbar-icon">⚡</span>
                  <h3>Alert Feed</h3>
                  <span className="alert-count">{filteredAlerts.length}</span>
                </div>
                <div className="filter-tabs">
                  {['all', 'critical', 'high', 'medium', 'low', 'open', 'approved', 'dismissed'].map((f) => (
                    <button
                      key={f}
                      className={`filter-tab ${filter === f ? 'active' : ''}`}
                      onClick={() => setFilter(f)}
                    >
                      {f}
                    </button>
                  ))}
                </div>
              </div>

              <div className="alert-table-wrapper glass">
                {filteredAlerts.length === 0 ? (
                  alerts.length === 0 ? (
                    /* ── True empty state: no data at all ── */
                    <div className="empty-state empty-state-full">
                      <div className="empty-hero-icon">🛡️</div>
                      <h3 className="empty-title">No data yet</h3>
                      <p className="empty-sub">
                        Your dashboard is empty. Generate sample logs and a simulated
                        brute-force attack to see how Aegis AI detects and triages threats.
                      </p>
                      <button
                        className={`btn btn-primary seed-btn-big${
                          seedStatus === 'loading' ? ' seed-loading' :
                          seedStatus === 'done'    ? ' seed-done'    : ''
                        }`}
                        onClick={seedDemoData}
                        disabled={seedStatus === 'loading'}
                      >
                        {seedStatus === 'loading' ? (
                          <><span className="btn-spinner seed-spinner" />Generating sample data…</>
                        ) : seedStatus === 'done' ? (
                          <>✓ Done! {seedResult?.logs_created} logs · {seedResult?.total_alerts} alerts</>
                        ) : (
                          <>⚡ Generate Sample Data</>
                        )}
                      </button>
                      <p className="empty-note">Safe to run multiple times · No real data is affected</p>
                    </div>
                  ) : (
                    /* ── Filter returned nothing ── */
                    <div className="empty-state">
                      <span className="empty-icon">🔍</span>
                      <p>No alerts match the current filter.</p>
                    </div>
                  )
                ) : (
                  <table className="alert-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Source IP</th>
                        <th>User</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>AI</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAlerts.map((alert) => (
                        <tr
                          key={alert.id}
                          className={`alert-row ${selectedId === alert.id ? 'selected' : ''} sev-${alert.severity?.toLowerCase()}`}
                          onClick={() => setSelectedId(selectedId === alert.id ? null : alert.id)}
                        >
                          <td className="col-time">
                            {new Date(alert.created_at).toLocaleTimeString()}
                          </td>
                          <td className="col-type">
                            <AlertTypeIcon alertType={alert.alert_type} />
                            {alert.alert_type?.replace(/_/g, ' ')}
                          </td>
                          <td className="col-ip">{alert.source_ip}</td>
                          <td className="col-user">{alert.username || '—'}</td>
                          <td className="col-sev">
                            <SeverityBadge severity={alert.severity} />
                          </td>
                          <td className="col-status">
                            <StatusBadge status={alert.status} />
                          </td>
                          <td className="col-ai">
                            <span className={`ai-indicator ${alert.report ? 'has-report' : 'no-report'}`}>
                              {alert.report ? '✓' : '○'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </section>

            {/* Detail Panel */}
            {selectedId && (
              <AlertDetailPanel
                alertId={selectedId}
                token={token}
                onClose={() => setSelectedId(null)}
                onStatusChange={handleStatusChange}
                onBlockResult={handleBlockResult}
              />
            )}
          </div>
        )}

        {/* ── Blocked IPs Tab ── */}
        {activeTab === 'blocked-ips' && (
          <BlockedIPsPanel token={token} />
        )}

      </div>
      </div>
    </>
  );
}
