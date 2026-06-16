import { useState } from 'react';
import axios from 'axios';
import './AlertDetail.css';

const API_BASE = 'http://127.0.0.1:8000';

export default function AlertDetail({ alert, onClose, onStatusUpdate }) {
  const [analyzing, setAnalyzing] = useState(false);

  const handleAnalyze = async () => {
    setAnalyzing(true);
    try {
      await axios.post(`${API_BASE}/alerts/${alert.id}/analyze`);
      // Refetch alert to get updated report
      const res = await axios.get(`${API_BASE}/alerts/${alert.id}`);
      // Would need to update parent, so just close and refresh
      onClose();
    } catch (err) {
      console.error('Error analyzing alert:', err);
    } finally {
      setAnalyzing(false);
    }
  };

  const report = alert.report;

  return (
    <div className="alert-detail">
      <div className="detail-header">
        <h3>Alert #{alert.id}</h3>
        <button className="close-btn" onClick={onClose}>×</button>
      </div>

      <div className="detail-section">
        <h4>Overview</h4>
        <dl>
          <dt>Created</dt>
          <dd>{new Date(alert.created_at).toLocaleString()}</dd>
          <dt>Type</dt>
          <dd className="capitalize">{alert.alert_type}</dd>
          <dt>Source IP</dt>
          <dd className="mono">{alert.source_ip}</dd>
          <dt>Target User</dt>
          <dd>{alert.username || '—'}</dd>
          <dt>Severity</dt>
          <dd className="severity-badge">{alert.severity}</dd>
          <dt>Status</dt>
          <dd className="status-select">
            <select
              value={alert.status}
              onChange={(e) => onStatusUpdate(alert.id, e.target.value)}
            >
              <option value="open">Open</option>
              <option value="approved">Approved</option>
              <option value="dismissed">Dismissed</option>
            </select>
          </dd>
        </dl>
      </div>

      {report ? (
        <div className="detail-section report-section">
          <h4>AI Analyst Report</h4>
          <div className="report-content">
            <div className="report-field">
              <label>Summary</label>
              <p>{report.summary}</p>
            </div>
            <div className="report-field">
              <label>Severity Assessment</label>
              <p className="severity-value">{report.severity}</p>
            </div>
            <div className="report-field">
              <label>MITRE ATT&CK Technique</label>
              <p className="mitre">{report.mitre_technique}</p>
            </div>
            <div className="report-field">
              <label>Recommended Action</label>
              <p>{report.recommended_action}</p>
            </div>
            <p className="report-time">
              Generated: {new Date(report.created_at).toLocaleString()}
            </p>
          </div>
        </div>
      ) : (
        <div className="detail-section no-report">
          <p>No AI analysis yet.</p>
          <button 
            className="analyze-btn" 
            onClick={handleAnalyze}
            disabled={analyzing}
          >
            {analyzing ? 'Analyzing...' : 'Run Analysis'}
          </button>
        </div>
      )}

      {alert.related_logs && alert.related_logs.length > 0 && (
        <div className="detail-section">
          <h4>Related Logs ({alert.related_logs.length})</h4>
          <div className="logs-list">
            {alert.related_logs.slice(0, 10).map((log) => (
              <div key={log.id} className="log-item">
                <span className="log-time">{new Date(log.timestamp).toLocaleTimeString()}</span>
                <span className="log-user">{log.username}</span>
                <span className="log-event">{log.event_type}</span>
                <span className="log-geo">{log.geo_location}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
