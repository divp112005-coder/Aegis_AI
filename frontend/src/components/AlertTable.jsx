import './AlertTable.css';

const SEVERITY_COLORS = {
  critical: '#ff4757',
  high: '#ff6348',
  medium: '#ffa502',
  low: '#2ed573',
  unknown: '#6c757d',
};

export default function AlertTable({ alerts, onSelectAlert, selectedId }) {
  return (
    <div className="alert-table-wrapper">
      <table className="alert-table">
        <thead>
          <tr>
            <th>Created</th>
            <th>Type</th>
            <th>Source IP</th>
            <th>User</th>
            <th>Severity</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {alerts.length === 0 ? (
            <tr>
              <td colSpan="6" className="no-data">
                No alerts yet. Generate some attack logs to see them here.
              </td>
            </tr>
          ) : (
            alerts.map((alert) => (
              <tr
                key={alert.id}
                className={`alert-row ${selectedId === alert.id ? 'selected' : ''}`}
                onClick={() => onSelectAlert(alert)}
              >
                <td className="time">
                  {new Date(alert.created_at).toLocaleTimeString()}
                </td>
                <td className="type">{alert.alert_type}</td>
                <td className="ip">{alert.source_ip}</td>
                <td className="user">{alert.username || '—'}</td>
                <td className="severity">
                  <span
                    className="badge"
                    style={{ backgroundColor: SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.unknown }}
                  >
                    {alert.severity}
                  </span>
                </td>
                <td className="status">
                  <span className={`status-badge status-${alert.status}`}>
                    {alert.status}
                  </span>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
