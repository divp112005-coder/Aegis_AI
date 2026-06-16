import { useState, useEffect } from 'react';
import axios from 'axios';
import AlertTable from './components/AlertTable';
import AlertDetail from './components/AlertDetail';
import './App.css';

const API_BASE = 'http://127.0.0.1:8000';

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000); // refresh every 5s
    return () => clearInterval(interval);
  }, []);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const res = await axios.get(`${API_BASE}/alerts`);
      setAlerts(res.data);
    } catch (err) {
      console.error('Error fetching alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectAlert = async (alert) => {
    try {
      const res = await axios.get(`${API_BASE}/alerts/${alert.id}`);
      setSelectedAlert(res.data);
    } catch (err) {
      console.error('Error fetching alert detail:', err);
    }
  };

  const handleStatusUpdate = async (alertId, newStatus) => {
    try {
      await axios.post(`${API_BASE}/alerts/${alertId}/status`, null, {
        params: { new_status: newStatus },
      });
      fetchAlerts();
      setSelectedAlert(null);
    } catch (err) {
      console.error('Error updating alert:', err);
    }
  };

  return (
    <div className="app">
      <header className="header">
        <h1>Aegis AI</h1>
        <p>Intelligent SIEM with AI-powered Alert Analysis</p>
      </header>

      <div className="container">
        <div className="alerts-panel">
          <div className="panel-header">
            <h2>Alerts ({alerts.length})</h2>
            <button onClick={fetchAlerts} disabled={loading} className="refresh-btn">
              {loading ? '⟳ Refreshing...' : '⟳ Refresh'}
            </button>
          </div>
          <AlertTable 
            alerts={alerts} 
            onSelectAlert={handleSelectAlert}
            selectedId={selectedAlert?.id}
          />
        </div>

        {selectedAlert && (
          <div className="detail-panel">
            <AlertDetail 
              alert={selectedAlert}
              onClose={() => setSelectedAlert(null)}
              onStatusUpdate={handleStatusUpdate}
            />
          </div>
        )}
      </div>
    </div>
  );
}
