import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './context/AuthContext'
import Landing from './pages/Landing'

const ComingSoon = ({ name }) => (
  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', flexDirection: 'column', gap: '1rem' }}>
    <div style={{ fontSize: '3rem' }}>⚙️</div>
    <h2 style={{ color: 'var(--cyan)' }}>{name}</h2>
    <p style={{ color: 'var(--text-muted)' }}>Coming up next...</p>
  </div>
)

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return null
  return user ? children : <Navigate to="/auth" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/auth" element={<ComingSoon name="Auth Page" />} />
      <Route path="/pricing" element={<ComingSoon name="Pricing Page" />} />
      <Route path="/docs" element={<ComingSoon name="Docs Page" />} />
      <Route path="/settings" element={<ProtectedRoute><ComingSoon name="Settings Page" /></ProtectedRoute>} />
      <Route path="/dashboard" element={<ProtectedRoute><ComingSoon name="Dashboard" /></ProtectedRoute>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}