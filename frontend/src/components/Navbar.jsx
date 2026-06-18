import { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import './Navbar.css';

export default function Navbar() {
  const { user, logout } = useAuth();
  const { dark, toggle } = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const [hidden, setHidden] = useState(false);

  useEffect(() => {
    let lastY = window.scrollY;
    const onScroll = () => {
      const y = window.scrollY;
      if (y < 60) {
        setHidden(false);           // always show at top
      } else if (y > lastY + 4) {
        setHidden(true);            // scrolling down → hide
      } else if (y < lastY - 4) {
        setHidden(false);           // scrolling up → show
      }
      lastY = y;
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const isActive = (path) => location.pathname === path;

  return (
    <nav className={`navbar glass${hidden ? ' navbar-hidden' : ''}`}>
      <Link to="/" className="nav-brand">
        <span className="brand-icon">⬡</span>
        <span className="brand-name gradient-text">Aegis AI</span>
      </Link>

      <div className="nav-links">
        <Link to="/docs" className={`nav-link ${isActive('/docs') ? 'active' : ''}`}>Docs</Link>
        <Link to="/pricing" className={`nav-link ${isActive('/pricing') ? 'active' : ''}`}>Pricing</Link>
        {user && (
          <Link to="/dashboard" className={`nav-link ${isActive('/dashboard') ? 'active' : ''}`}>Dashboard</Link>
        )}
      </div>

      <div className="nav-actions">
        {/* Dark mode toggle */}
        <button
          className="theme-toggle"
          onClick={toggle}
          aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}
          title={dark ? 'Light mode' : 'Dark mode'}
        >
          <span className="theme-toggle-track">
            <span className="theme-toggle-thumb" />
          </span>
          <span className="theme-toggle-icon">{dark ? '☀️' : '🌙'}</span>
        </button>

        {user ? (
          <>
            <span className="nav-user">
              <span className="user-dot" />
              {user.username}
              <span className="plan-badge">{user.plan}</span>
            </span>
            <Link to="/settings" className="btn btn-ghost btn-sm">Settings</Link>
            <button onClick={handleLogout} className="btn btn-outline btn-sm">Logout</button>
          </>
        ) : (
          <>
            <Link to="/auth" className="btn btn-ghost btn-sm">Login</Link>
            <Link to="/auth?mode=signup" className="btn btn-primary btn-sm">Get Started</Link>
          </>
        )}
      </div>
    </nav>
  );
}
