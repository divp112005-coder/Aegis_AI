import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import Navbar from '../components/Navbar';
import './Auth.css';

const API_BASE = 'http://127.0.0.1:8000';

export default function Auth() {
  const [searchParams] = useSearchParams();
  const [mode, setMode] = useState(searchParams.get('mode') === 'signup' ? 'signup' : 'login');
  const [form, setForm] = useState({ email: '', username: '', password: '', full_name: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (user) navigate('/dashboard');
  }, [user]);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      let res, data;

      if (mode === 'login') {
        const body = new URLSearchParams();
        body.append('username', form.email);
        body.append('password', form.password);
        res = await fetch(`${API_BASE}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
        });
      } else {
        res = await fetch(`${API_BASE}/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(form),
        });
      }

      data = await res.json();

      if (!res.ok) {
        setError(data.detail || 'Something went wrong');
        return;
      }

      login(data.access_token, data.user);
      navigate('/dashboard');
    } catch (err) {
      setError('Cannot connect to server. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="orb orb-cyan" style={{ position: 'fixed' }} />
      <div className="orb orb-purple" style={{ position: 'fixed' }} />
      <Navbar />
      <div className="auth-page page">
      <div className="auth-container">
        {/* Left panel — branding */}
        <div className="auth-brand glass">
          <div className="brand-logo">⬡</div>
          <h2>Intelligent SIEM<br />for modern teams</h2>
          <p>AI-powered threat detection and autonomous alert triage — from log ingestion to analyst report in seconds.</p>

          <div className="auth-features">
            {[
              { icon: '⚡', text: 'Real-time brute-force detection' },
              { icon: '🤖', text: 'LLaMA 3.3 AI analyst on every alert' },
              { icon: '🛡️', text: 'MITRE ATT&CK auto-mapping' },
              { icon: '🔑', text: 'JWT-secured REST API' },
            ].map((f) => (
              <div key={f.text} className="auth-feature-item">
                <span>{f.icon}</span>
                <span>{f.text}</span>
              </div>
            ))}
          </div>

          <div className="auth-stat-row">
            <div className="auth-stat">
              <span className="gradient-text">99.9%</span>
              <span>Uptime</span>
            </div>
            <div className="auth-stat">
              <span className="gradient-text">&lt;10s</span>
              <span>Detection</span>
            </div>
            <div className="auth-stat">
              <span className="gradient-text">Free</span>
              <span>To start</span>
            </div>
          </div>
        </div>

        {/* Right panel — form */}
        <div className="auth-form-panel glass-strong">
          {/* Mode toggle */}
          <div className="auth-toggle">
            <button
              className={mode === 'login' ? 'active' : ''}
              onClick={() => { setMode('login'); setError(''); }}
            >
              Login
            </button>
            <button
              className={mode === 'signup' ? 'active' : ''}
              onClick={() => { setMode('signup'); setError(''); }}
            >
              Sign Up
            </button>
          </div>

          <h3 className="form-title">
            {mode === 'login' ? 'Welcome back' : 'Create your account'}
          </h3>
          <p className="form-sub">
            {mode === 'login'
              ? 'Sign in to your Aegis AI dashboard'
              : 'Start your free tier — no credit card required'}
          </p>

          <form onSubmit={handleSubmit} className="auth-form">
            {mode === 'signup' && (
              <div className="form-group">
                <label>Full Name</label>
                <input
                  className="input"
                  type="text"
                  name="full_name"
                  placeholder="Divesh"
                  value={form.full_name}
                  onChange={handleChange}
                />
              </div>
            )}

            <div className="form-group">
              <label>Email</label>
              <input
                className="input"
                type="email"
                name="email"
                placeholder="you@company.com"
                value={form.email}
                onChange={handleChange}
                required
              />
            </div>

            {mode === 'signup' && (
              <div className="form-group">
                <label>Username</label>
                <input
                  className="input"
                  type="text"
                  name="username"
                  placeholder="johndoe"
                  value={form.username}
                  onChange={handleChange}
                  required
                />
              </div>
            )}

            <div className="form-group">
              <label>Password</label>
              <input
                className="input"
                type="password"
                name="password"
                placeholder="••••••••"
                value={form.password}
                onChange={handleChange}
                required
                minLength={6}
              />
            </div>

            {error && (
              <div className="auth-error">
                <span>⚠</span> {error}
              </div>
            )}

            <button
              type="submit"
              className="btn btn-primary auth-submit"
              disabled={loading}
            >
              {loading
                ? 'Please wait...'
                : mode === 'login' ? 'Sign In →' : 'Create Account →'}
            </button>
          </form>

          <p className="auth-switch">
            {mode === 'login' ? "Don't have an account? " : 'Already have an account? '}
            <button onClick={() => { setMode(mode === 'login' ? 'signup' : 'login'); setError(''); }}>
              {mode === 'login' ? 'Sign up free' : 'Sign in'}
            </button>
          </p>

          <p className="auth-terms">
            By continuing, you agree to our Terms of Service and Privacy Policy.
          </p>
        </div>
      </div>
      </div>
    </>
  );
}
