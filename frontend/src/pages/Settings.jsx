import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import Navbar from '../components/Navbar';
import { useAuth } from '../context/AuthContext';
import './Settings.css';

const API_BASE = 'http://127.0.0.1:8000';

/* ── Tooltip wrapper ─────────────────────────────────────────────── */
function Tooltip({ text, children }) {
  return (
    <div className="tooltip-wrap">
      {children}
      <span className="tooltip-bubble">{text}</span>
    </div>
  );
}

/* ── Copy-to-clipboard hook ──────────────────────────────────────── */
function useCopy() {
  const [copied, setCopied] = useState(false);
  const copy = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return { copied, copy };
}

/* ── Plan badge ──────────────────────────────────────────────────── */
function PlanBadge({ plan }) {
  const label = plan || 'Free';
  const cls =
    label.toLowerCase() === 'pro'
      ? 'plan-badge plan-pro'
      : label.toLowerCase() === 'enterprise'
      ? 'plan-badge plan-enterprise'
      : 'plan-badge plan-free';
  return <span className={cls}>{label}</span>;
}

/* ── Section card ────────────────────────────────────────────────── */
function SectionCard({ icon, title, children }) {
  return (
    <div className="settings-card glass">
      <div className="settings-card-header">
        <span className="settings-card-icon">{icon}</span>
        <h2 className="settings-card-title">{title}</h2>
      </div>
      <div className="settings-card-body">{children}</div>
    </div>
  );
}

/* ── Settings page ───────────────────────────────────────────────── */
export default function Settings() {
  const { user, token, logout } = useAuth();
  const navigate = useNavigate();

  /* ── Password change state ── */
  const [pwForm, setPwForm] = useState({
    current_password: '',
    new_password: '',
    confirm_password: '',
  });
  const [pwErrors, setPwErrors] = useState({});
  const [pwStatus, setPwStatus] = useState(''); // '' | 'loading' | 'success' | 'error'
  const [pwMsg, setPwMsg] = useState('');

  /* ── Delete account state ── */
  const [deleteStep, setDeleteStep] = useState('idle'); // 'idle' | 'confirm' | 'deleting' | 'error'
  const [deleteError, setDeleteError] = useState('');

  /* ── API key state ── */
  const MOCK_KEY = 'aegis_sk_live_4xB9mZpQrT8sKjL2vYnW6cDhE0oFuIa3';
  const [keyVisible, setKeyVisible] = useState(false);
  const { copied, copy } = useCopy();

  /* ── Password validation ── */
  const validatePw = () => {
    const e = {};
    if (!pwForm.current_password) e.current_password = 'Current password is required';
    if (pwForm.new_password.length < 8)
      e.new_password = 'New password must be at least 8 characters';
    if (pwForm.new_password !== pwForm.confirm_password)
      e.confirm_password = 'Passwords do not match';
    return e;
  };

  const handlePwChange = async (ev) => {
    ev.preventDefault();
    const errs = validatePw();
    if (Object.keys(errs).length) { setPwErrors(errs); return; }
    setPwErrors({});
    setPwStatus('loading');
    setPwMsg('');
    try {
      const res = await fetch(`${API_BASE}/auth/change-password`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          current_password: pwForm.current_password,
          new_password: pwForm.new_password,
        }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || 'Password change failed');
      }
      setPwStatus('success');
      setPwMsg('Password updated successfully!');
      setPwForm({ current_password: '', new_password: '', confirm_password: '' });
    } catch (err) {
      setPwStatus('error');
      setPwMsg(err.message);
    }
  };

  const handleDeleteAccount = async () => {
    if (deleteStep === 'idle') {
      setDeleteStep('confirm');
      return;
    }
    setDeleteStep('deleting');
    setDeleteError('');
    try {
      const res = await fetch(`${API_BASE}/auth/me`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || 'Account deletion failed');
      }
      logout();
      navigate('/');
    } catch (err) {
      setDeleteError(err.message);
      setDeleteStep('error');
    }
  };

  const maskedKey = MOCK_KEY.slice(0, 12) + '•'.repeat(20) + MOCK_KEY.slice(-6);

  return (
    <>
      <div className="orb orb-cyan" style={{ position: 'fixed' }} />
      <div className="orb orb-purple" style={{ position: 'fixed' }} />
      <Navbar />
      <div className="page settings-page">

      <div className="settings-content">
        {/* Page heading */}
        <header className="settings-header">
          <div className="settings-header-inner">
            <span className="settings-header-icon">⚙️</span>
            <div>
              <h1 className="settings-title">
                Account <span className="gradient-text">Settings</span>
              </h1>
              <p className="settings-sub">Manage your profile, security, and API access.</p>
            </div>
          </div>
        </header>

        <div className="settings-grid">

          {/* ── Profile ── */}
          <SectionCard icon="👤" title="Your Profile">
            <div className="profile-avatar-row">
              <div className="profile-avatar">
                {(user?.full_name || user?.username || '?')[0].toUpperCase()}
              </div>
              <div>
                <p className="profile-name">{user?.full_name || 'Unknown User'}</p>
                <p className="profile-handle">@{user?.username}</p>
              </div>
              <PlanBadge plan={user?.plan} />
            </div>

            <div className="profile-fields">
              <div className="profile-field">
                <span className="profile-field-label">Full Name</span>
                <span className="profile-field-value">{user?.full_name || '—'}</span>
              </div>
              <div className="profile-field">
                <span className="profile-field-label">Email</span>
                <span className="profile-field-value">{user?.email || '—'}</span>
              </div>
              <div className="profile-field">
                <span className="profile-field-label">Username</span>
                <span className="profile-field-value">@{user?.username || '—'}</span>
              </div>
              <div className="profile-field">
                <span className="profile-field-label">Current Plan</span>
                <span className="profile-field-value">
                  <PlanBadge plan={user?.plan} />
                </span>
              </div>
            </div>
          </SectionCard>

          {/* ── Change Password ── */}
          <SectionCard icon="🔐" title="Change Password">
            <form className="pw-form" onSubmit={handlePwChange} noValidate>
              <div className="field-group">
                <label htmlFor="current_password">Current Password</label>
                <input
                  id="current_password"
                  type="password"
                  className={`input${pwErrors.current_password ? ' input-error' : ''}`}
                  placeholder="Enter current password"
                  value={pwForm.current_password}
                  onChange={(e) => {
                    setPwForm({ ...pwForm, current_password: e.target.value });
                    setPwErrors({ ...pwErrors, current_password: '' });
                  }}
                />
                {pwErrors.current_password && (
                  <span className="field-error">{pwErrors.current_password}</span>
                )}
              </div>

              <div className="field-group">
                <label htmlFor="new_password">New Password</label>
                <input
                  id="new_password"
                  type="password"
                  className={`input${pwErrors.new_password ? ' input-error' : ''}`}
                  placeholder="Minimum 8 characters"
                  value={pwForm.new_password}
                  onChange={(e) => {
                    setPwForm({ ...pwForm, new_password: e.target.value });
                    setPwErrors({ ...pwErrors, new_password: '' });
                  }}
                />
                {pwErrors.new_password && (
                  <span className="field-error">{pwErrors.new_password}</span>
                )}
              </div>

              <div className="field-group">
                <label htmlFor="confirm_password">Confirm New Password</label>
                <input
                  id="confirm_password"
                  type="password"
                  className={`input${pwErrors.confirm_password ? ' input-error' : ''}`}
                  placeholder="Repeat new password"
                  value={pwForm.confirm_password}
                  onChange={(e) => {
                    setPwForm({ ...pwForm, confirm_password: e.target.value });
                    setPwErrors({ ...pwErrors, confirm_password: '' });
                  }}
                />
                {pwErrors.confirm_password && (
                  <span className="field-error">{pwErrors.confirm_password}</span>
                )}
              </div>

              {pwMsg && (
                <div className={`pw-feedback pw-feedback-${pwStatus}`}>
                  {pwStatus === 'success' ? '✓ ' : '⚠ '}
                  {pwMsg}
                </div>
              )}

              <button
                type="submit"
                className="btn btn-primary pw-submit"
                disabled={pwStatus === 'loading'}
              >
                {pwStatus === 'loading' ? (
                  <><span className="btn-spinner" /> Updating…</>
                ) : (
                  'Update Password'
                )}
              </button>
            </form>
          </SectionCard>

          {/* ── API Key ── */}
          <SectionCard icon="🔑" title="API Key">
            <p className="apikey-desc">
              Use this key to authenticate requests to the Aegis AI REST API. Keep it secret — never expose it in client-side code.
            </p>
            <div className="apikey-box glass-glow">
              <span className="apikey-value">
                {keyVisible ? MOCK_KEY : maskedKey}
              </span>
              <div className="apikey-actions">
                <button
                  className="btn btn-ghost apikey-btn"
                  id="apikey-toggle"
                  onClick={() => setKeyVisible((v) => !v)}
                  aria-label={keyVisible ? 'Hide API key' : 'Reveal API key'}
                >
                  {keyVisible ? '🙈 Hide' : '👁 Reveal'}
                </button>
                <button
                  className="btn btn-ghost apikey-btn"
                  id="apikey-copy"
                  onClick={() => copy(MOCK_KEY)}
                  aria-label="Copy API key"
                >
                  {copied ? '✓ Copied!' : '📋 Copy'}
                </button>
              </div>
            </div>
            <p className="apikey-note">
              🛡 This is a mock key for demonstration. Real key generation will be available in the Pro plan.
            </p>
          </SectionCard>

          {/* ── Danger Zone ── */}
          <SectionCard icon="⚠️" title="Danger Zone">
            <p className="danger-desc">
              Permanently delete your account and all associated data. This action is irreversible.
            </p>
            <div className="danger-action">
              <div className="danger-info">
                <strong>Delete Account</strong>
                <p>All your alerts, logs, and settings will be erased forever.</p>
              </div>
              <div className="delete-btn-group">
                {deleteStep === 'confirm' && (
                  <p className="delete-confirm-msg">
                    ⚠️ Are you sure? This cannot be undone.
                  </p>
                )}
                {deleteStep === 'error' && (
                  <p className="delete-error-msg">⚠ {deleteError}</p>
                )}
                <div className="delete-btn-row">
                  {deleteStep === 'confirm' && (
                    <button
                      className="btn btn-ghost btn-cancel-delete"
                      onClick={() => setDeleteStep('idle')}
                    >
                      Cancel
                    </button>
                  )}
                  <button
                    className={`btn btn-danger-active${deleteStep === 'confirm' ? ' btn-danger-confirm' : ''}`}
                    id="delete-account-btn"
                    onClick={handleDeleteAccount}
                    disabled={deleteStep === 'deleting'}
                  >
                    {deleteStep === 'deleting' ? (
                      <><span className="btn-spinner" style={{ borderTopColor: '#fff', borderColor: 'rgba(255,255,255,0.3)' }} /> Deleting…</>
                    ) : deleteStep === 'confirm' ? (
                      '🗑 Yes, Delete My Account'
                    ) : (
                      '🗑 Delete Account'
                    )}
                  </button>
                </div>
              </div>
            </div>
          </SectionCard>

        </div>
      </div>
      </div>
    </>
  );
}
