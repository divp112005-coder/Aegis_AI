import { useState } from 'react';
import { Link } from 'react-router-dom';
import Navbar from '../components/Navbar';
import { useAuth } from '../context/AuthContext';
import './Pricing.css';

const TIERS = [
  {
    id: 'free',
    name: 'Free',
    price: 0,
    period: '/mo',
    tagline: 'Perfect for individuals exploring Aegis AI.',
    features: [
      { icon: '📋', text: '1,000 log events / day' },
      { icon: '👤', text: '1 user seat' },
      { icon: '💬', text: 'Community support' },
      { icon: '🤖', text: 'AI alert analysis (basic)' },
      { icon: '📊', text: 'Live dashboard' },
    ],
    cta: 'Get Started Free',
    ctaLink: '/auth?mode=signup',
    highlighted: false,
  },
  {
    id: 'pro',
    name: 'Pro',
    price: 29,
    period: '/mo',
    tagline: 'For growing security teams that need real power.',
    badge: 'Most Popular',
    features: [
      { icon: '📋', text: '100,000 log events / day' },
      { icon: '👥', text: 'Up to 5 user seats' },
      { icon: '📧', text: 'Priority email support' },
      { icon: '⚙️', text: 'Custom detection rules' },
      { icon: '🤖', text: 'Full AI analyst agent (LLaMA 3.3 70B)' },
      { icon: '🗺️', text: 'MITRE ATT&CK auto-mapping' },
      { icon: '🔗', text: 'REST API + webhook access' },
    ],
    cta: 'Upgrade to Pro',
    highlighted: true,
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: 99,
    period: '/mo',
    tagline: 'For organisations demanding reliability at scale.',
    features: [
      { icon: '♾️', text: 'Unlimited log events / day' },
      { icon: '🏢', text: 'Unlimited user seats' },
      { icon: '🔐', text: 'SSO / SAML 2.0 integration' },
      { icon: '📜', text: 'Custom SLA guarantee' },
      { icon: '🛡️', text: 'Dedicated support engineer' },
      { icon: '🤖', text: 'Full AI analyst agent (LLaMA 3.3 70B)' },
      { icon: '📋', text: 'Audit logs & compliance reports' },
      { icon: '⚙️', text: 'Custom detection rules' },
    ],
    cta: 'Contact Sales',
    highlighted: false,
  },
];

/* ── Stripe mock modal ───────────────────────────────────────────── */
function CheckoutModal({ tier, onClose }) {
  const [step, setStep] = useState('form'); // 'form' | 'processing' | 'success'
  const [card, setCard] = useState({ name: '', number: '', expiry: '', cvc: '' });
  const [errors, setErrors] = useState({});

  const validate = () => {
    const e = {};
    if (!card.name.trim()) e.name = 'Cardholder name is required';
    if (!/^\d{16}$/.test(card.number.replace(/\s/g, ''))) e.number = 'Enter a valid 16-digit card number';
    if (!/^\d{2}\/\d{2}$/.test(card.expiry)) e.expiry = 'Format: MM/YY';
    if (!/^\d{3,4}$/.test(card.cvc)) e.cvc = 'Enter 3–4 digit CVC';
    return e;
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const e2 = validate();
    if (Object.keys(e2).length > 0) { setErrors(e2); return; }
    setStep('processing');
    setTimeout(() => setStep('success'), 2200);
  };

  const fmt = (val, field) => {
    if (field === 'number') return val.replace(/\D/g, '').slice(0, 16).replace(/(.{4})/g, '$1 ').trim();
    if (field === 'expiry') {
      const d = val.replace(/\D/g, '').slice(0, 4);
      return d.length >= 3 ? d.slice(0, 2) + '/' + d.slice(2) : d;
    }
    if (field === 'cvc') return val.replace(/\D/g, '').slice(0, 4);
    return val;
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-box glass-strong" onClick={(e) => e.stopPropagation()}>

        {/* Close */}
        <button className="modal-close" onClick={onClose} aria-label="Close">✕</button>

        {step === 'form' && (
          <>
            <div className="modal-header">
              <span className="modal-icon">💳</span>
              <h2>Upgrade to <span className="gradient-text">{tier.name}</span></h2>
              <p className="modal-sub">You'll be charged <strong>${tier.price}/mo</strong>. Cancel anytime.</p>
            </div>

            <div className="modal-secure-badge glass">
              <span>🔒</span> Secured by Stripe — your card details never touch our servers
            </div>

            <form className="checkout-form" onSubmit={handleSubmit} noValidate>
              <div className="field-group">
                <label>Cardholder Name</label>
                <input
                  className={`input ${errors.name ? 'input-error' : ''}`}
                  type="text"
                  placeholder="Jane Smith"
                  value={card.name}
                  onChange={(e) => { setCard({ ...card, name: e.target.value }); setErrors({ ...errors, name: '' }); }}
                />
                {errors.name && <span className="field-error">{errors.name}</span>}
              </div>

              <div className="field-group">
                <label>Card Number</label>
                <div className="card-input-wrap">
                  <span className="card-scheme">💳</span>
                  <input
                    className={`input card-number-input ${errors.number ? 'input-error' : ''}`}
                    type="text"
                    placeholder="4242 4242 4242 4242"
                    value={card.number}
                    onChange={(e) => { setCard({ ...card, number: fmt(e.target.value, 'number') }); setErrors({ ...errors, number: '' }); }}
                  />
                </div>
                {errors.number && <span className="field-error">{errors.number}</span>}
              </div>

              <div className="field-row">
                <div className="field-group">
                  <label>Expiry</label>
                  <input
                    className={`input ${errors.expiry ? 'input-error' : ''}`}
                    type="text"
                    placeholder="MM/YY"
                    value={card.expiry}
                    onChange={(e) => { setCard({ ...card, expiry: fmt(e.target.value, 'expiry') }); setErrors({ ...errors, expiry: '' }); }}
                  />
                  {errors.expiry && <span className="field-error">{errors.expiry}</span>}
                </div>
                <div className="field-group">
                  <label>CVC</label>
                  <input
                    className={`input ${errors.cvc ? 'input-error' : ''}`}
                    type="text"
                    placeholder="123"
                    value={card.cvc}
                    onChange={(e) => { setCard({ ...card, cvc: fmt(e.target.value, 'cvc') }); setErrors({ ...errors, cvc: '' }); }}
                  />
                  {errors.cvc && <span className="field-error">{errors.cvc}</span>}
                </div>
              </div>

              <button type="submit" className="btn btn-primary checkout-btn">
                Pay ${tier.price} / month →
              </button>
              <p className="modal-fine-print">30-day money-back guarantee · No hidden fees</p>
            </form>
          </>
        )}

        {step === 'processing' && (
          <div className="modal-state">
            <div className="processing-ring" />
            <h2>Processing…</h2>
            <p className="modal-sub">Securely charging your card</p>
          </div>
        )}

        {step === 'success' && (
          <div className="modal-state">
            <div className="success-icon">✓</div>
            <h2>You're on <span className="gradient-text">{tier.name}</span>!</h2>
            <p className="modal-sub">Your plan has been upgraded. Enjoy the full power of Aegis AI.</p>
            <Link to="/dashboard" className="btn btn-primary checkout-btn" onClick={onClose}>
              Go to Dashboard →
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Contact Sales Modal ─────────────────────────────────────────── */
function ContactSalesModal({ onClose }) {
  const { user } = useAuth();
  const [form, setForm] = useState({
    name: user?.full_name || user?.username || '',
    email: user?.email || '',
    message: '',
  });
  const [status, setStatus] = useState(''); // '' | 'sending' | 'sent' | 'error'

  const handleSend = (e) => {
    e.preventDefault();
    if (!form.message.trim()) return;
    setStatus('sending');
    // Simulate sending (no backend endpoint for sales enquiries)
    setTimeout(() => setStatus('sent'), 1600);
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-box glass-strong" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose} aria-label="Close">✕</button>

        {status === 'sent' ? (
          <div className="modal-state">
            <div className="success-icon">✓</div>
            <h2>Message <span className="gradient-text">Sent!</span></h2>
            <p className="modal-sub">Our sales team will reach out within 24 hours. Thanks for reaching out!</p>
            <button className="btn btn-primary checkout-btn" onClick={onClose}>Close</button>
          </div>
        ) : (
          <>
            <div className="modal-header">
              <span className="modal-icon">💬</span>
              <h2>Talk to <span className="gradient-text">Sales</span></h2>
              <p className="modal-sub">Tell us about your needs and we'll get back to you within 24 hours.</p>
            </div>

            <form className="checkout-form" onSubmit={handleSend} noValidate>
              <div className="field-group">
                <label>Name</label>
                <input
                  className="input"
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="Your name"
                  required
                />
              </div>

              <div className="field-group">
                <label>Email</label>
                <input
                  className="input"
                  type="email"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  placeholder="your@email.com"
                  required
                />
              </div>

              <div className="field-group">
                <label>Your Message / Issue</label>
                <textarea
                  className="input sales-textarea"
                  rows={5}
                  value={form.message}
                  onChange={(e) => setForm({ ...form, message: e.target.value })}
                  placeholder="Describe your use case, team size, or any questions you have…"
                  required
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary checkout-btn"
                disabled={status === 'sending' || !form.message.trim()}
              >
                {status === 'sending' ? (
                  <><span className="btn-spinner" /> Sending…</>
                ) : (
                  'Send Message →'
                )}
              </button>
              <p className="modal-fine-print">We typically respond within 24 hours · No spam, ever</p>
            </form>
          </>
        )}
      </div>
    </div>
  );
}

/* ── Pricing page ────────────────────────────────────────────────── */
export default function Pricing() {
  const [activeTier, setActiveTier] = useState(null); // tier object for checkout modal
  const [salesOpen, setSalesOpen] = useState(false);  // contact sales modal

  return (
    <>
      <div className="orb orb-cyan" style={{ position: 'fixed' }} />
      <div className="orb orb-purple" style={{ position: 'fixed' }} />
      <Navbar />
      <div className="page pricing-page">

      <section className="pricing-hero">
        <div className="pricing-badge glass">
          <span className="badge-dot" />
          Transparent Pricing
        </div>
        <h1 className="pricing-title">
          Plans that scale<br />
          <span className="gradient-text">with your threat surface</span>
        </h1>
        <p className="pricing-sub">
          Start free. Upgrade when you're ready. Every plan includes AI-powered alert analysis,
          real-time detection, and the MITRE ATT&CK mapping engine.
        </p>
      </section>

      <section className="pricing-grid-section">
        <div className="pricing-grid">
          {TIERS.map((tier) => (
            <div
              key={tier.id}
              className={`tier-card glass${tier.highlighted ? ' tier-pro' : ''}`}
            >
              {tier.badge && (
                <div className="tier-badge">{tier.badge}</div>
              )}

              <div className="tier-header">
                <h2 className="tier-name">{tier.name}</h2>
                <div className="tier-price">
                  <span className="price-dollar">$</span>
                  <span className="price-amount">{tier.price}</span>
                  <span className="price-period">{tier.period}</span>
                </div>
                <p className="tier-tagline">{tier.tagline}</p>
              </div>

              <ul className="tier-features">
                {tier.features.map((f, i) => (
                  <li key={i} className="tier-feature">
                    <span className="feature-check">✓</span>
                    <span className="feature-icon-sm">{f.icon}</span>
                    {f.text}
                  </li>
                ))}
              </ul>

              <div className="tier-cta">
                {tier.ctaLink ? (
                  <Link
                    to={tier.ctaLink}
                    className={`btn ${tier.highlighted ? 'btn-primary' : 'btn-ghost'} tier-btn`}
                  >
                    {tier.cta}
                  </Link>
                ) : tier.id === 'enterprise' ? (
                  <button
                    className={`btn btn-ghost tier-btn`}
                    onClick={() => setSalesOpen(true)}
                  >
                    {tier.cta}
                  </button>
                ) : (
                  <button
                    className={`btn ${tier.highlighted ? 'btn-primary' : 'btn-ghost'} tier-btn`}
                    onClick={() => setActiveTier(tier)}
                  >
                    {tier.cta}
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* FAQ-style note */}
      <section className="pricing-note-section">
        <div className="pricing-note glass">
          <span className="note-icon">💡</span>
          <div>
            <strong>Need something custom?</strong>{' '}
            <span style={{ color: 'var(--text-muted)' }}>
              Enterprise plans can be tailored to your team's exact log volume, compliance requirements, and SLA. Reach out and we'll scope it together.
            </span>
          </div>
          <button className="btn btn-outline" onClick={() => setSalesOpen(true)}>
            Talk to Sales
          </button>
        </div>
      </section>

      {/* Footer mirror from Landing */}
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

      {/* Checkout Modal */}
      {activeTier && (
        <CheckoutModal tier={activeTier} onClose={() => setActiveTier(null)} />
      )}
      {/* Contact Sales Modal */}
      {salesOpen && (
        <ContactSalesModal onClose={() => setSalesOpen(false)} />
      )}
      </div>
    </>
  );
}
