import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext(null);

const API_BASE = 'http://127.0.0.1:8000';

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('aegis_token'));
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    if (token) {
      fetch(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (data) setUser(data);
          else logout();
        })
        .catch(() => logout())
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, [token]);

  const login = (tokenValue, userData) => {
    localStorage.setItem('aegis_token', tokenValue);
    setToken(tokenValue);
    setUser(userData);
  };

  const logout = useCallback(() => {
    localStorage.removeItem('aegis_token');
    setToken(null);
    setUser(null);
  }, []);

  /**
   * Re-fetches the current user from /auth/me and updates state in place —
   * no page reload needed. Useful after actions that change user data
   * server-side without going through login() again, e.g. regenerating
   * an API key or updating profile fields.
   */
  const refreshUser = async () => {
    if (!token) return null;
    try {
      const res = await fetch(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        logout();
        return null;
      }
      const data = await res.json();
      setUser(data);
      return data;
    } catch {
      return null;
    }
  };

  /**
   * Global authenticated fetch wrapper.
   *
   * - Automatically injects `Authorization: Bearer <token>`.
   * - Intercepts **any 401 response** from the backend (including ghost-token
   *   sessions where the user no longer exists in the DB) and immediately
   *   clears the local session and redirects to /auth.
   *
   * Usage (drop-in replacement for fetch()):
   *   const res = await apiFetch('/alerts');
   *   const res = await apiFetch('/alerts', { method: 'DELETE' });
   */
  const apiFetch = useCallback(
    async (path, options = {}) => {
      const currentToken = localStorage.getItem('aegis_token');
      const headers = {
        ...(options.headers || {}),
        ...(currentToken ? { Authorization: `Bearer ${currentToken}` } : {}),
      };

      const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

      if (res.status === 401) {
        // Ghost token or expired session — purge local auth state and
        // send the user back to the login page immediately.
        logout();
        navigate('/auth', { replace: true });
        // Re-throw so callers can bail out of their own try/catch cleanly.
        throw new Error('Session expired. Please log in again.');
      }

      return res;
    },
    [logout, navigate],
  );

  return (
    <AuthContext.Provider value={{ user, token, login, logout, loading, refreshUser, apiFetch }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
