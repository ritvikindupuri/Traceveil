// Self-contained client-side Auth and Database client.
// Replaces external Supabase dependencies with local, secure session auth.

export interface User {
  id: string;
  email: string;
}

export interface Session {
  access_token: string;
  user: User;
}

type AuthChangeEvent = 'SIGNED_IN' | 'SIGNED_OUT' | 'USER_UPDATED' | 'PASSWORD_RECOVERY';
type AuthListener = (event: AuthChangeEvent, session: Session | null) => void;

const listeners = new Set<AuthListener>();
const STORAGE_KEY = 'traceveil_auth_session';

function getStoredSession(): Session | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function setStoredSession(session: Session | null) {
  if (typeof window === 'undefined') return;
  try {
    if (session) {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    } else {
      window.localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore storage quota errors
  }
}

function notify(event: AuthChangeEvent, session: Session | null) {
  listeners.forEach(cb => {
    try {
      cb(event, session);
    } catch (err) {
      console.error('[auth] Listener error:', err);
    }
  });
}

export const auth = {
  async getUser(): Promise<{ data: { user: User | null }; error: Error | null }> {
    const session = getStoredSession();
    if (!session?.access_token) {
      return { data: { user: null }, error: null };
    }
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ action: 'session' }),
      });
      const json = await res.json();
      if (json.data?.user) {
        return { data: { user: json.data.user }, error: null };
      }
      setStoredSession(null);
      return { data: { user: null }, error: null };
    } catch {
      return { data: { user: session.user || null }, error: null };
    }
  },

  async getSession(): Promise<{ data: { session: Session | null }; error: Error | null }> {
    const session = getStoredSession();
    return { data: { session }, error: null };
  },

  async signInWithPassword({ email, password }: { email: string; password: string }): Promise<{
    data: { user: User | null; session: Session | null };
    error: Error | null;
  }> {
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'signin', email, password }),
      });
      const json = await res.json();
      if (!res.ok || json.error) {
        return { data: { user: null, session: null }, error: new Error(json.error || 'Sign in failed') };
      }
      const session: Session = json.data.session;
      setStoredSession(session);
      notify('SIGNED_IN', session);
      return { data: json.data, error: null };
    } catch (err) {
      return {
        data: { user: null, session: null },
        error: new Error(err instanceof Error ? err.message : 'Sign in failed'),
      };
    }
  },

  async signUp({ email, password }: { email: string; password: string }): Promise<{
    data: { user: User | null; session: Session | null };
    error: Error | null;
  }> {
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'signup', email, password }),
      });
      const json = await res.json();
      if (!res.ok || json.error) {
        return { data: { user: null, session: null }, error: new Error(json.error || 'Sign up failed') };
      }
      const session: Session = json.data.session;
      setStoredSession(session);
      notify('SIGNED_IN', session);
      return { data: json.data, error: null };
    } catch (err) {
      return {
        data: { user: null, session: null },
        error: new Error(err instanceof Error ? err.message : 'Sign up failed'),
      };
    }
  },

  async signOut(): Promise<{ error: Error | null }> {
    const session = getStoredSession();
    if (session?.access_token) {
      fetch('/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ action: 'signout' }),
      }).catch(() => {});
    }
    setStoredSession(null);
    notify('SIGNED_OUT', null);
    return { error: null };
  },

  onAuthStateChange(callback: AuthListener): { data: { subscription: { unsubscribe: () => void } } } {
    listeners.add(callback);
    // Fire initial state
    const session = getStoredSession();
    if (session) {
      setTimeout(() => callback('SIGNED_IN', session), 0);
    }
    return {
      data: {
        subscription: {
          unsubscribe: () => {
            listeners.delete(callback);
          },
        },
      },
    };
  },

  async resetPasswordForEmail(email: string): Promise<{ data: unknown; error: Error | null }> {
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'reset-password', email }),
      });
      const json = await res.json();
      return { data: json.data || {}, error: null };
    } catch (err) {
      return { data: null, error: new Error(err instanceof Error ? err.message : 'Reset failed') };
    }
  },

  async updateUser({ password }: { password: string }): Promise<{
    data: { user: User | null };
    error: Error | null;
  }> {
    const session = getStoredSession();
    if (!session?.access_token) {
      return { data: { user: null }, error: new Error('Sign in required') };
    }
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ action: 'update-password', password }),
      });
      const json = await res.json();
      if (!res.ok || json.error) {
        return { data: { user: null }, error: new Error(json.error || 'Update failed') };
      }
      return { data: json.data, error: null };
    } catch (err) {
      return { data: { user: null }, error: new Error(err instanceof Error ? err.message : 'Update failed') };
    }
  },
};

export const supabase = {
  auth,
};
