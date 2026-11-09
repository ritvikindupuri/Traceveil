import { useState } from 'react';
import { KeyRound, Trash2, Loader2, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { supabase } from '@/integrations/supabase/client';

export function GithubCredential({ signedIn, onSignIn }: { signedIn: boolean; onSignIn: () => void }) {
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState('');
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function getAuthHeader() {
    const { data } = await supabase.auth.getSession();
    const token = data.session?.access_token;
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  async function show() {
    if (!signedIn) {
      onSignIn();
      return;
    }
    setOpen(true);
    setBusy(true);
    setError('');
    try {
      const headers = await getAuthHeader();
      const res = await fetch('/api/github-credentials', { headers });
      if (res.ok) {
        const data = await res.json();
        setConnected(data.connected);
        if (data.error) setError(data.error);
      } else {
        setError('Could not load GitHub connection.');
      }
    } catch {
      setError('Could not load GitHub connection.');
    } finally {
      setBusy(false);
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    const value = token.trim();
    try {
      const headers = await getAuthHeader();
      const res = await fetch('/api/github-credentials', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...headers,
        },
        body: JSON.stringify({ token: value }),
      });
      const data = await res.json();
      if (data.ok) {
        setConnected(true);
        setToken('');
      } else {
        setError(data.error ?? 'Could not save token.');
      }
    } catch {
      setError('Could not save token.');
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    setError('');
    setToken('');
    try {
      const headers = await getAuthHeader();
      const res = await fetch('/api/github-credentials', {
        method: 'DELETE',
        headers,
      });
      const data = await res.json();
      if (data.ok) {
        setConnected(false);
      } else {
        setError(data.error ?? 'Could not remove token.');
      }
    } catch {
      setError('Could not remove token.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Button
        variant="ghost"
        size="icon"
        aria-label="GitHub token"
        title="GitHub credentials"
        onClick={() => void show()}
      >
        <KeyRound className="size-4" />
      </Button>
      <Dialog
        open={open && signedIn}
        onOpenChange={value => {
          setOpen(value);
          setToken('');
          setError('');
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>GitHub access</DialogTitle>
            <DialogDescription>
              Personal Access Token (classic or fine-grained) with repo permissions to create branches, open pull requests, and auto-merge fixes live. Token is encrypted server-side.
            </DialogDescription>
          </DialogHeader>
          <div className="flex items-center justify-between border-y border-border py-3 text-xs">
            <span className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-primary" />
              {busy ? 'Checking…' : connected ? 'Token saved' : 'No token saved'}
            </span>
            {connected && (
              <Button
                variant="ghost"
                size="icon"
                aria-label="Remove GitHub token"
                title="Remove GitHub token"
                disabled={busy}
                onClick={() => void disconnect()}
              >
                <Trash2 className="size-4" />
              </Button>
            )}
          </div>
          <form onSubmit={submit} className="space-y-3" autoComplete="off">
            <label className="block text-xs" htmlFor="github-pat">
              {connected ? 'Replace token' : 'Personal access token'}
            </label>
            <input
              id="github-pat"
              name="github-pat"
              type="password"
              autoComplete="off"
              spellCheck={false}
              autoCapitalize="none"
              value={token}
              onChange={e => setToken(e.target.value)}
              maxLength={256}
              required
              className="h-10 w-full rounded border border-input bg-background px-3 text-sm outline-none focus:ring-1 focus:ring-ring"
            />
            <Button type="submit" disabled={busy || !token} className="w-full">
              {busy ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />}
              {connected ? 'Replace token' : 'Save token'}
            </Button>
          </form>
          {error && (
            <p role="alert" className="text-xs text-destructive">
              {error}
            </p>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}