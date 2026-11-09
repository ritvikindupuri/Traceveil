import {useState} from 'react';
import {supabase} from '@/integrations/supabase/client';
import {Button} from '@/components/ui/button';
import {Input} from '@/components/ui/input';
import {Dialog,DialogContent,DialogTitle,DialogDescription} from '@/components/ui/dialog';
import {Lock,Mail,ShieldCheck} from 'lucide-react';

export function AccountDialog({open,onOpenChange}:{open:boolean;onOpenChange:(v:boolean)=>void}) {
  const [mode,setMode] = useState<'signin'|'signup'|'reset'>('signin');
  const [email,setEmail] = useState('');
  const [password,setPassword] = useState('');
  const [message,setMessage] = useState('');
  const [busy,setBusy] = useState(false);

  async function submit(e:React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage('');
    try {
      if (mode === 'reset') {
        const {error} = await supabase.auth.resetPasswordForEmail(email);
        if (error) throw error;
        setMessage('Check your email for password reset instructions.');
      } else if (mode === 'signup') {
        if (password.length < 8) {
          setMessage('Password must be at least 8 characters.');
          setBusy(false);
          return;
        }
        const {data,error} = await supabase.auth.signUp({email,password});
        if (error) throw error;
        if (data.session) {
          onOpenChange(false);
          setEmail('');
          setPassword('');
        } else {
          setMessage('Account created. You may now sign in.');
        }
      } else {
        const {error} = await supabase.auth.signInWithPassword({email,password});
        if (error) throw error;
        onOpenChange(false);
        setEmail('');
        setPassword('');
      }
    } catch(err) {
      setMessage(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <div className="flex items-center gap-2 text-primary font-medium">
          <ShieldCheck className="size-5" />
          <DialogTitle>
            {mode === 'signup' ? 'Create Traceveil account' : mode === 'reset' ? 'Reset password' : 'Sign in to Traceveil'}
          </DialogTitle>
        </div>
        <DialogDescription>
          Private audits · approved tools · execution records
        </DialogDescription>
        <form onSubmit={submit} className="space-y-3 pt-2">
          <div className="relative">
            <Mail className="absolute left-3 top-2.5 size-4 text-muted-foreground" />
            <Input
              type="email"
              aria-label="Email"
              placeholder="Email"
              autoComplete="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              className="pl-9"
            />
          </div>
          {mode !== 'reset' && (
            <div className="space-y-1">
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 size-4 text-muted-foreground" />
                <Input
                  type="password"
                  aria-label="Password"
                  placeholder="Password (min 8 chars)"
                  autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
                  minLength={8}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  className="pl-9"
                />
              </div>
              {mode === 'signup' && (
                <p className="text-[11px] text-muted-foreground">Passwords are securely hashed using scrypt.</p>
              )}
            </div>
          )}
          <Button type="submit" className="w-full" disabled={busy}>
            {busy ? 'Processing…' : mode === 'signup' ? 'Create account' : mode === 'reset' ? 'Send reset link' : 'Sign in'}
          </Button>
        </form>

        <div className="flex flex-wrap justify-between pt-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setMode(mode === 'signup' ? 'signin' : 'signup');
              setMessage('');
            }}
          >
            {mode === 'signup' ? 'Sign in instead' : 'Create account'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setMode(mode === 'reset' ? 'signin' : 'reset');
              setMessage('');
            }}
          >
            {mode === 'reset' ? 'Back to sign in' : 'Forgot password?'}
          </Button>
        </div>
        {message && <p role="status" className="text-xs text-amber-500">{message}</p>}
      </DialogContent>
    </Dialog>
  );
}