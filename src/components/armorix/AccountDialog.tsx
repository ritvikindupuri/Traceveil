import {useState} from 'react';
import {supabase} from '@/integrations/supabase/client';
import {lovable} from '@/integrations/lovable';
import {Button} from '@/components/ui/button';
import {Input} from '@/components/ui/input';
import {Dialog,DialogContent,DialogTitle,DialogDescription} from '@/components/ui/dialog';
import '@lovable.dev/cloud-auth-js/styles.css';

export function AccountDialog({open,onOpenChange}:{open:boolean;onOpenChange:(v:boolean)=>void}) {
  const [mode,setMode] = useState<'signin'|'signup'|'reset'>('signin');
  const [email,setEmail] = useState(''); const [password,setPassword] = useState('');
  const [message,setMessage] = useState(''); const [busy,setBusy] = useState(false);
  async function submit(e:React.FormEvent) {
    e.preventDefault();setBusy(true);setMessage('');
    try {
      if (mode === 'reset') {
        const {error} = await supabase.auth.resetPasswordForEmail(email,{redirectTo:window.location.origin+'/reset-password'});
        if (error) throw error;
        setMessage('Check your email for the reset link.');
      } else if (mode === 'signup') {
        const {data,error} = await supabase.auth.signUp({email,password,options:{emailRedirectTo:window.location.origin}});
        if (error) throw error;
        if (data.session) onOpenChange(false); else setMessage('Check your email to confirm your account.');
      } else {
        const {error} = await supabase.auth.signInWithPassword({email,password});
        if (error) throw error;
        onOpenChange(false);
      }
    } catch(err) {setMessage(err instanceof Error ? err.message : 'Sign-in failed');} finally {setBusy(false);}
  }
  async function oauth(provider:'google') {
    setBusy(true);setMessage('');
    try {
      const result = await lovable.auth.signInWithOAuth(provider,{redirect_uri:window.location.origin});
      if (result.error) setMessage(result.error.message); else if (!result.redirected) onOpenChange(false);
    } catch {setMessage('Sign-in failed');} finally {setBusy(false);}
  }
  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent className="max-w-sm">
    <DialogTitle>{mode === 'signup' ? 'Create Traceveil account' : mode === 'reset' ? 'Reset password' : 'Sign in to Traceveil'}</DialogTitle>
    <DialogDescription>Private audits · approved tools · execution records</DialogDescription>
    <form onSubmit={submit} className="space-y-3">
      <Input type="email" aria-label="Email" placeholder="Email" autoComplete="email" value={email} onChange={e=>setEmail(e.target.value)} required />
      {mode !== 'reset' && <Input type="password" aria-label="Password" placeholder="Password" autoComplete={mode === 'signup' ? 'new-password':'current-password'} minLength={8} value={password} onChange={e=>setPassword(e.target.value)} required />}
      <Button type="submit" className="w-full" disabled={busy}>{mode === 'signup'?'Create account':mode === 'reset'?'Send reset link':'Sign in'}</Button>
    </form>
    {mode !== 'reset' && <div className="space-y-2">
      <Button type="button" variant="outline" className="google-auth w-full" disabled={busy} onClick={()=>oauth('google')}>
        <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M23.49 12.27c0-.79-.07-1.54-.19-2.27H12v4.51h6.47c-.29 1.48-1.14 2.73-2.4 3.58v3h3.86c2.26-2.09 3.56-5.17 3.56-8.82z"/><path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.86-3c-1.08.72-2.45 1.16-4.07 1.16-3.13 0-5.78-2.11-6.73-4.96H1.29v3.09C3.26 21.3 7.31 24 12 24z"/><path fill="#FBBC05" d="M5.27 14.29c-.25-.72-.38-1.49-.38-2.29s.14-1.57.38-2.29V6.62H1.29C.47 8.24 0 10.06 0 12s.47 3.76 1.29 5.38l3.98-3.09z"/><path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.29 6.62l3.98 3.09c.95-2.85 3.6-4.96 6.73-4.96z"/></svg>Continue with Google
      </Button>
    </div>}
    <div className="flex flex-wrap justify-between">
      <Button variant="ghost" size="sm" onClick={()=>{setMode(mode === 'signup'?'signin':'signup');setMessage('');}}>{mode === 'signup'?'Sign in instead':'Create account'}</Button>
      <Button variant="ghost" size="sm" onClick={()=>{setMode(mode === 'reset'?'signin':'reset');setMessage('');}}>{mode === 'reset'?'Back to sign in':'Forgot password?'}</Button>
    </div>
    {message && <p role="status" className="text-sm text-warning">{message}</p>}
  </DialogContent></Dialog>;
}