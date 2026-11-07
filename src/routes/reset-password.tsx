import {createFileRoute} from '@tanstack/react-router';
import {useEffect,useState} from 'react';
import {supabase} from '@/integrations/supabase/client';
import {Button} from '@/components/ui/button';
import {Input} from '@/components/ui/input';
import {Logo} from '@/components/armorix/Logo';
export const Route = createFileRoute('/reset-password')({head:()=>({meta:[{title:'Reset password — Armorix'},{name:'description',content:'Securely reset your Armorix account password.'},{property:'og:title',content:'Reset password — Armorix'},{property:'og:description',content:'Securely reset your Armorix account password.'},{property:'og:type',content:'website'},{name:'twitter:card',content:'summary'}]}),component:ResetPassword});
function ResetPassword() {
  const [ready,setReady] = useState(false);const [password,setPassword] = useState('');const [message,setMessage] = useState('');const [busy,setBusy] = useState(false);
  useEffect(()=>{
    const hash = new URLSearchParams(window.location.hash.slice(1));
    if (hash.get('type') === 'recovery') setReady(true);
    const {data} = supabase.auth.onAuthStateChange(event=>{if (event === 'PASSWORD_RECOVERY') setReady(true);});
    return ()=>data.subscription.unsubscribe();
  },[]);
  async function submit(e:React.FormEvent) {e.preventDefault();setBusy(true);const {error} = await supabase.auth.updateUser({password});setMessage(error?.message ?? 'Password updated.');setBusy(false);}
  return <main className="mx-auto flex min-h-screen max-w-sm flex-col justify-center gap-4 px-5"><Logo/><h1 className="text-xl font-semibold">Reset password</h1>{ready?<form onSubmit={submit} className="space-y-3"><Input aria-label="New password" type="password" autoComplete="new-password" minLength={8} required value={password} onChange={e=>setPassword(e.target.value)}/><Button disabled={busy} type="submit">Update password</Button></form>:<p className="text-sm text-muted-foreground">Open the recovery link from your email.</p>}{message&&<p role="status" className="text-sm">{message}</p>}<Button variant="outline" onClick={()=>window.location.assign('/')}>Back to Armorix</Button></main>;
}