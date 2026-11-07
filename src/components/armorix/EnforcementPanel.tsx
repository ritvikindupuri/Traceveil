import {useEffect,useState} from 'react';
import {useServerFn} from '@tanstack/react-start';
import {approveAudit,getEnforcement,revokeApproval} from '@/lib/scan/records.functions';
import {supabase} from '@/integrations/supabase/client';
import {Button} from '@/components/ui/button';
import {Input} from '@/components/ui/input';
import {ShieldCheck,ShieldOff,Play,RefreshCw} from 'lucide-react';
import {cn} from '@/lib/utils';

export function EnforcementPanel({id,endpoint,token}:{id:string;endpoint:string|null;token:string}) {
  const get = useServerFn(getEnforcement);const approve = useServerFn(approveAudit);const revoke = useServerFn(revokeApproval);
  const [state,setState] = useState<Awaited<ReturnType<typeof getEnforcement>> | null>(null);
  const [name,setName] = useState('');const [args,setArgs] = useState('{}');
  const [error,setError] = useState(''); const [busy,setBusy] = useState(false); const [result,setResult] = useState('');
  async function refresh() {try {setState(await get({data:{id}}));} catch(e) {setError(e instanceof Error?e.message:'Could not load events');}}
  useEffect(()=>{void refresh();},[id]);
  async function action(kind:'approve'|'revoke'|'call') {
    setBusy(true);setError('');setResult('');
    try {
      if (kind === 'approve') { const res = await approve({data:{id}});setName(res.tools[0] ?? ''); }
      else if (kind === 'revoke') await revoke({data:{id}});
      else {
        const {data} = await supabase.auth.getSession();
        if (!data.session) throw new Error('Sign in to continue');
        const response = await fetch('/api/guard',{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${data.session.access_token}`},body:JSON.stringify({auditId:id,name,arguments:JSON.parse(args),token:token || undefined})});
        const value = await response.json();setResult(JSON.stringify(value,null,2));
      }
      await refresh();
    } catch(e) {setError(e instanceof Error?e.message:'Action failed');} finally {setBusy(false);}
  }
  return <section className="min-w-0 border-t border-border pt-4">
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2"><h2 className="text-sm font-medium">Runtime enforcement</h2>
      <div className="flex gap-2"><Button variant="ghost" size="icon-sm" title="Refresh execution records" onClick={refresh}><RefreshCw className="size-3.5"/></Button>
        {endpoint && (state?.tools.length ? <Button variant="outline" size="sm" disabled={busy} onClick={()=>action('revoke')}><ShieldOff className="size-3.5"/>Revoke approval</Button>:<Button variant="outline" size="sm" disabled={busy} onClick={()=>action('approve')}><ShieldCheck className="size-3.5"/>Approve low-risk tools</Button>)}
      </div>
    </div>
    <p className="mb-3 text-xs text-muted-foreground">{state?.tools.length ? `${state.tools.length} approved · schema validation · change blocking`:'Default deny · no approved tools'}</p>
    {endpoint && new URL(endpoint).hostname !== 'mcp.deepwiki.com' && <p className="mb-3 text-xs text-warning">Execution blocked for this host until destination-pinned egress is configured.</p>}
    {endpoint && <div className="grid min-w-0 gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
      <Input aria-label="Tool name" placeholder="Tool name" value={name} onChange={e=>setName(e.target.value)} list={`approved-${id}`}/>
      <datalist id={`approved-${id}`}>{state?.tools.map(t=><option key={t} value={t}/>)}</datalist>
      <Button disabled={busy || !name} onClick={()=>action('call')}><Play className="size-3.5"/>Guarded call</Button>
      <textarea aria-label="Tool arguments" value={args} onChange={e=>setArgs(e.target.value)} className="h-24 min-w-0 rounded-md border border-input bg-background p-3 font-mono text-xs sm:col-span-2"/>
    </div>}
    {error && <p role="alert" className="mt-2 text-xs text-warning">{error}</p>}
    {result && <pre aria-label="Guarded call result" className="mt-3 max-h-60 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3 font-mono text-xs">{result}</pre>}
    <div className="mt-3 divide-y divide-border">{state?.events.map(e=><div key={e.id} className="flex flex-wrap gap-x-3 gap-y-1 py-2 text-xs"><span className={cn('font-mono',e.decision === 'blocked'?'text-destructive':e.decision === 'forwarded'?'text-success':'text-warning')}>{e.decision}</span><span className="font-mono">{e.tool}</span><span className="text-muted-foreground">{e.reason}</span></div>)}</div>
  </section>;
}