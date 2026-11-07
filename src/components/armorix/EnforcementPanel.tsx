import {useEffect,useState} from 'react';
import {useServerFn} from '@tanstack/react-start';
import {approveAudit,getEnforcement,revokeApproval,sanitizeAudit} from '@/lib/scan/records.functions';
import {supabase} from '@/integrations/supabase/client';
import {Button} from '@/components/ui/button';
import {Input} from '@/components/ui/input';
import {ShieldCheck,ShieldOff,Play,RefreshCw,WandSparkles,Download,ChevronDown} from 'lucide-react';
import {cn} from '@/lib/utils';

export function EnforcementPanel({id,endpoint,token}:{id:string;endpoint:string|null;token:string}) {
  const get = useServerFn(getEnforcement);const approve = useServerFn(approveAudit);const revoke = useServerFn(revokeApproval);
  const sanitize=useServerFn(sanitizeAudit);
  const [remediation,setRemediation]=useState<Awaited<ReturnType<typeof sanitizeAudit>>|null>(null);
  const [state,setState] = useState<Awaited<ReturnType<typeof getEnforcement>> | null>(null);
  const [name,setName] = useState('');const [args,setArgs] = useState('{}');
  const [error,setError] = useState(''); const [busy,setBusy] = useState(false); const [result,setResult] = useState('');
  async function refresh() {try {setState(await get({data:{id}}));} catch(e) {setError(e instanceof Error?e.message:'Could not load events');}}
  useEffect(()=>{void refresh();},[id]);
  async function action(kind:'approve'|'revoke'|'call'|'sanitize') {
    setBusy(true);setError('');setResult('');
    try {
      if (kind === 'approve') { const res = await approve({data:{id}});setName(res.tools[0] ?? ''); }
      else if (kind === 'revoke') await revoke({data:{id}});
      else if(kind === 'sanitize')setRemediation(await sanitize({data:{id}}));
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
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2"><h2 className="text-sm font-medium">Guardrail dashboard</h2>
      <div className="flex gap-2"><Button variant="ghost" size="icon" title="Refresh execution records" onClick={refresh}><RefreshCw className="size-3.5"/></Button>
        {endpoint && (state?.tools.length ? <Button variant="outline" size="sm" disabled={busy} onClick={()=>action('revoke')}><ShieldOff className="size-3.5"/>Revoke approval</Button>:<Button variant="outline" size="sm" disabled={busy||!state?.classifications.some(t=>t.eligible)} onClick={()=>action('approve')}><ShieldCheck className="size-3.5"/>Approve low-risk tools</Button>)}
      </div>
    </div>
    <p className="mb-3 text-xs text-muted-foreground">{state?.tools.length ? `${state.tools.length} approved`:'Default deny'}</p>
    {state&&<><div className="mb-3 grid grid-cols-3 gap-3">{(['allowed','blocked','review'] as const).map(status=><div key={status} className="border-l-2 border-border pl-3"><span className={cn('font-mono text-xl',status==='allowed'?'text-success':status==='blocked'?'text-destructive':'text-warning')}>{state.classifications.filter(t=>t.status===status).length}</span><p className="text-xs capitalize text-muted-foreground">{status==='review'?'Needs review':status}</p></div>)}</div><div className="mb-4 max-h-64 overflow-auto divide-y divide-border">{state.classifications.map(tool=><div key={tool.name} className="grid min-w-0 grid-cols-[minmax(0,1fr)_auto] gap-1 py-2 text-xs"><span className="truncate font-mono" title={tool.name}>{tool.name}</span><span className={cn('capitalize',tool.status==='allowed'?'text-success':tool.status==='blocked'?'text-destructive':'text-warning')}>{tool.status==='review'?'Needs review':tool.status}</span><span className="col-span-2 text-muted-foreground">{tool.reason}</span></div>)}</div></>}
    {endpoint && <details className="group border-y border-border"><summary className="flex cursor-pointer list-none items-center justify-between py-3 text-xs"><span className="flex items-center gap-2"><Play className="size-3.5 text-primary"/>Runtime console</span><ChevronDown className="size-3.5 text-muted-foreground transition-transform group-open:rotate-180"/></summary><div className="grid min-w-0 gap-2 pb-3 sm:grid-cols-[minmax(0,1fr)_auto]">
      <Input aria-label="Tool name" placeholder="Tool name" value={name} onChange={e=>setName(e.target.value)} list={`approved-${id}`}/>
      <datalist id={`approved-${id}`}>{state?.tools.map(t=><option key={t} value={t}/>)}</datalist>
      <Button disabled={busy || !name} onClick={()=>action('call')}><Play className="size-3.5"/>Guarded call</Button>
      <textarea aria-label="Tool arguments" value={args} onChange={e=>setArgs(e.target.value)} className="h-24 min-w-0 rounded-md border border-input bg-background p-3 font-mono text-xs sm:col-span-2"/>
    </div></details>}
    {error && <p role="alert" className="mt-2 text-xs text-warning">{error}</p>}
    {result && <pre aria-label="Guarded call result" className="mt-3 max-h-60 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3 font-mono text-xs">{result}</pre>}
    <div className="mt-4 border-t border-border pt-3"><Button variant="outline" size="sm" disabled={busy} onClick={()=>action('sanitize')}><WandSparkles className="size-3.5"/>Sanitize definitions</Button>{remediation&&<div className="mt-3 space-y-2"><div className="flex flex-wrap items-center justify-between gap-2"><span className="text-xs text-muted-foreground">{remediation.changes.length} removals · {remediation.excluded.length} excluded tools · Re-audit required</span><Button variant="ghost" size="icon" aria-label="Download sanitized definitions" title="Download sanitized definitions" onClick={()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(remediation,null,2)],{type:'application/json'}));const anchor=document.createElement('a');anchor.href=url;anchor.download=`armorix-sanitized-${id}.json`;anchor.click();URL.revokeObjectURL(url);}}><Download className="size-4"/></Button></div><p className="text-xs text-warning">{remediation.warning}</p><pre aria-label="Sanitized definitions" className="max-h-48 overflow-auto whitespace-pre-wrap break-words bg-muted p-3 font-mono text-xs">{JSON.stringify({tools:remediation.tools,changes:remediation.changes,excluded:remediation.excluded},null,2)}</pre></div>}</div>
    <div className="mt-3 divide-y divide-border">{state?.events.map(e=><div key={e.id} className="flex flex-wrap gap-x-3 gap-y-1 py-2 text-xs"><span className={cn('font-mono',e.decision === 'blocked'?'text-destructive':e.decision === 'forwarded'?'text-success':'text-warning')}>{e.decision}</span><span className="font-mono">{e.tool}</span><span className="text-muted-foreground">{e.reason}</span></div>)}</div>
  </section>;
}