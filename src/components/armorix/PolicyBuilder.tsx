import {useEffect,useState} from 'react';
import {useServerFn} from '@tanstack/react-start';
import {getRuntimePolicy,saveRuntimePolicy} from '@/lib/scan/runtime-policy.functions';
import {runtimePolicySchema,evaluateRuntimePolicy,type RuntimePolicy} from '@/lib/scan/runtime-policy';
import {trustedDestination} from '@/lib/scan/destinations';
import type {Verdict} from '@/lib/scan/types';
import {Button} from '@/components/ui/button';
import {Input} from '@/components/ui/input';
import {Switch} from '@/components/ui/switch';
import {Save,X,ShieldCheck,ChevronDown} from 'lucide-react';
import {cn} from '@/lib/utils';

export function PolicyBuilder({onClose,onSaved,endpoint,verdict}:{onClose:()=>void;onSaved:()=>void;endpoint:string|null;verdict:Verdict|null}){
 const get=useServerFn(getRuntimePolicy);const save=useServerFn(saveRuntimePolicy);
 const [policy,setPolicy]=useState<RuntimePolicy|null>(null);
 const [hosts,setHosts]=useState('');const [tools,setTools]=useState('');
 const [revision,setRevision]=useState('');const [status,setStatus]=useState('');const [busy,setBusy]=useState(false);
 useEffect(()=>{void get().then(value=>{setPolicy(value.policy);setHosts(value.policy.hosts.join('\n'));setTools(value.policy.tools.join('\n'));setRevision(value.revision);}).catch(()=>setStatus('Policy unavailable'));},[]);
 const draft=policy?{...policy,hosts:hosts.split(/[,\n]/).map(s=>s.trim()).filter(Boolean),tools:tools.split(/[,\n]/).map(s=>s.trim()).filter(Boolean)}:null;
 const parsed=runtimePolicySchema.safeParse(draft);
 async function submit(e:React.FormEvent){
  e.preventDefault();if(!parsed.success)return;
  setBusy(true);setStatus('');
  try{const value=await save({data:parsed.data});setPolicy(value.policy);setRevision(value.revision);setStatus('Policy saved');onSaved();}catch{setStatus('Policy could not be saved');}finally{setBusy(false);}
 }
 return <section className="mx-auto max-w-[1400px] border-b border-border px-5 py-4">
  <div className="mb-4 flex items-center justify-between"><h2 className="flex items-center gap-2 text-sm font-medium"><ShieldCheck className="size-4 text-primary"/>Runtime policy</h2><Button variant="ghost" size="icon" aria-label="Close policy" onClick={onClose}><X className="size-4"/></Button></div>
  {policy&&<form onSubmit={submit} className="grid min-w-0 gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
   <div className="min-w-0 space-y-4">
    <div className="flex items-center justify-between"><label htmlFor="policy-enabled" className="text-xs">Forwarding enabled</label><Switch id="policy-enabled" checked={policy.enabled} onCheckedChange={enabled=>setPolicy({...policy,enabled})}/></div>
    <div className="grid gap-3 sm:grid-cols-2">{(['maxToolRisk','maxAuditRisk'] as const).map(key=><label key={key} className="space-y-2 text-xs text-muted-foreground">{key==='maxToolRisk'?'Maximum tool risk':'Maximum audit risk'}<Input aria-label={key==='maxToolRisk'?'Maximum tool risk':'Maximum audit risk'} type="number" min={0} max={100} step={1} value={policy[key]} onChange={e=>setPolicy({...policy,[key]:Number(e.target.value)})}/></label>)}</div>
    <div className="grid gap-3 sm:grid-cols-2"><label className="space-y-2 text-xs text-muted-foreground">Allowed hosts<textarea aria-label="Allowed hosts" value={hosts} onChange={e=>setHosts(e.target.value)} className="h-32 w-full resize-y rounded-md border border-input bg-background p-3 font-mono text-xs"/></label><label className="space-y-2 text-xs text-muted-foreground">Allowed tools<textarea aria-label="Allowed tools" value={tools} onChange={e=>setTools(e.target.value)} className="h-32 w-full resize-y rounded-md border border-input bg-background p-3 font-mono text-xs"/></label></div>
    <div className="flex items-center gap-3"><Button type="submit" size="sm" disabled={busy||!parsed.success}><Save className="size-3.5"/>Save policy</Button><span role="status" className="text-xs text-muted-foreground">{status||'Unsaved preview'}</span></div>
    {!parsed.success&&<p role="alert" className="text-xs text-warning">{parsed.error.issues[0]?.message}</p>}
   </div>
   <div className="min-w-0 space-y-3 lg:border-l lg:border-border lg:pl-5">
    <div className="flex items-center justify-between text-xs"><span>Live policy view</span><span className="text-muted-foreground">Default deny</span></div>
    {parsed.success&&verdict&&<div className="divide-y divide-border">{verdict.tools.map(tool=>{const reason=evaluateRuntimePolicy(parsed.data,endpoint,tool.tool,verdict);const authority=endpoint&&trustedDestination(endpoint)?.tools.some(t=>t===tool.tool);return <div key={tool.tool} className="flex items-center justify-between gap-3 py-2 text-xs" title={reason??(!authority?'Outside platform runtime allowlist':'Approval, schema and baseline checks still required')}><span className="min-w-0 truncate font-mono">{tool.tool}</span><span className={cn('shrink-0',reason||!authority?'text-destructive':'text-success')}>{reason||!authority?'Denied':'Policy eligible'}</span></div>;})}</div>}
    <div className="border-y border-border py-3 text-xs"><div className="flex justify-between gap-3"><span>Egress IP</span><span className="text-warning">Not configured</span></div><p className="mt-2 text-muted-foreground">Custom hosts blocked · destination-pinned service required</p></div>
    <details className="group"><summary className="flex cursor-pointer list-none items-center justify-between text-xs text-muted-foreground">Policy document<ChevronDown className="size-3.5 transition-transform group-open:rotate-180"/></summary><pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] text-muted-foreground">{JSON.stringify({revision,...draft,approvalRequired:true,platformAllowlistRequired:true},null,2)}</pre></details>
   </div>
  </form>}
  {!policy&&<p className="text-xs text-muted-foreground">{status||'Loading policy…'}</p>}
 </section>;
}