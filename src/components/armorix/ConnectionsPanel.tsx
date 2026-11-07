import {useEffect,useState} from 'react';
import {useServerFn} from '@tanstack/react-start';
import {listConnections,saveConnection,deleteConnection} from '@/lib/scan/connections.functions';
import {MCP_DESTINATIONS} from '@/lib/scan/destinations';
import {Button} from '@/components/ui/button';
import {Input} from '@/components/ui/input';
import {Switch} from '@/components/ui/switch';
import {Select,SelectContent,SelectItem,SelectTrigger,SelectValue} from '@/components/ui/select';
import {Lock,Plus,Power,X} from 'lucide-react';

export function ConnectionsPanel({onSelect,onClose}:{onSelect:(id:string,endpoint:string)=>void;onClose:()=>void}) {
  const list=useServerFn(listConnections),save=useServerFn(saveConnection),disable=useServerFn(deleteConnection);
  const [rows,setRows]=useState<Awaited<ReturnType<typeof listConnections>>>([]);
  const [endpoint,setEndpoint]=useState<string>(MCP_DESTINATIONS[0].endpoint);
  const [name,setName]=useState('DeepWiki'),[token,setToken]=useState(''),[enabled,setEnabled]=useState(true),[clearToken,setClearToken]=useState(false);
  const [busy,setBusy]=useState(false),[error,setError]=useState('');
  const destination=MCP_DESTINATIONS.find(d=>d.endpoint===endpoint);
  async function refresh(){try{setRows(await list());}catch{setError('Could not load connections');}}
  useEffect(()=>{void refresh();},[]);
  async function submit(e:React.FormEvent){e.preventDefault();setBusy(true);setError('');try{await save({data:{name,endpoint,enabled,token:token||undefined,clearToken}});setToken('');setClearToken(false);await refresh();}catch(e){setError(e instanceof Error?e.message:'Could not save');}finally{setBusy(false);}}
  return <section className="mx-auto max-w-[1400px] border-b border-border px-5 py-4">
    <div className="mb-4 flex items-center justify-between"><h2 className="text-sm font-medium">Trusted MCP connections</h2><Button variant="ghost" size="icon" aria-label="Close connections" onClick={onClose}><X className="size-4"/></Button></div>
    <div className="grid gap-5 lg:grid-cols-2">
      <form onSubmit={submit} className="space-y-3">
        <Select value={endpoint} onValueChange={value=>{setEndpoint(value);setName(MCP_DESTINATIONS.find(d=>d.endpoint===value)?.name??'');setToken('');setClearToken(false);}}><SelectTrigger aria-label="Trusted server"><SelectValue/></SelectTrigger><SelectContent>{MCP_DESTINATIONS.map(d=><SelectItem key={d.endpoint} value={d.endpoint}>{d.name}</SelectItem>)}</SelectContent></Select>
        <Input aria-label="Connection name" value={name} onChange={e=>setName(e.target.value)} required maxLength={100}/>
        <p className="break-all font-mono text-xs text-muted-foreground">{endpoint}</p>
        {destination?.auth&&<><Input aria-label="Stored bearer token" type="password" autoComplete="off" value={token} onChange={e=>setToken(e.target.value)} placeholder="Bearer token · leave blank to keep current"/><div className="flex items-center justify-between text-xs"><span>Remove saved token</span><Switch aria-label="Remove saved token" checked={clearToken} onCheckedChange={setClearToken}/></div></>}
        <div className="flex items-center justify-between"><label className="flex items-center gap-2 text-xs">Enabled<Switch aria-label="Connection enabled" checked={enabled} onCheckedChange={setEnabled}/></label><Button size="sm" disabled={busy} type="submit"><Plus className="size-3.5"/>Save connection</Button></div>
        <p className="text-xs text-muted-foreground"><Lock className="mr-1 inline size-3"/>Tokens encrypted · custom hosts blocked pending pinned egress</p>
        {error&&<p role="alert" className="text-xs text-warning">{error}</p>}
      </form>
      <div className="divide-y divide-border">{!rows.length&&<p className="py-3 text-xs text-muted-foreground">No saved connections.</p>}{rows.map(row=><div key={row.id} className="flex min-w-0 items-center justify-between gap-3 py-3"><div className="min-w-0"><p className="text-sm">{row.name}</p><p className="truncate font-mono text-[10px] text-muted-foreground">{row.endpoint}</p><p className="mt-1 text-xs text-muted-foreground">{row.enabled?'Enabled':'Disabled'} · {row.hasToken?'Token saved':'No token'}</p></div><div className="flex shrink-0 gap-1"><Button variant="outline" size="sm" disabled={!row.enabled} onClick={()=>onSelect(row.id,row.endpoint)}>Use</Button><Button variant="ghost" size="icon" aria-label={`Disable ${row.name}`} title="Disable and remove token" onClick={async()=>{try{await disable({data:{id:row.id}});await refresh();}catch{setError('Could not disable connection');}}}><Power className="size-3.5"/></Button></div></div>)}</div>
    </div>
  </section>;
}