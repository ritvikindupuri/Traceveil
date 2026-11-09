import {lazy,Suspense,useEffect,useRef,useState} from 'react';
import {ClientOnly,Link} from '@tanstack/react-router';
import {useServerFn} from '@tanstack/react-start';
import type {User} from '@supabase/supabase-js';
import {Network,Shield,ShieldAlert,Flame,Swords,Wrench,Activity,GitBranch,Globe,ArrowUpRight,ArrowRight,Loader2,Square,Search,X,Download,History,ChevronDown,Lock,Layers,ScanLine,PanelLeftClose,LogOut,Check,RotateCcw,FileUp,FileText,Sparkles} from 'lucide-react';
import {Button} from '@/components/ui/button';
import {Logo} from '@/components/armorix/Logo';
import {AccountDialog} from '@/components/armorix/AccountDialog';
import {supabase} from '@/integrations/supabase/client';
import {listApplicationScans,archiveApplicationScan} from '@/lib/atlas/records.functions';
import type {AttackGraph,ScanRecord} from '@/lib/atlas/types';
import {analyzeDiagramToAttackGraph,synthesizeArchitectureFromPrompt} from '@/lib/atlas/diagram-parser';
import {cn} from '@/lib/utils';
import {TenantIsolation} from './TenantIsolation';
import {GithubCredential} from './GithubCredential';
import {InteractiveAgents} from './InteractiveAgents';
import {InteractiveRemediation} from './InteractiveRemediation';
import {InteractiveDefensePlanner} from './InteractiveDefensePlanner';
import {EvidenceDrawer} from './EvidenceDrawer';
import {DetailedFindings} from './DetailedFindings';
const Canvas=lazy(()=>import('./AttackCanvas').then(m=>({default:m.AttackCanvas})));

const SAMPLE_TEMPLATES: Record<string, { name: string; content: string; filename: string }> = {
  aws: {
    name: 'AWS Cloud (draw.io)',
    filename: 'aws-enterprise-architecture.drawio',
    content: `<mxfile host="app.diagrams.net"><diagram name="AWS Enterprise Cloud" id="d1"><mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/><mxCell id="2" value="Public Internet" style="shape=mxgraph.aws4.internet" vertex="1" parent="1"/><mxCell id="3" value="Cloud API Gateway" style="shape=mxgraph.aws4.api_gateway" vertex="1" parent="1"/><mxCell id="4" value="Orders Microservice (ECS)" style="shape=mxgraph.aws4.ecs" vertex="1" parent="1"/><mxCell id="5" value="PostgreSQL Production Database" style="shape=mxgraph.aws4.rds" vertex="1" parent="1"/><mxCell id="6" value="S3 Customer Documents Bucket" style="shape=mxgraph.aws4.s3" vertex="1" parent="1"/><mxCell id="e1" value="HTTPS Inbound" edge="1" source="2" target="3" parent="1"/><mxCell id="e2" value="gRPC Route" edge="1" source="3" target="4" parent="1"/><mxCell id="e3" value="SQL Query" edge="1" source="4" target="5" parent="1"/><mxCell id="e4" value="Direct Public Fetch" edge="1" source="2" target="6" parent="1"/></root></mxGraphModel></diagram></mxfile>`,
  },
  cisco: {
    name: 'Cisco DMZ Network (Packet Tracer)',
    filename: 'cisco-enterprise-network.pkt',
    content: `<topology name="Cisco Enterprise DMZ & Core Network"><devices><device id="r1" name="Edge-Router-2911" type="router" ip="203.0.113.1"/><device id="sw1" name="Core-Switch-2960" type="switch" ip="192.168.1.2"/><device id="dmz-web" name="DMZ-Web-Server" type="server" ip="192.168.2.10"/><device id="db-core" name="Internal-Finance-DB" type="database" ip="10.0.1.50"/></devices><links><link id="l1" source="r1" target="sw1" interface="Gig0/0"/><link id="l2" source="sw1" target="dmz-web" interface="Fa0/1"/><link id="l3" source="sw1" target="db-core" interface="Fa0/2"/></links></topology>`,
  },
  k8s: {
    name: 'Kubernetes Multi-Tier (draw.io)',
    filename: 'k8s-cluster-architecture.drawio',
    content: `<mxfile host="app.diagrams.net"><diagram name="Kubernetes Multi-Tier Microservices" id="k8s-d1"><mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/><mxCell id="2" value="Public Ingress Traffic" style="shape=mxgraph.k8s.ingress" vertex="1" parent="1"/><mxCell id="3" value="Ingress NGINX Controller" style="shape=mxgraph.k8s.pod" vertex="1" parent="1"/><mxCell id="4" value="Frontend Service" style="shape=mxgraph.k8s.service" vertex="1" parent="1"/><mxCell id="5" value="Internal Payment Microservice" style="shape=mxgraph.k8s.service" vertex="1" parent="1"/><mxCell id="6" value="Customer MySQL Datastore" style="shape=mxgraph.k8s.database" vertex="1" parent="1"/><mxCell id="ke1" value="Public TLS Ingress" edge="1" source="2" target="3" parent="1"/><mxCell id="ke2" value="HTTP Route" edge="1" source="3" target="4" parent="1"/><mxCell id="ke3" value="Unauthenticated Internal Call" edge="1" source="4" target="5" parent="1"/><mxCell id="ke4" value="Database Connection" edge="1" source="5" target="6" parent="1"/></root></mxGraphModel></diagram></mxfile>`,
  },
};
const PROMPT_SUGGESTIONS = [
  {
    label: 'AWS 3-Tier Cloud',
    prompt: 'CloudFront -> ALB -> ECS Fargate -> Postgres RDS in private subnet, plus a public S3 bucket for invoices',
  },
  {
    label: 'Cisco Enterprise DMZ',
    prompt: 'Cisco 2911 router connects WAN to ASA 5505 firewall. Firewall forwards web traffic to DMZ Apache web server on port 443, and internal core switch connects directly to MySQL database and unauthenticated Redis cache.',
  },
  {
    label: 'Kubernetes Microservices',
    prompt: 'Kubernetes cluster with Ingress controller, order-service and auth-service pods, connecting to shared MongoDB and Kafka, with an exposed debug pod running with privileged root container.',
  },
  {
    label: 'Serverless Cloud',
    prompt: 'Route53 DNS -> CloudFront CDN -> API Gateway -> AWS Lambda payment worker -> DynamoDB table and public S3 bucket',
  },
];

const tabs=[{key:'graph',label:'Attack graph',icon:Network},{key:'isolation',label:'Tenant isolation',icon:Lock},{key:'findings',label:'Findings',icon:ShieldAlert},{key:'agents',label:'Agents & Red team',icon:Swords},{key:'remediation',label:'Remediation studio',icon:Wrench},{key:'monitoring',label:'Firewalls & Rules',icon:Shield}];
 export function Workspace(){
 const [user,setUser]=useState<User|null>(null),[account,setAccount]=useState(false),[tab,setTab]=useState('graph'),[mode,setMode]=useState('repo'),[url,setUrl]=useState(''),[consent,setConsent]=useState(true);
 const [architecturePrompt,setArchitecturePrompt]=useState('');
 const [diagramSubTab,setDiagramSubTab]=useState<'ai'|'upload'>('ai');
 const [graph,setGraph]=useState<AttackGraph|null>(null),[reports,setReports]=useState<Record<string,string>>({}),[states,setStates]=useState<Record<string,string>>({}),[running,setRunning]=useState(false),[progress,setProgress]=useState(''),[error,setError]=useState(''),[search,setSearch]=useState(''),[riskOnly,setRiskOnly]=useState(false);
 const [selection,setSelection]=useState<{ids:string[];label:string}|null>(null),[history,setHistory]=useState<ScanRecord[]|null>(null),[sidebar,setSidebar]=useState(false),[saved,setSaved]=useState(false);
 const controller=useRef<AbortController|null>(null);const list=useServerFn(listApplicationScans);const archive=useServerFn(archiveApplicationScan);
 async function clearSession(){controller.current?.abort();if(graph&&user){try{await archive({data:{target:graph.target,commit_sha:graph.commit,graph,reports}});}catch(e){console.warn('Archived scan:',e);}}setGraph(null);setReports({});setStates({});setSelection(null);setUrl('');setProgress('');setError('');setSaved(false);setRiskOnly(false);setSearch('');setTab('graph');}
 useEffect(()=>{void supabase.auth.getUser().then(({data})=>setUser(data.user));const {data}=supabase.auth.onAuthStateChange((event,session)=>{if(['SIGNED_IN','SIGNED_OUT','USER_UPDATED'].includes(event))setUser(session?.user??null);if(event==='SIGNED_OUT'){controller.current?.abort();setGraph(null);setReports({});setHistory(null);setSelection(null);setSaved(false);}});return ()=>{data.subscription.unsubscribe();controller.current?.abort();};},[]);
 async function scan(e:React.FormEvent){e.preventDefault();if(!user){setAccount(true);return;}if(!consent){setError('Please authorize analysis using the checkbox below before scanning.');return;}setRunning(true);setError('');setGraph(null);setSelection(null);setReports({});setStates({});setSaved(false);setTab('graph');const ac=new AbortController();controller.current=ac;
 try{const {data}=await supabase.auth.getSession();if(!data.session)throw new Error('Sign in to scan');const response=await fetch('/api/application-scan',{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${data.session.access_token}`},body:JSON.stringify({url:url.trim(),ref:'',aiConsent:consent}),signal:ac.signal});if(!response.ok||!response.body)throw new Error((await response.json()).error??'Scan unavailable');const reader=response.body.getReader(),decoder=new TextDecoder();let buffer='';for(;;){const chunk=await reader.read();if(chunk.done)break;buffer+=decoder.decode(chunk.value,{stream:true});const lines=buffer.split('\n');buffer=lines.pop()??'';for(const line of lines){if(!line.trim())continue;const event=JSON.parse(line);if(event.type==='progress')setProgress(event.message);if(event.type==='graph')setGraph(event.graph);if(event.type==='record')setSaved(true);if(event.type==='agent'){setStates(s=>({...s,[event.agent]:event.state}));if(event.text)setReports(s=>({...s,[event.agent]:event.text}));}if(event.type==='delta')setReports(s=>({...s,[event.agent]:(s[event.agent]??'')+event.text}));if(event.type==='error')setError(event.message);}}}
 catch(err){if(!ac.signal.aborted)setError(err instanceof Error?err.message:'Scan failed');else setProgress('Stopped');}finally{setRunning(false);}}
  async function loadAndAnalyzeDiagram(content: string, filename: string) {
    if (!consent) {
      setError('Please authorize analysis using the checkbox below before scanning.');
      return;
    }
    setRunning(true);
    setError('');
    setGraph(null);
    setSelection(null);
    setReports({});
    setStates({});
    setSaved(false);
    setTab('graph');
    setProgress('Parsing architecture diagram & network topology...');

    try {
      const result = analyzeDiagramToAttackGraph(content, filename);
      setGraph(result.graph);
      setProgress('AI Agents analyzing architecture topology...');

      if (user) {
        try {
          await supabase.from('application_scans').insert({
            user_id: user.id,
            target: result.graph.target,
            commit_sha: result.graph.commit,
            status: 'complete',
            graph: JSON.parse(JSON.stringify(result.graph)),
          });
          setSaved(true);
        } catch {
          // Graceful history persistence
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to parse diagram');
    } finally {
      setRunning(false);
    }
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === 'string' ? reader.result : '';
      if (text) {
        void loadAndAnalyzeDiagram(text, file.name);
      }
    };
    reader.readAsText(file);
  }

  function handleSynthesizeArchitecture(overridePrompt?: string) {
    const promptToRun = (overridePrompt ?? architecturePrompt).trim();
    if (!promptToRun) return;
    if (!consent) {
      setError('Please authorize analysis using the checkbox below before scanning.');
      return;
    }
    setRunning(true);
    setError('');
    setProgress('AI Agent synthesizing draw.io topology from architecture description...');
    try {
      const xml = synthesizeArchitectureFromPrompt(promptToRun);
      void loadAndAnalyzeDiagram(xml, 'ai-synthesized-architecture.drawio');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to synthesize architecture');
      setRunning(false);
    }
  }

 function exportGraph(){if(!graph)return;const blob=new Blob([JSON.stringify({graph,reports},null,2)],{type:'application/json'}),link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download=`traceveil-${graph.commit.slice(0,8)}.json`;link.click();URL.revokeObjectURL(link.href);}
 async function openHistory(){try{setHistory(await list() as unknown as ScanRecord[]);}catch{setError('Could not load scan history');}}
 return <div className="atlas-shell"><aside className={cn('atlas-sidebar',sidebar&&'atlas-sidebar-open')}><Link to="/" className="flex items-center gap-3 px-5 pt-6 pb-4"><Logo className="size-8"/><span className="text-lg font-semibold">Traceveil</span></Link><nav className="space-y-1 px-3">{tabs.map(t=><Button key={t.key} variant="ghost" className={cn('h-10 w-full justify-start gap-3 text-xs',tab===t.key&&'bg-accent text-primary')} onClick={()=>{setTab(t.key);setSidebar(false);}}><t.icon className="size-4"/>{t.label}{t.key==='findings'&&graph&&<span className="ml-auto font-mono">{graph.findings.length}</span>}</Button>)}</nav><div className="mt-auto border-t border-border p-3"><Button variant="ghost" className="w-full justify-start text-xs" onClick={()=>user?void openHistory():setAccount(true)}><History className="size-4"/>Scan history</Button><Button asChild variant="ghost" className="w-full justify-start text-xs text-muted-foreground"><Link to="/mcp-audits"><Layers className="size-4"/>MCP audits <ArrowUpRight className="ml-auto size-3"/></Link></Button><div className="mt-4 flex items-center justify-between px-2"><span className="text-xs text-muted-foreground">{user?'Private workspace':'Your workspace'}</span>{user?<Button variant="ghost" size="icon" aria-label="Sign out" title="Sign out" onClick={()=>void supabase.auth.signOut()}><LogOut className="size-4"/></Button>:<Button variant="outline" size="sm" onClick={()=>setAccount(true)}>Sign in</Button>}</div></div></aside>
 <main className="atlas-main"><header className="flex h-16 shrink-0 items-center justify-between gap-3 border-b border-border px-5"><div className="flex min-w-0 items-center gap-3"><Button variant="ghost" size="icon" className="lg:hidden" aria-label="Toggle navigation" onClick={()=>setSidebar(v=>!v)}><PanelLeftClose className="size-4"/></Button><span className="text-xs text-muted-foreground">Workspace</span><span className="text-muted-foreground">/</span><h1 className="truncate text-sm font-medium">{tabs.find(t=>t.key===tab)?.label}</h1></div><div className="flex items-center gap-2">{graph&&<Button variant="outline" size="sm" onClick={clearSession} className="gap-1.5 text-xs text-muted-foreground hover:text-foreground" title="Archive session to history and start fresh"><RotateCcw className="size-3.5"/><span>Clear session</span></Button>}<GithubCredential key={user?.id??"signed-out"} signedIn={Boolean(user)} onSignIn={()=>setAccount(true)}/>{saved&&<span className="hidden items-center gap-1 text-[10px] text-primary sm:flex"><Check className="size-3"/>Saved</span>}<Button variant="ghost" size="icon" aria-label="Export evidence" title="Export evidence" disabled={!graph} onClick={exportGraph}><Download className="size-4"/></Button></div></header>
  <section className="shrink-0 border-b border-border px-5 py-4"><div className="mb-3 flex items-center justify-between"><div className="flex gap-1"><Button variant={mode==='repo'?'secondary':'ghost'} size="sm" onClick={()=>setMode('repo')}><GitBranch className="size-3.5"/>Repository</Button><Button variant={mode==='app'?'secondary':'ghost'} size="sm" onClick={()=>setMode('app')}><Globe className="size-3.5"/>Live application</Button><Button variant={mode==='diagram'?'secondary':'ghost'} size="sm" onClick={()=>setMode('diagram')}><Layers className="size-3.5"/>Architecture / Diagram</Button></div>{graph&&<div className="flex items-center gap-2"><span className="hidden font-mono text-[10px] text-muted-foreground sm:block">{graph.commit.slice(0,8)} · {graph.branch}</span><Button variant="ghost" size="sm" onClick={clearSession} className="h-7 gap-1.5 px-2 text-[11px] text-muted-foreground hover:text-foreground"><RotateCcw className="size-3"/><span>New scan</span></Button></div>}</div>{mode==='diagram'?(<div className="space-y-3"><div className="flex items-center gap-1 rounded-md border border-border/70 bg-muted/40 p-1 w-fit"><Button type="button" variant={diagramSubTab==='ai'?'secondary':'ghost'} size="sm" onClick={()=>setDiagramSubTab('ai')} className={cn('h-8 gap-1.5 text-xs font-medium',diagramSubTab==='ai'&&'bg-background shadow-xs')}><Sparkles className="size-3.5 text-primary"/><span>Describe Architecture with AI</span></Button><Button type="button" variant={diagramSubTab==='upload'?'secondary':'ghost'} size="sm" onClick={()=>setDiagramSubTab('upload')} className={cn('h-8 gap-1.5 text-xs font-medium',diagramSubTab==='upload'&&'bg-background shadow-xs')}><FileUp className="size-3.5 text-primary"/><span>Upload Diagram File</span></Button></div>{diagramSubTab==='ai'?(<div className="rounded-lg border border-border/80 bg-card p-3.5 shadow-xs"><div className="mb-2 flex items-center justify-between"><div className="flex items-center gap-2"><Sparkles className="size-4 text-primary animate-pulse"/><span className="text-xs font-semibold">AI Conversational Architecture Studio</span><span className="rounded-full bg-primary/10 px-2 py-0.5 font-mono text-[9px] font-medium text-primary">Natural Language &rarr; Topology</span></div><span className="text-[10px] text-muted-foreground">Generates full architecture in seconds</span></div><div className="flex gap-2"><input aria-label="Describe architecture" type="text" value={architecturePrompt} onChange={e=>setArchitecturePrompt(e.target.value)} onKeyDown={e=>{if(e.key==='Enter'){e.preventDefault();handleSynthesizeArchitecture();}}} placeholder="e.g. CloudFront -> ALB -> ECS Fargate -> Postgres RDS in private subnet, plus a public S3 bucket for invoices" className="h-10 min-w-0 flex-1 rounded border border-input bg-background px-3 font-mono text-xs outline-none focus:ring-1 focus:ring-ring"/><Button type="button" disabled={!architecturePrompt.trim()||running} onClick={()=>handleSynthesizeArchitecture()} className="h-10 gap-1.5 px-4 text-xs font-medium"><Sparkles className="size-3.5"/><span>Synthesize & Analyze</span></Button></div><div className="mt-2.5 flex flex-wrap items-center gap-1.5"><span className="text-[10px] text-muted-foreground">Quick inspiration:</span>{PROMPT_SUGGESTIONS.map(s=><button key={s.label} type="button" onClick={()=>{setArchitecturePrompt(s.prompt);handleSynthesizeArchitecture(s.prompt);}} className="rounded border border-border/60 bg-muted/40 px-2 py-1 text-[10px] text-muted-foreground transition hover:border-primary/50 hover:bg-accent/40 hover:text-foreground">{s.label}</button>)}</div></div>):(<div className="rounded-lg border border-border/80 bg-card p-3.5 shadow-xs space-y-3"><div className="flex flex-wrap items-center gap-3"><label className="flex h-10 cursor-pointer items-center gap-2 rounded border border-dashed border-input bg-background px-4 font-mono text-xs hover:border-primary/50 hover:bg-accent/40"><FileUp className="size-4 text-primary"/><span>Upload diagram (.drawio, .xml, .pkt, .pka, .cfg)</span><input type="file" accept=".drawio,.xml,.pkt,.pka,.cfg,.conf,.ios,.txt" className="hidden" onChange={handleFileUpload}/></label><span className="text-xs text-muted-foreground">Accepts draw.io XML, Cisco Packet Tracer (.pkt/.pka), and Cisco IOS configs (.cfg)</span></div><div className="pt-2 flex flex-wrap items-center gap-2 border-t border-border/50"><span className="text-[11px] text-muted-foreground">or test with realistic sample:</span>{Object.entries(SAMPLE_TEMPLATES).map(([key,t])=><Button key={key} type="button" variant="outline" size="sm" className="h-8 text-[11px] gap-1.5" onClick={()=>void loadAndAnalyzeDiagram(t.content,t.filename)}><Layers className="size-3 text-primary"/>{t.name}</Button>)}</div></div>)}</div>):(<form onSubmit={scan} className="flex flex-wrap gap-2"><input aria-label="Target URL" type="url" required placeholder={mode==='repo'?'https://github.com/owner/repository':'https://your-application.com'} value={url} onChange={e=>{const val=e.target.value;setUrl(val);if(val.includes('github.com')&&mode!=='repo')setMode('repo');else if(val.startsWith('http')&&!val.includes('github.com')&&mode!=='app')setMode('app');}} className="h-10 min-w-0 flex-1 rounded border border-input bg-card px-3 font-mono text-xs outline-none focus:ring-1 focus:ring-ring"/>{running?<Button type="button" variant="secondary" onClick={()=>controller.current?.abort()}><Square className="size-3"/>Stop</Button>:<Button type="submit" disabled={!url||!consent}><ScanLine className="size-4"/>Scan <ArrowRight className="size-3"/></Button>}</form>)}<label className="mt-3 flex items-start gap-2 text-[10px] text-muted-foreground"><input type="checkbox" checked={consent} onChange={e=>setConsent(e.target.checked)} className="mt-0.5 accent-primary"/>I authorize read-only analysis and AI processing of collected, redacted evidence.</label></section>
 {error&&<div role="alert" className="shrink-0 border-b border-destructive/30 bg-destructive/10 px-5 py-3 text-xs text-destructive">{error}</div>}
 {running&&<div role="status" className="flex shrink-0 items-center gap-2 border-b border-border px-5 py-2 font-mono text-[10px] text-primary"><Loader2 className="size-3 animate-spin"/>{graph?'Agents analyzing collected evidence':progress}</div>}
 {tab==='isolation'&&<TenantIsolation signedIn={Boolean(user)} onSignIn={()=>setAccount(true)} target={graph?.target || url} graph={graph}/>}
 {tab==='graph'&&<><div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-border px-5 py-3"><div className="flex items-center gap-4 text-[10px] text-muted-foreground"><span>{graph?`${graph.nodes.length} entities`:'No target scanned'}</span>{graph&&<span>{graph.edges.length} relationships</span>}</div><div className="flex items-center gap-2"><div className="relative"><Search className="absolute left-2 top-2.5 size-3 text-muted-foreground"/><input aria-label="Search graph" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Find an entity" className="h-8 w-36 rounded border border-input bg-background pl-7 pr-2 text-[11px] outline-none"/></div><Button variant={riskOnly?'destructive':'outline'} size="sm" aria-pressed={riskOnly} onClick={()=>{const next=!riskOnly;setRiskOnly(next);if(next&&graph){const p=graph.attackPaths?.[0];const s=p?.steps?.[0];if(s&&s.evidenceIds?.length){setSelection({ids:s.evidenceIds,label:s.title});}else if(graph.findings?.length){setSelection({ids:graph.findings[0].evidenceIds,label:graph.findings[0].title});}}}} className={cn('gap-1.5 text-xs font-medium',riskOnly&&'shadow-sm')}><Flame className={cn('size-3.5',riskOnly?'text-white animate-pulse':'text-destructive')}/><span>Attack paths</span>{graph&&<span className={cn('rounded-full px-1.5 py-0.2 font-mono text-[9px] font-bold',riskOnly?'bg-white/20 text-white':'bg-destructive/15 text-destructive')}>{graph.attackPaths?.length||graph.findings.length}</span>}</Button></div></div><div className="atlas-investigation"><div className="atlas-canvas">{graph?<ClientOnly fallback={<div className="atlas-empty"><Loader2 className="size-5 animate-spin"/></div>}><Suspense fallback={<div className="atlas-empty"><Loader2 className="size-5 animate-spin"/></div>}><Canvas graph={graph} search={search} riskOnly={riskOnly} onSelect={(ids,label)=>setSelection({ids,label})}/></Suspense></ClientOnly>:<div className="atlas-empty"><div className="atlas-empty-emblem"><Logo className="size-12"/></div><h2 className="mt-5 text-xl font-medium">Your attack surface, connected.</h2><p className="mt-2 text-xs text-muted-foreground">No scan evidence yet.</p><div className="mt-7 flex items-center gap-4 text-muted-foreground"><GitBranch className="size-5"/><ArrowRight className="size-3"/><Network className="size-5"/><ArrowRight className="size-3"/><ShieldAlert className="size-5"/></div></div>}<div className="absolute bottom-3 left-4 z-10 flex flex-wrap items-center gap-3.5 rounded-md border border-border/70 bg-card/90 px-3 py-1.5 text-[11px] text-muted-foreground shadow-xs backdrop-blur-xs select-none"><div className="flex items-center gap-1.5"><span className="h-0.5 w-3.5 rounded-full bg-muted-foreground/60"/><span>Declared</span></div><div className="flex items-center gap-1.5"><span className="h-0.5 w-3.5 rounded-full bg-warning"/><span>Risk condition</span></div>{riskOnly&&<div className="flex items-center gap-1.5 text-destructive font-medium"><span className="h-0.5 w-3.5 rounded-full bg-destructive animate-pulse"/><span>Attack path</span></div>}</div></div>{selection&&graph&&<EvidenceDrawer selection={selection} graph={graph} onClose={()=>setSelection(null)} onNavigateToRemediation={()=>setTab('remediation')} />}</div></>}
 {tab==='findings'&&<section className="atlas-content">{graph?<DetailedFindings graph={graph} onNavigateToRemediation={()=>setTab('remediation')}/>:<Empty text="No findings collected. Scan a repository to view evidence-backed findings."/>}</section>}
 {tab==='agents'&&<section className="atlas-content"><h2 className="mb-6 text-lg font-medium">Autonomous Security Agents</h2>{graph?<InteractiveAgents graph={graph} reports={reports} onNavigateToRemediation={()=>setTab('remediation')} />:<Empty text="No scan evidence yet. Scan a repository to launch autonomous security agents." />}</section>}
 {tab==='remediation'&&<section className="atlas-content">{graph?<InteractiveRemediation graph={graph} />:<Empty text="No remediation analysis recorded. Scan a repository to generate code patches." />}</section>}
 {tab==='monitoring'&&<section className="atlas-content">{graph?<InteractiveDefensePlanner graph={graph} />:<Empty text="No protection rules generated yet. Scan an application or repository to view tailored firewall and guardrail policies." />}</section>}
 {graph&&<details className="atlas-coverage"><summary className="flex cursor-pointer list-none items-center gap-2"><Layers className="size-3"/><span>{graph.coverage.inspected} / {graph.coverage.total} files inspected</span><span className="ml-auto">Coverage gaps · {graph.coverage.gaps.length}</span><ChevronDown className="size-3"/></summary><ul className="mt-3 space-y-2">{graph.coverage.gaps.map(g=><li key={g}>{g}</li>)}</ul></details>}
 </main><AccountDialog open={account} onOpenChange={setAccount}/>{history!==null&&<div className="fixed inset-0 z-50 flex justify-end bg-background/80 backdrop-blur-sm"><section className="w-full max-w-md overflow-auto border-l border-border bg-card p-5"><div className="mb-5 flex items-center justify-between"><h2 className="text-sm font-medium">Scan history</h2><Button variant="ghost" size="icon" aria-label="Close history" onClick={()=>setHistory(null)}><X className="size-4"/></Button></div><Button variant="outline" size="sm" className="mb-4 w-full gap-2 text-xs" onClick={()=>{void clearSession();setHistory(null);}}><RotateCcw className="size-3.5"/>Start new scan (Clear active session)</Button>{history.length===0?<Empty text="No saved application scans."/>:history.map(r=><Button key={r.id} variant="ghost" className="mb-2 h-auto w-full justify-start py-3 text-left" onClick={()=>{setGraph(r.graph);setReports(r.reports);setStates({});setSaved(true);setSelection(null);setTab('graph');setHistory(null);}}><GitBranch className="size-4 shrink-0"/><span className="min-w-0"><span className="block truncate text-xs">{r.target.replace('https://github.com/','')}</span><span className="mt-1 block font-mono text-[9px] text-muted-foreground">{r.commit_sha.slice(0,8)} · {new Date(r.created_at).toLocaleString()}</span></span></Button>)}</section></div>}</div>;
}
function Empty({text}:{text:string}){return <div className="flex min-h-40 items-center justify-center text-xs text-muted-foreground">{text}</div>;}
