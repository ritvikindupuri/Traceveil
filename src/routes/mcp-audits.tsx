import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, Loader2, Square, Check, Circle, History, LogOut, Download, X,Server, ChevronDown, SlidersHorizontal } from "lucide-react";
import {useServerFn} from '@tanstack/react-start';
import {useQueryClient} from '@tanstack/react-query';
import {supabase} from '@/integrations/supabase/client';
import type {User} from '@supabase/supabase-js';
import {AccountDialog} from '@/components/armorix/AccountDialog';
import {EnforcementPanel} from '@/components/armorix/EnforcementPanel';
import {ConnectionsPanel} from '@/components/armorix/ConnectionsPanel';
import {PolicyBuilder} from '@/components/armorix/PolicyBuilder';
import {listAudits} from '@/lib/scan/records.functions';
import { Logo } from "@/components/armorix/Logo";
import { AuditVisuals } from "@/components/armorix/AuditVisuals";
import { Button } from "@/components/ui/button";
import type { Inventory, Mode, Sev, Signal, Verdict } from "@/lib/scan/types";
import { cn } from "@/lib/utils";
import { trustedDestination } from '@/lib/scan/destinations';

export const Route = createFileRoute("/mcp-audits")({
  head: () => ({
    meta: [
      { title: "MCP audits — Traceveil" },
      { name: "description", content: "Audit MCP tool definitions, live MCP servers and agent transcripts for prompt injection, tool poisoning and exfiltration." },
      { property: "og:title", content: "MCP audits — Traceveil" },
      { property: "og:description", content: "Agentic audits of MCP servers and agent transcripts for injection, poisoning and exfiltration." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Index,
});

type Stage = "idle" | "collect" | "agents" | "verdict" | "done" | "error";
type AgentState = { text: string; done: boolean; declined?: boolean } | undefined;

const sevClass: Record<Sev, string> = {
  critical: "text-destructive bg-destructive/10 border-destructive/30",
  high: "text-warning bg-warning/10 border-warning/30",
  medium: "text-foreground bg-secondary border-border",
  low: "text-muted-foreground bg-muted border-border",
};
const MODES: { k: Mode; l: string; ph: string }[] = [
  { k: "definitions", l: "Tool definitions", ph: "Paste tools/list JSON or YAML" },
  { k: "endpoint", l: "MCP endpoint", ph: "https://mcp.example.com/mcp" },
  { k: "transcript", l: "Agent transcript", ph: "Paste agent session log / transcript" },
];
const AGENTS = [
  { k: "semantic", l: "Semantic risk" },
  { k: "fuzz", l: "Adversarial fuzzing" },
  { k: "blast", l: "Blast radius" },
];

function Index() {
  const [user,setUser] = useState<User|null>(null);
  const [accountOpen,setAccountOpen] = useState(false);
  const [historyOpen,setHistoryOpen] = useState(false);
  const [connectionsOpen,setConnectionsOpen]=useState(false);
  const [policyOpen,setPolicyOpen]=useState(false);
  const [policyEpoch,setPolicyEpoch]=useState(0);
  const [connectionId,setConnectionId]=useState<string|undefined>();
  const [records,setRecords] = useState<Awaited<ReturnType<typeof listAudits>>>([]);
  const [record,setRecord] = useState<{id:string;fingerprint:string;changed:boolean|null;endpoint:string|null}|null>(null);
  const list = useServerFn(listAudits);
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<Mode>("definitions");
  const [input, setInput] = useState("");
  const [token, setToken] = useState("");
  const [stage, setStage] = useState<Stage>("idle");
  const [inv, setInv] = useState<Inventory | null>(null);
  const [signals, setSignals] = useState<Signal[]>([]);
  const [agents, setAgents] = useState<Record<string, AgentState>>({});
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [error, setError] = useState<string | null>(null);
  const ctrl = useRef<AbortController | null>(null);
  const running = stage === "collect" || stage === "agents" || stage === "verdict";
  const started = stage !== "idle" || inv !== null;
  useEffect(()=>{
    void supabase.auth.getUser().then(({data})=>setUser(data.user));
    const {data} = supabase.auth.onAuthStateChange((event,session)=>{
      if (event === 'SIGNED_IN' || event === 'SIGNED_OUT' || event === 'USER_UPDATED') setUser(session?.user ?? null);
      if (event === 'SIGNED_OUT') {ctrl.current?.abort();setRecords([]);setRecord(null);setInv(null);setVerdict(null);setSignals([]);setAgents({});setStage('idle');setHistoryOpen(false);setToken('');setInput('');setConnectionId(undefined);setConnectionsOpen(false);}
    });
    return ()=>data.subscription.unsubscribe();
  },[]);

  async function history() {setHistoryOpen(true);try {setRecords(await list());} catch {setError('Could not load audit records');}}
  async function signOut() {ctrl.current?.abort();await queryClient.cancelQueries();queryClient.clear();await supabase.auth.signOut();}
  function openRecord(r:Awaited<ReturnType<typeof listAudits>>[number]) {
    setToken('');setConnectionId(undefined);
    ctrl.current?.abort();setInv(r.inventory as unknown as Inventory);setSignals(r.signals as unknown as Signal[]);setVerdict(r.verdict as unknown as Verdict);
    const reports = r.reports as Record<string,string>;
    setAgents(Object.fromEntries(Object.entries(reports).map(([k,text])=>[k,{text,done:true,declined:text === '(agent returned no output)'}])));
    setRecord({id:r.id,fingerprint:r.fingerprint,changed:null,endpoint:r.endpoint});setStage('done');setError(null);setHistoryOpen(false);
  }
  function download() {
    if (!record || !inv || !verdict) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify({record,inventory:inv,signals,verdict,agents},null,2)],{type:'application/json'}));
    const anchor = document.createElement('a');anchor.href=url;anchor.download=`traceveil-audit-${record.id}.json`;anchor.click();URL.revokeObjectURL(url);
  }

  async function scan(e?: React.FormEvent) {
    e?.preventDefault();
    if (!input.trim() || running) return;
    if (!user) {setAccountOpen(true);return;}
    if (mode === 'endpoint') {
      try {
        const raw = input.trim();
        new URL(raw.startsWith('http://') || raw.startsWith('https://') ? raw : `https://${raw}`);
      } catch {
        setError('Enter a valid MCP endpoint URL (e.g. https://mcp.deepwiki.com/mcp or http://localhost:8000/sse).');
        setStage('error');
        return;
      }
    }
    setRecord(null);setInv(null); setSignals([]); setAgents({}); setVerdict(null); setError(null); setStage("collect");
    const ac = new AbortController();
    ctrl.current = ac;
    try {
      const {data} = await supabase.auth.getSession();
      if (!data.session) throw new Error('Sign in to audit');
      const res = await fetch("/api/scan", { method: "POST", headers: { "content-type": "application/json", authorization:`Bearer ${data.session.access_token}` }, body: JSON.stringify({ mode, input, token: mode === "endpoint" && !connectionId ? token : undefined,connectionId:mode==='endpoint'?connectionId:undefined }), signal: ac.signal });
      if (!res.ok || !res.body) throw new Error((await res.json().catch(() => null))?.error ?? `Request failed (${res.status})`);
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const l of lines) if (l.trim()) handle(JSON.parse(l));
      }
    } catch (err: any) {
      if (err?.name === "AbortError") { setStage("idle"); return; }
      setError(err?.message ?? "Scan failed"); setStage("error");
    }
  }

  function handle(ev: any) {
    switch (ev.type) {
      case "stage": setStage(ev.stage); break;
      case "evidence": setInv(ev.inventory); setSignals(ev.signals); break;
      case "agent:start": setAgents((a) => ({ ...a, [ev.agent]: { text: "", done: false } })); break;
      case "agent:delta": setAgents((a) => ({ ...a, [ev.agent]: { text: (a[ev.agent]?.text ?? "") + ev.text, done: false } })); break;
      case "agent:end": setAgents((a) => ({ ...a, [ev.agent]: { text: a[ev.agent]?.text ?? "", done: true, declined: Boolean(ev.declined) } })); break;
      case "verdict": setVerdict(ev); break;
      case 'record': setRecord({id:ev.id,fingerprint:ev.fingerprint,changed:ev.changed,endpoint:mode === 'endpoint'?input:null}); break;
      case "done": setStage("done"); break;
      case "error": setError(ev.message); setStage("error"); break;
    }
  }

  const ph = MODES.find((m) => m.k === mode)?.ph ?? "";

  return (
    <div className="min-h-screen">
      <header className="flex min-h-14 flex-wrap items-center justify-between gap-2 border-b border-border px-5 py-2">
        <div className="flex items-center gap-2.5">
          <Button variant="ghost" size="icon" asChild><Link to="/console" aria-label="Back to Traceveil workspace" title="Back to workspace"><ArrowLeft className="size-4"/></Link></Button>
          <Logo />
          <span className="text-[15px] font-semibold">Traceveil</span>
          <span className="ml-1 rounded border border-border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">agent guardrails</span>
        </div>
        <div className="flex items-center gap-1">
          {user ? <><Button variant="ghost" size="sm" onClick={()=>setPolicyOpen(v=>!v)}><SlidersHorizontal className="size-3.5"/>Policy</Button><Button variant="ghost" size="sm" onClick={()=>setConnectionsOpen(v=>!v)}><Server className="size-3.5"/>Connections</Button><Button variant="ghost" size="sm" onClick={history}><History className="size-3.5"/>Audit history</Button><Button variant="ghost" size="icon" aria-label="Sign out" title="Sign out" onClick={signOut}><LogOut className="size-4"/></Button></>:<Button variant="outline" size="sm" onClick={()=>setAccountOpen(true)}>Sign in</Button>}
        </div>
      </header>
      <AccountDialog open={accountOpen} onOpenChange={setAccountOpen}/>
      {user&&policyOpen&&<PolicyBuilder key={user.id} onClose={()=>setPolicyOpen(false)} onSaved={()=>setPolicyEpoch(v=>v+1)} endpoint={record?.endpoint??null} verdict={verdict}/>}
      {user&&connectionsOpen&&<ConnectionsPanel onClose={()=>setConnectionsOpen(false)} onSelect={(id,endpoint)=>{if(running)return;setConnectionId(id);setInput(endpoint);setToken('');setMode('endpoint');setConnectionsOpen(false);}}/>}
      {historyOpen && <section className="mx-auto max-w-[1400px] border-b border-border px-5 py-4"><div className="mb-3 flex items-center justify-between"><h2 className="text-sm font-medium">Audit history</h2><Button variant="ghost" size="icon" aria-label="Close history" onClick={()=>setHistoryOpen(false)}><X/></Button></div>{records.length === 0?<p className="text-xs text-muted-foreground">No saved audits.</p>:<div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">{records.map(r=><Button key={r.id} variant="outline" className="h-auto justify-between gap-3 py-3 text-left" onClick={()=>openRecord(r)}><span className="min-w-0 truncate text-xs">{r.source}</span><span className="shrink-0 font-mono text-[10px] text-muted-foreground">{new Date(r.created_at).toLocaleString()}</span></Button>)}</div>}</section>}

      <main className="mx-auto grid max-w-[1400px] grid-cols-[minmax(0,1fr)] gap-4 p-5 lg:grid-cols-[420px_minmax(0,1fr)]">
        <form onSubmit={scan} className="flex h-fit min-w-0 flex-col rounded-lg border border-border bg-card lg:sticky lg:top-5">
          <div className="flex border-b border-border">
            {MODES.map((m) => (
              <Button variant="ghost" key={m.k} type="button" onClick={() => {setMode(m.k);setToken('');setConnectionId(undefined);}} disabled={running}
                className={cn("h-10 flex-1 rounded-none border-b-2 px-2 text-xs", mode === m.k ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground")}>
                {m.l}
              </Button>
            ))}
          </div>
          {mode === "endpoint" ? (
            <div className="space-y-2 p-3">
              <input aria-label="MCP endpoint URL" value={input} onChange={(e) => {setInput(e.target.value);if(connectionId)setConnectionId(undefined);}} placeholder={ph} spellCheck={false}
                className="h-9 w-full rounded-md border border-input bg-background px-3 font-mono text-xs outline-none focus:ring-2 focus:ring-ring" />
              <input aria-label="Bearer token" disabled={Boolean(connectionId)} value={token} onChange={(e) => setToken(e.target.value)} placeholder={connectionId?'Saved connection · token held server-side':'Bearer token (optional, not stored)'} type="password"
                className={cn("h-9 w-full rounded-md border border-input bg-background px-3 font-mono text-xs outline-none focus:ring-2 focus:ring-ring", (error?.includes('401') || error?.toLowerCase().includes('bearer')) ? "border-warning/80 ring-1 ring-warning/60 bg-warning/5" : "")} />
              <div className="pt-1.5">
                <span className="block text-[10px] text-muted-foreground mb-1.5">Quick-test endpoints:</span>
                <div className="flex flex-wrap gap-1.5">
                  <button type="button" onClick={() => { setInput('https://docs.mcp.cloudflare.com/mcp'); setError(null); }} className="rounded border border-border/70 bg-muted/30 px-2 py-1 text-[10px] text-muted-foreground transition hover:border-primary/50 hover:bg-accent/40 hover:text-foreground">
                    Cloudflare Docs (Public)
                  </button>
                  <button type="button" onClick={() => { setInput('https://learn.microsoft.com/api/mcp'); setError(null); }} className="rounded border border-border/70 bg-muted/30 px-2 py-1 text-[10px] text-muted-foreground transition hover:border-primary/50 hover:bg-accent/40 hover:text-foreground">
                    Microsoft Learn (Public)
                  </button>
                  <button type="button" onClick={() => { setInput('https://mcp.scrapewise.ai/mcp'); setError(null); }} className="rounded border border-border/70 bg-muted/30 px-2 py-1 text-[10px] text-muted-foreground transition hover:border-primary/50 hover:bg-accent/40 hover:text-foreground">
                    Scrapewise AI (Auth Required)
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <textarea aria-label="Input" value={input} onChange={(e) => setInput(e.target.value)} placeholder={ph} spellCheck={false}
              className="h-[min(60vh,520px)] resize-none bg-transparent p-3 font-mono text-xs leading-relaxed outline-none placeholder:text-muted-foreground/60" />
          )}
          <div className="flex items-center justify-between border-t border-border p-2.5">
            <span className="pl-1 font-mono text-[10px] text-muted-foreground">{input.length ? `${input.length.toLocaleString()} chars` : ""}</span>
            {running ? (
              <Button variant="secondary" size="sm" type="button" onClick={() => ctrl.current?.abort()}>
                <Square className="h-3 w-3" /> Stop
              </Button>
            ) : (
              <Button size="sm" type="submit" disabled={!input.trim()}>
                Audit <ArrowRight className="h-3 w-3" />
              </Button>
            )}
          </div>
        </form>

        <div className="min-w-0 space-y-4">
          {!started && (
            <div className="flex h-[min(60vh,560px)] flex-col items-center justify-center rounded-lg border border-dashed border-border text-center">
              <Logo className="h-10 w-10 opacity-80" />
              <div className="mt-4 text-lg font-medium tracking-tight">Audit tools before agents trust them.</div>
              <div className="mt-1 text-xs text-muted-foreground">Poisoning · injection · shadowing · escalation · exfiltration</div>
            </div>
          )}
          {started && <Pipeline stage={stage} inv={inv} />}
          {error && (
            <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-xs text-destructive space-y-2.5">
              <div className="flex items-start gap-2">
                <span className="font-semibold text-sm leading-snug">{error}</span>
              </div>
              {error.includes('401') && (
                <div className="rounded border border-warning/40 bg-warning/10 p-2.5 text-[11px] text-warning flex flex-wrap items-center justify-between gap-2">
                  <span>This server requires authentication. Enter your API key above, or test a public unauthenticated endpoint:</span>
                  <Button
                    size="sm"
                    variant="outline"
                    type="button"
                    className="h-7 text-[11px] gap-1.5 border-warning/40 hover:bg-warning/20 hover:text-warning"
                    onClick={() => {
                      setInput('https://docs.mcp.cloudflare.com/mcp');
                      setError(null);
                      setStage('idle');
                    }}
                  >
                    Test with Cloudflare Docs MCP (Public)
                  </Button>
                </div>
              )}
            </div>
          )}
          {inv && <AuditVisuals key={`${inv.source}-${inv.mode}`} inventory={inv} signals={signals} verdict={verdict} />}
          {verdict && <VerdictCard v={verdict} />}
          {record && <div className="min-w-0 border-y border-border py-2"><div className="flex flex-wrap items-center justify-between gap-2"><span className={cn('text-xs',record.changed?'text-warning':'text-muted-foreground')} title={`SHA-256 · ${record.fingerprint}`}>{record.changed === null?'Baseline recorded':record.changed?'Tool definitions changed':'Baseline unchanged'} · Saved</span><Button variant="ghost" size="icon" aria-label="Download audit record" title="Download audit record" onClick={download}><Download className="size-4"/></Button></div><EnforcementPanel key={`${record.id}-${policyEpoch}`} id={record.id} endpoint={record.endpoint} token={token}/></div>}
          {started && (
            <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-3">
              {AGENTS.map((a) => <AgentPanel key={a.k} name={a.l} state={agents[a.k]} />)}
            </div>
          )}
          {inv && <details className="group border-t border-border"><summary className="flex cursor-pointer list-none items-center justify-between py-3 text-xs text-muted-foreground">Static evidence · {signals.length}<ChevronDown className="size-3.5 transition-transform group-open:rotate-180"/></summary><SignalTable signals={signals} /></details>}
        </div>
      </main>
    </div>
  );
}

function Pipeline({ stage, inv }: { stage: Stage; inv: Inventory | null }) {
  const steps = ["Ingest", "Analyze", "Decide"];
  const order = ["collect", "agents", "verdict", "done"];
  const cur = order.indexOf(stage);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card px-4 py-3">
      <div className="flex min-w-0 items-center gap-4 font-mono text-xs">
        <span className="truncate">{inv?.server ?? inv?.source ?? "…"}</span>
        {inv && <span className="text-muted-foreground">{inv.tools.length} tools{inv.transcriptChars ? ` · ${inv.transcriptChars.toLocaleString()} chars` : ""}</span>}
      </div>
      <div className="flex items-center gap-5">
        {steps.map((s, i) => {
          const done = cur > i || stage === "done";
          const active = cur === i;
          return (
            <div key={s} className={cn("flex items-center gap-1.5 text-xs", done ? "text-foreground" : active ? "text-primary" : "text-muted-foreground")}>
              {done ? <Check className="h-3.5 w-3.5 text-primary" /> : active && stage !== "error" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Circle className="h-3 w-3" />}
              {s}
            </div>
          );
        })}
      </div>
    </div>
  );
}

const riskBar = (r: number) => (r >= 70 ? "bg-destructive" : r >= 40 ? "bg-warning" : "bg-success");

function VerdictCard({ v }: { v: Verdict }) {
  const tone = v.verdict === "block" ? "text-destructive" : v.verdict === "review" ? "text-warning" : "text-success";
  return (
    <section className="min-w-0 border-y border-border">
      <div className="flex flex-wrap items-center gap-6 border-b border-border p-4">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Verdict</div>
          <div className={cn("text-2xl font-semibold uppercase tracking-tight", tone)}>{v.verdict}</div>
        </div>
        <div className="w-36">
          <div className="flex justify-between font-mono text-[10px] uppercase tracking-wider text-muted-foreground"><span>Risk</span><span>{v.risk}</span></div>
          <div className="mt-2 h-1.5 rounded-full bg-muted"><div className={cn("h-full rounded-full", riskBar(v.risk))} style={{ width: `${Math.min(100, Math.max(0, v.risk))}%` }} /></div>
        </div>
        <div className="ml-auto text-right"><div className="font-mono text-xl">{v.findings?.length ?? 0}</div><div className="text-[10px] text-muted-foreground">Findings</div></div>
      </div>
      <details className="group border-b border-border"><summary className="flex cursor-pointer list-none items-center justify-between px-4 py-2.5 text-xs text-muted-foreground">Assessment<ChevronDown className="size-3.5 transition-transform group-open:rotate-180"/></summary><p className="px-4 pb-4 text-sm leading-relaxed text-muted-foreground">{v.summary}</p></details>
      <div className="grid grid-cols-[minmax(0,1fr)] xl:grid-cols-[minmax(0,1fr)_240px]">
        <div className="px-4 py-2">
          <ul className="divide-y divide-border">
            {(v.findings ?? []).map((f, i) => (
              <li key={i}>
                <details className="group/finding"><summary className="flex cursor-pointer list-none items-center gap-3 py-3"><span className={cn("shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase", sevClass[f.severity] ?? sevClass.low)}>{f.severity}</span><span className="min-w-0 flex-1 text-xs font-medium">{f.title}</span><ChevronDown className="size-3.5 shrink-0 text-muted-foreground transition-transform group-open/finding:rotate-180"/></summary><div className="pb-3 text-xs leading-relaxed text-muted-foreground">{f.detail}{f.evidence && <div className="mt-2 break-words font-mono text-[11px]">{f.evidence}</div>}</div></details>
              </li>
            ))}
            {(v.findings ?? []).length === 0 && <li className="text-sm text-muted-foreground">No findings.</li>}
          </ul>
        </div>
        <div className="space-y-4 border-t border-border p-4 xl:border-t-0 xl:border-l">
          {(v.tools ?? []).length > 0 && (
            <div>
              <div className="mb-2 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Tool risk</div>
              <ul className="space-y-1.5">
                {v.tools.map((t) => (
                  <li key={t.tool} className="grid grid-cols-[1fr_60px_24px] items-center gap-2 text-xs">
                    <span className="truncate font-mono" title={t.class}>{t.tool}</span>
                    <span className="h-1 rounded-full bg-muted"><span className={cn("block h-full rounded-full", riskBar(t.risk))} style={{ width: `${t.risk}%` }} /></span>
                    <span className="text-right font-mono text-muted-foreground">{t.risk}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <details className="group/guardrails">
            <summary className="flex cursor-pointer list-none items-center justify-between text-xs text-muted-foreground">Recommendations · {v.guardrails?.length ?? 0}<ChevronDown className="size-3.5 transition-transform group-open/guardrails:rotate-180"/></summary>
            <ol className="mt-3 space-y-2 text-xs">
              {(v.guardrails ?? []).map((a, i) => <li key={i} className="flex gap-2"><span className="font-mono text-muted-foreground">{i + 1}</span>{a}</li>)}
            </ol>
          </details>
        </div>
      </div>
    </section>
  );
}

function AgentPanel({ name, state }: { name: string; state: AgentState }) {
  return (
    <details className="group min-w-0 border-y border-border">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-1 py-3">
        <span className="text-xs font-medium">{name}</span>
        <span className="ml-auto font-mono text-[10px] uppercase text-muted-foreground">{!state ? "queued" : state.declined ? "declined" : state.done ? "complete" : "running"}</span><ChevronDown className="size-3.5 text-muted-foreground transition-transform group-open:rotate-180"/>
      </summary>
      <div className="max-h-80 overflow-auto whitespace-pre-wrap break-words pb-4 text-[12px] leading-relaxed text-muted-foreground">
        {state?.declined && <span className="text-warning">Model declined this analysis. Verdict uses the other agents.</span>}
        {state?.text || (state && !state.done ? <span className="inline-block h-3.5 w-1.5 animate-pulse bg-primary" /> : null)}
      </div>
    </details>
  );
}

function SignalTable({ signals }: { signals: Signal[] }) {
  return (
    <section className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <span className="text-xs font-medium">Static signals</span>
        <span className="font-mono text-xs text-muted-foreground">{signals.length}</span>
      </div>
      {signals.length === 0 ? (
        <div className="px-4 py-5 text-xs text-muted-foreground">No matches.</div>
      ) : (
        <div className="max-h-96 overflow-auto">
          <table className="w-full text-left text-xs">
            <tbody>
              {signals.map((s, i) => (
                <tr key={i} className="border-b border-border last:border-0">
                  <td className="w-20 px-4 py-2"><span className={cn("rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase", sevClass[s.severity])}>{s.severity}</span></td>
                  <td className="w-52 px-2 py-2">{s.label}</td>
                  <td className="w-48 truncate px-2 py-2 font-mono text-muted-foreground">{s.target}</td>
                  <td className="max-w-0 truncate px-2 py-2 pr-4 font-mono text-muted-foreground/80">{s.excerpt}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
