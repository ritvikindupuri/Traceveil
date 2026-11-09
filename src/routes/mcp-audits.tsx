import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, Loader2, Square, Check, Circle, History, LogOut, Download, X,Server, ChevronDown, SlidersHorizontal, Info, ShieldAlert, ShieldCheck, AlertTriangle, Ban, CheckCircle2, AlertCircle } from "lucide-react";
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
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from "@/components/ui/tooltip";
import { classifyAuditParts, type ClassifiedPart, type PartStatus } from "@/lib/scan/tool-classification";
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
          {verdict && <VerdictCard v={verdict} inv={inv} signals={signals} />}
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

function VerdictCard({ v, inv, signals }: { v: Verdict; inv?: Inventory | null; signals?: Signal[] }) {
  const [activeTab, setActiveTab] = useState<'all' | 'blocked' | 'review' | 'allowed'>('all');
  const classified = classifyAuditParts(inv, v, signals);
  const tone = v.verdict === "block" ? "text-destructive" : v.verdict === "review" ? "text-warning" : "text-success";

  return (
    <section className="min-w-0 border-y border-border">
      {/* 1. Header with Verdict, Risk Score, and Findings */}
      <div className="flex flex-wrap items-center gap-6 border-b border-border p-4">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
            <span>Agent Guardrail Verdict</span>
            <TooltipProvider delayDuration={100}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="cursor-help text-muted-foreground hover:text-foreground">
                    <Info className="size-3" />
                  </span>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-xs p-3 text-xs bg-popover text-popover-foreground border border-border shadow-xl">
                  <div className="font-semibold text-foreground border-b border-border pb-1">What does this verdict mean?</div>
                  <p className="mt-1.5 text-[11px] text-muted-foreground leading-relaxed">
                    Traceveil acts as an AI agent security guardrail. The verdict advises your agent runtime or proxy whether to permit or block tool invocations before the agent executes them.
                  </p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className={cn("text-2xl font-semibold uppercase tracking-tight", tone)}>{v.verdict}</span>
            <span className={cn(
              "rounded-full px-2 py-0.5 text-[10px] font-medium border flex items-center gap-1",
              v.verdict === "block" ? "bg-destructive/10 text-destructive border-destructive/30" :
              v.verdict === "review" ? "bg-warning/10 text-warning border-warning/30" :
              "bg-success/10 text-success border-success/30"
            )}>
              {v.verdict === "block" && <ShieldAlert className="size-3" />}
              {v.verdict === "review" && <AlertTriangle className="size-3" />}
              {v.verdict === "allow" && <ShieldCheck className="size-3" />}
              <span>
                {v.verdict === "block" ? "Agent Execution Blocked" :
                 v.verdict === "review" ? "Approval Required" :
                 "Safe to Execute"}
              </span>
            </span>
          </div>
          <p className="mt-1 text-[11px] text-muted-foreground max-w-sm leading-relaxed">
            {v.verdict === "block"
              ? "Critical risks detected. Guardrails recommend blocking agent tool calls to this server to prevent unauthorized actions or credential leakage."
              : v.verdict === "review"
              ? "Sensitive capabilities detected. Requires human approval or parameter scoping before execution."
              : "Tools conform to safety policies. Safe for autonomous agent invocation."}
          </p>
        </div>

        <TooltipProvider delayDuration={100}>
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="w-44 cursor-help rounded-md p-2 hover:bg-muted/40 transition">
                <div className="flex justify-between font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                  <span className="flex items-center gap-1">Risk Score <Info className="size-2.5" /></span>
                  <span className="font-bold text-foreground">{v.risk}/100</span>
                </div>
                <div className="mt-2 h-1.5 rounded-full bg-muted">
                  <div className={cn("h-full rounded-full", riskBar(v.risk))} style={{ width: `${Math.min(100, Math.max(0, v.risk))}%` }} />
                </div>
                <div className="mt-1 text-[9px] text-muted-foreground text-right">
                  {v.risk >= 70 ? 'High Risk · Blocked' : v.risk >= 40 ? 'Moderate · Review' : 'Low Risk · Allowed'}
                </div>
              </div>
            </TooltipTrigger>
            <TooltipContent side="top" className="max-w-xs p-3 text-xs bg-popover text-popover-foreground border border-border shadow-xl">
              <div className="font-semibold text-foreground border-b border-border pb-1">Risk Score: {v.risk} / 100</div>
              <p className="mt-1.5 text-[11px] text-muted-foreground leading-relaxed">
                Evaluated dynamically from discovered security signals and static rule violations:
              </p>
              <div className="mt-2 space-y-1 font-mono text-[10px] text-muted-foreground bg-muted/30 p-2 rounded border border-border/50">
                <div>• <span className="text-destructive font-bold">+40 pts:</span> Critical findings (RCE, token exfiltration)</div>
                <div>• <span className="text-warning font-bold">+20 pts:</span> High severity (SSRF, arbitrary filesystem)</div>
                <div>• <span className="text-foreground font-bold">+10 pts:</span> Base exposure for static triggers</div>
              </div>
              <div className="mt-2 pt-1 border-t border-border/50 text-[10px] text-muted-foreground">
                Score &ge; 70 triggers an <strong>Agent Execution BLOCK</strong> recommendation.
              </div>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>

        <div className="ml-auto text-right">
          <div className="font-mono text-xl">{v.findings?.length ?? 0}</div>
          <div className="text-[10px] text-muted-foreground">Findings</div>
        </div>
      </div>

      {/* 2. Color-Coded Classification Filter Pills */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border bg-muted/20 px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-medium text-muted-foreground mr-1">Component Classification:</span>
          
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => setActiveTab('all')}
            className={cn(
              "h-7 px-3 text-xs rounded-full border transition",
              activeTab === 'all'
                ? "bg-accent border-foreground/30 font-semibold text-foreground shadow-sm"
                : "border-border/60 text-muted-foreground hover:text-foreground"
            )}
          >
            All Parts ({classified.counts.total})
          </Button>

          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => setActiveTab('blocked')}
            className={cn(
              "h-7 px-3 text-xs rounded-full border transition flex items-center gap-1.5",
              activeTab === 'blocked'
                ? "bg-destructive/20 border-destructive text-destructive font-semibold shadow-sm"
                : "border-destructive/30 bg-destructive/5 text-destructive/80 hover:bg-destructive/10"
            )}
          >
            <ShieldAlert className="size-3.5 text-destructive" />
            <span>Blocked ({classified.counts.blocked})</span>
          </Button>

          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => setActiveTab('review')}
            className={cn(
              "h-7 px-3 text-xs rounded-full border transition flex items-center gap-1.5",
              activeTab === 'review'
                ? "bg-warning/20 border-warning text-warning font-semibold shadow-sm"
                : "border-warning/30 bg-warning/5 text-warning/80 hover:bg-warning/10"
            )}
          >
            <AlertTriangle className="size-3.5 text-warning" />
            <span>Needs Review ({classified.counts.review})</span>
          </Button>

          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => setActiveTab('allowed')}
            className={cn(
              "h-7 px-3 text-xs rounded-full border transition flex items-center gap-1.5",
              activeTab === 'allowed'
                ? "bg-success/20 border-success text-success font-semibold shadow-sm"
                : "border-success/30 bg-success/5 text-success/80 hover:bg-success/10"
            )}
          >
            <ShieldCheck className="size-3.5 text-success" />
            <span>Allowed ({classified.counts.allowed})</span>
          </Button>
        </div>

        <span className="font-mono text-[10px] text-muted-foreground hidden sm:inline">
          {classified.counts.blocked} blocked · {classified.counts.review} review · {classified.counts.allowed} allowed
        </span>
      </div>

      {/* 3. Assessment summary */}
      <details className="group border-b border-border">
        <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-2.5 text-xs text-muted-foreground">
          <span>Assessment Summary</span>
          <ChevronDown className="size-3.5 transition-transform group-open:rotate-180"/>
        </summary>
        <p className="px-4 pb-4 text-sm leading-relaxed text-muted-foreground">{v.summary}</p>
      </details>

      {/* 4. Main Content: Color-Coded Breakdown Sections + Side Panel */}
      <div className="grid grid-cols-[minmax(0,1fr)] xl:grid-cols-[minmax(0,1fr)_260px]">
        <div className="p-4 space-y-5">
          {/* A. BLOCKED SECTION */}
          {(activeTab === 'all' || activeTab === 'blocked') && (
            <div className="rounded-lg border border-destructive/30 bg-destructive/[0.03] p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-destructive/20 pb-2.5">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="size-4 text-destructive" />
                  <span className="text-xs font-semibold text-destructive">Blocked Capabilities & Dangerous Primitives</span>
                </div>
                <span className="rounded bg-destructive/15 px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-destructive border border-destructive/30">
                  Blocked · Execution Denied ({classified.counts.blocked})
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                Autonomous agent invocation to these capabilities is actively <strong>blocked</strong> by runtime guardrails. They contain execution primitives that could permit prompt injection to trigger Remote Code Execution (RCE) or secret leakage.
              </p>

              {classified.blocked.length === 0 ? (
                <div className="flex items-center gap-2 rounded border border-border/50 bg-background/50 p-3 text-xs text-muted-foreground">
                  <CheckCircle2 className="size-4 text-success" />
                  <span>No blocked capabilities or critical threats detected in this server.</span>
                </div>
              ) : (
                <div className="space-y-2.5">
                  {classified.blocked.map((item) => (
                    <div key={item.name} className="rounded-md border border-destructive/30 bg-card p-3 shadow-sm border-l-4 border-l-destructive space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <Ban className="size-3.5 text-destructive shrink-0" />
                          <span className="font-mono text-xs font-bold text-foreground">{item.name}</span>
                        </div>
                        <div className="flex items-center gap-1.5 font-mono text-[10px]">
                          <span className="rounded bg-destructive/10 px-2 py-0.5 font-semibold text-destructive border border-destructive/20">
                            Risk: {item.risk}/100
                          </span>
                          <span className="rounded bg-muted px-1.5 py-0.5 text-muted-foreground">
                            BLOCKED
                          </span>
                        </div>
                      </div>

                      {/* Color-Coded Explanation Box */}
                      <div className="rounded bg-destructive/10 p-2.5 text-xs text-destructive border border-destructive/20 space-y-1">
                        <div className="font-semibold text-[11px] flex items-center gap-1">
                          <span>Why this part is blocked:</span>
                        </div>
                        <p className="text-[11px] leading-relaxed text-destructive/90">
                          {item.explanation}
                        </p>
                      </div>

                      {/* Signals & Findings */}
                      {item.rules.length > 0 && (
                        <div className="flex flex-wrap gap-1 pt-1">
                          {item.rules.map((rule) => (
                            <span key={rule} className="rounded bg-muted/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground border border-border/40">
                              rule: {rule}
                            </span>
                          ))}
                        </div>
                      )}

                      {item.findings.length > 0 && (
                        <details className="group/itemfind pt-1">
                          <summary className="flex cursor-pointer list-none items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground">
                            <span>Technical Evidence ({item.findings.length})</span>
                            <ChevronDown className="size-3 transition-transform group-open/itemfind:rotate-180" />
                          </summary>
                          <div className="mt-1.5 space-y-1.5 pl-2 border-l border-destructive/30">
                            {item.findings.map((f, fi) => (
                              <div key={fi} className="text-[11px]">
                                <div className="font-medium text-foreground">{f.title}</div>
                                <div className="text-muted-foreground">{f.detail}</div>
                                {f.evidence && (
                                  <pre className="mt-1 p-1.5 rounded bg-muted font-mono text-[10px] overflow-auto text-muted-foreground break-all">
                                    {f.evidence}
                                  </pre>
                                )}
                              </div>
                            ))}
                          </div>
                        </details>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* B. REVIEW REQUIRED SECTION */}
          {(activeTab === 'all' || activeTab === 'review') && (
            <div className="rounded-lg border border-warning/30 bg-warning/[0.03] p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-warning/20 pb-2.5">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="size-4 text-warning" />
                  <span className="text-xs font-semibold text-warning">Review Required & Sensitive Capabilities</span>
                </div>
                <span className="rounded bg-warning/15 px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-warning border border-warning/30">
                  Needs Review ({classified.counts.review})
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                These capabilities access sensitive resources like external networks, user files, or parameter expansions. They require <strong>human-in-the-loop authorization</strong> or parameter whitelisting before execution.
              </p>

              {classified.counts.review === 0 ? (
                <div className="flex items-center gap-2 rounded border border-border/50 bg-background/50 p-3 text-xs text-muted-foreground">
                  <CheckCircle2 className="size-4 text-success" />
                  <span>No capabilities flagged for review.</span>
                </div>
              ) : (
                <div className="space-y-2.5">
                  {classified.review.map((item) => (
                    <div key={item.name} className="rounded-md border border-warning/30 bg-card p-3 shadow-sm border-l-4 border-l-warning space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="size-3.5 text-warning shrink-0" />
                          <span className="font-mono text-xs font-bold text-foreground">{item.name}</span>
                        </div>
                        <div className="flex items-center gap-1.5 font-mono text-[10px]">
                          <span className="rounded bg-warning/10 px-2 py-0.5 font-semibold text-warning border border-warning/20">
                            Risk: {item.risk}/100
                          </span>
                          <span className="rounded bg-muted px-1.5 py-0.5 text-muted-foreground">
                            REVIEW
                          </span>
                        </div>
                      </div>

                      {/* Color-Coded Explanation Box */}
                      <div className="rounded bg-warning/10 p-2.5 text-xs text-warning border border-warning/20 space-y-1">
                        <div className="font-semibold text-[11px] flex items-center gap-1">
                          <span>Why review is required:</span>
                        </div>
                        <p className="text-[11px] leading-relaxed text-warning/90">
                          {item.explanation}
                        </p>
                      </div>

                      {/* Signals & Findings */}
                      {item.rules.length > 0 && (
                        <div className="flex flex-wrap gap-1 pt-1">
                          {item.rules.map((rule) => (
                            <span key={rule} className="rounded bg-muted/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground border border-border/40">
                              rule: {rule}
                            </span>
                          ))}
                        </div>
                      )}

                      {item.findings.length > 0 && (
                        <details className="group/itemfind pt-1">
                          <summary className="flex cursor-pointer list-none items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground">
                            <span>Technical Details ({item.findings.length})</span>
                            <ChevronDown className="size-3 transition-transform group-open/itemfind:rotate-180" />
                          </summary>
                          <div className="mt-1.5 space-y-1.5 pl-2 border-l border-warning/30">
                            {item.findings.map((f, fi) => (
                              <div key={fi} className="text-[11px]">
                                <div className="font-medium text-foreground">{f.title}</div>
                                <div className="text-muted-foreground">{f.detail}</div>
                                {f.evidence && (
                                  <pre className="mt-1 p-1.5 rounded bg-muted font-mono text-[10px] overflow-auto text-muted-foreground break-all">
                                    {f.evidence}
                                  </pre>
                                )}
                              </div>
                            ))}
                          </div>
                        </details>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* C. ALLOWED SECTION */}
          {(activeTab === 'all' || activeTab === 'allowed') && (
            <div className="rounded-lg border border-success/30 bg-success/[0.03] p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-success/20 pb-2.5">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="size-4 text-success" />
                  <span className="text-xs font-semibold text-success">Allowed Capabilities & Safe Tools</span>
                </div>
                <span className="rounded bg-success/15 px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-success border border-success/30">
                  Allowed · Safe to Execute ({classified.counts.allowed})
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                These tools operate within least-privilege constraints (e.g. documentation lookups, schema queries). They contain no dangerous execution primitives and are <strong>approved for autonomous agent invocation</strong>.
              </p>

              {classified.counts.allowed === 0 ? (
                <div className="flex items-center gap-2 rounded border border-border/50 bg-background/50 p-3 text-xs text-muted-foreground">
                  <AlertCircle className="size-4 text-muted-foreground" />
                  <span>No tools currently classified as allowed.</span>
                </div>
              ) : (
                <div className="space-y-2.5">
                  {classified.allowed.map((item) => (
                    <div key={item.name} className="rounded-md border border-success/30 bg-card p-3 shadow-sm border-l-4 border-l-success space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <CheckCircle2 className="size-3.5 text-success shrink-0" />
                          <span className="font-mono text-xs font-bold text-foreground">{item.name}</span>
                        </div>
                        <div className="flex items-center gap-1.5 font-mono text-[10px]">
                          <span className="rounded bg-success/10 px-2 py-0.5 font-semibold text-success border border-success/20">
                            Risk: {item.risk}/100
                          </span>
                          <span className="rounded bg-muted px-1.5 py-0.5 text-muted-foreground">
                            ALLOWED
                          </span>
                        </div>
                      </div>

                      {/* Color-Coded Explanation Box */}
                      <div className="rounded bg-success/10 p-2.5 text-xs text-success border border-success/20 space-y-1">
                        <div className="font-semibold text-[11px] flex items-center gap-1">
                          <span>Why this part is allowed:</span>
                        </div>
                        <p className="text-[11px] leading-relaxed text-success/90">
                          {item.explanation}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* 5. Right Sidebar with Tool Risk Scores and Recommendations */}
        <div className="space-y-4 border-t border-border p-4 xl:border-t-0 xl:border-l bg-card/40">
          {(v.tools ?? []).length > 0 && (
            <div>
              <div className="mb-2 font-mono text-[10px] uppercase tracking-wider text-muted-foreground flex justify-between items-center">
                <span>Tool Risk Scores</span>
                <span>{v.tools.length}</span>
              </div>
              <ul className="space-y-2">
                {v.tools.map((t) => {
                  const part = classified.all.find(p => p.name === t.tool);
                  const status = part?.status ?? (t.risk >= 70 ? 'blocked' : t.risk >= 40 ? 'review' : 'allowed');
                  return (
                    <li key={t.tool} className="rounded border border-border/60 bg-card p-2 text-xs space-y-1">
                      <div className="flex items-center justify-between gap-1">
                        <span className="truncate font-mono font-medium" title={t.tool}>{t.tool}</span>
                        <span className={cn(
                          "rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase",
                          status === 'blocked' ? "bg-destructive/15 text-destructive border border-destructive/30" :
                          status === 'review' ? "bg-warning/15 text-warning border border-warning/30" :
                          "bg-success/15 text-success border border-success/30"
                        )}>
                          {status}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 flex-1 rounded-full bg-muted">
                          <div className={cn("h-full rounded-full", riskBar(t.risk))} style={{ width: `${Math.min(100, Math.max(0, t.risk))}%` }} />
                        </div>
                        <span className="font-mono text-[10px] text-muted-foreground shrink-0">{t.risk}/100</span>
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          <details className="group/guardrails" open>
            <summary className="flex cursor-pointer list-none items-center justify-between text-xs text-muted-foreground font-medium">
              <span>Guardrail Rules · {v.guardrails?.length ?? 0}</span>
              <ChevronDown className="size-3.5 transition-transform group-open/guardrails:rotate-180"/>
            </summary>
            <ol className="mt-3 space-y-2 text-xs">
              {(v.guardrails ?? []).map((a, i) => (
                <li key={i} className="flex gap-2 text-muted-foreground">
                  <span className="font-mono text-foreground font-semibold">{i + 1}.</span>
                  <span>{a}</span>
                </li>
              ))}
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
