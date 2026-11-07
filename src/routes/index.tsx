import { createFileRoute } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { ArrowRight, Loader2, Square, Check, Circle } from "lucide-react";
import { Logo } from "@/components/armorix/Logo";
import { AuditVisuals } from "@/components/armorix/AuditVisuals";
import { Button } from "@/components/ui/button";
import type { Inventory, Mode, Sev, Signal, Verdict } from "@/lib/scan/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Armorix — MCP tool poisoning & agent guardrails" },
      { name: "description", content: "Audit MCP tool definitions, live MCP servers and agent transcripts for prompt injection, tool poisoning and exfiltration." },
      { property: "og:title", content: "Armorix — MCP tool poisoning & agent guardrails" },
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

  async function scan(e?: React.FormEvent) {
    e?.preventDefault();
    if (!input.trim() || running) return;
    setInv(null); setSignals([]); setAgents({}); setVerdict(null); setError(null); setStage("collect");
    const ac = new AbortController();
    ctrl.current = ac;
    try {
      const res = await fetch("/api/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ mode, input, token: mode === "endpoint" ? token : undefined }), signal: ac.signal });
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
      case "done": setStage("done"); break;
      case "error": setError(ev.message); setStage("error"); break;
    }
  }

  const ph = MODES.find((m) => m.k === mode)?.ph ?? "";

  return (
    <div className="min-h-screen">
      <header className="flex min-h-14 flex-wrap items-center justify-between gap-2 border-b border-border px-5 py-2">
        <div className="flex items-center gap-2.5">
          <Logo />
          <span className="text-[15px] font-semibold">Armorix</span>
          <span className="ml-1 rounded border border-border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">agent guardrails</span>
        </div>
        <div role="status" className="flex items-center gap-2 font-mono text-[10px] text-muted-foreground">
          <span className={cn("h-1.5 w-1.5 rounded-full", stage === "error" ? "bg-warning" : "bg-primary")} /> Neural Guardrail Engine · <span className={stage === "error" ? "text-warning" : "text-primary"}>{stage === "error" ? "Attention" : running ? "Analyzing" : "Active"}</span>
        </div>
      </header>

      <main className="mx-auto grid max-w-[1400px] grid-cols-[minmax(0,1fr)] gap-4 p-5 lg:grid-cols-[420px_minmax(0,1fr)]">
        <form onSubmit={scan} className="flex h-fit min-w-0 flex-col rounded-lg border border-border bg-card lg:sticky lg:top-5">
          <div className="flex border-b border-border">
            {MODES.map((m) => (
              <Button variant="ghost" key={m.k} type="button" onClick={() => setMode(m.k)} disabled={running}
                className={cn("h-10 flex-1 rounded-none border-b-2 px-2 text-xs", mode === m.k ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground")}>
                {m.l}
              </Button>
            ))}
          </div>
          {mode === "endpoint" ? (
            <div className="space-y-2 p-3">
              <input aria-label="MCP endpoint URL" value={input} onChange={(e) => setInput(e.target.value)} placeholder={ph} spellCheck={false}
                className="h-9 w-full rounded-md border border-input bg-background px-3 font-mono text-xs outline-none focus:ring-2 focus:ring-ring" />
              <input aria-label="Bearer token" value={token} onChange={(e) => setToken(e.target.value)} placeholder="Bearer token (optional, not stored)" type="password"
                className="h-9 w-full rounded-md border border-input bg-background px-3 font-mono text-xs outline-none focus:ring-2 focus:ring-ring" />
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
          {error && <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>}
          {inv && <AuditVisuals key={`${inv.source}-${inv.mode}`} inventory={inv} signals={signals} verdict={verdict} />}
          {verdict && <VerdictCard v={verdict} />}
          {started && (
            <div className="grid grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-3">
              {AGENTS.map((a) => <AgentPanel key={a.k} name={a.l} state={agents[a.k]} />)}
            </div>
          )}
          {inv && <SignalTable signals={signals} />}
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
    <section className="min-w-0 rounded-lg border border-border bg-card">
      <div className="flex flex-wrap items-center gap-6 border-b border-border p-4">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Verdict</div>
          <div className={cn("text-2xl font-semibold uppercase tracking-tight", tone)}>{v.verdict}</div>
        </div>
        <div className="w-36">
          <div className="flex justify-between font-mono text-[10px] uppercase tracking-wider text-muted-foreground"><span>Risk</span><span>{v.risk}</span></div>
          <div className="mt-2 h-1.5 rounded-full bg-muted"><div className={cn("h-full rounded-full", riskBar(v.risk))} style={{ width: `${Math.min(100, Math.max(0, v.risk))}%` }} /></div>
        </div>
        <p className="min-w-[240px] flex-1 text-sm text-muted-foreground">{v.summary}</p>
      </div>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-px bg-border xl:grid-cols-[minmax(0,1fr)_300px]">
        <div className="bg-card p-4">
          <ul className="space-y-3">
            {(v.findings ?? []).map((f, i) => (
              <li key={i} className="flex gap-3">
                <span className={cn("mt-0.5 h-fit rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase", sevClass[f.severity] ?? sevClass.low)}>{f.severity}</span>
                <div className="min-w-0">
                  <div className="text-sm font-medium">{f.title}</div>
                  <div className="text-sm text-muted-foreground">{f.detail}</div>
                  {f.evidence && <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground/80">{f.evidence}</div>}
                </div>
              </li>
            ))}
            {(v.findings ?? []).length === 0 && <li className="text-sm text-muted-foreground">No findings.</li>}
          </ul>
        </div>
        <div className="space-y-5 bg-card p-4">
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
          <div>
            <div className="mb-2 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Guardrails</div>
            <ol className="space-y-2 text-xs">
              {(v.guardrails ?? []).map((a, i) => <li key={i} className="flex gap-2"><span className="font-mono text-muted-foreground">{i + 1}</span>{a}</li>)}
            </ol>
          </div>
        </div>
      </div>
    </section>
  );
}

function AgentPanel({ name, state }: { name: string; state: AgentState }) {
  return (
    <section className="min-w-0 rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <span className="text-xs font-medium">{name}</span>
        <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{!state ? "queued" : state.declined ? "declined" : state.done ? "complete" : "running"}</span>
      </div>
      <div className="max-h-80 min-h-[140px] overflow-auto whitespace-pre-wrap break-words p-4 text-[12px] leading-relaxed text-muted-foreground">
        {state?.declined && <span className="text-warning">Model declined this analysis. Verdict uses the other agents.</span>}
        {state?.text || (state && !state.done ? <span className="inline-block h-3.5 w-1.5 animate-pulse bg-primary" /> : null)}
      </div>
    </section>
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
