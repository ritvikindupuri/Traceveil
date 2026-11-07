import { createFileRoute } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { ArrowRight, Loader2, Square, Check, Circle } from "lucide-react";
import { Logo } from "@/components/vigil/Logo";
import type { Recon } from "@/lib/scan/types";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Vigil — Agentic supply-chain defense" },
      { name: "description", content: "Autonomous Gemini agents that inspect npm releases for worm propagation, token theft and account takeover." },
      { property: "og:title", content: "Vigil — Agentic supply-chain defense" },
      { property: "og:description", content: "Autonomous agents that inspect npm releases for worm propagation and credential theft." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Index,
});

type Sev = "critical" | "high" | "medium" | "low";
type Signal = { id: string; label: string; severity: Sev; file: string; line: number; excerpt: string };

type Verdict = {
  verdict: "block" | "review" | "allow";
  risk: number;
  summary: string;
  findings: { severity: Sev; title: string; detail: string; evidence: string }[];
  actions: string[];
};
type Stage = "idle" | "collect" | "agents" | "verdict" | "done" | "error";

const sevClass: Record<Sev, string> = {
  critical: "text-destructive bg-destructive/10 border-destructive/30",
  high: "text-warning bg-warning/10 border-warning/30",
  medium: "text-foreground bg-secondary border-border",
  low: "text-muted-foreground bg-muted border-border",
};

function Index() {
  const [spec, setSpec] = useState("");
  const [stage, setStage] = useState<Stage>("idle");
  const [recon, setRecon] = useState<Recon | null>(null);
  const [signals, setSignals] = useState<Signal[]>([]);
  const [agents, setAgents] = useState<Record<string, { text: string; done: boolean }>>({});
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [target, setTarget] = useState("");
  const ctrl = useRef<AbortController | null>(null);
  const running = ["collect", "agents", "verdict"].includes(stage);

  async function scan(e?: React.FormEvent) {
    e?.preventDefault();
    const s = spec.trim();
    if (!s || running) return;
    setTarget(s);
    setRecon(null); setSignals([]); setAgents({}); setVerdict(null); setError(null); setStage("collect");
    const ac = new AbortController();
    ctrl.current = ac;
    try {
      const res = await fetch("/api/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ spec: s }), signal: ac.signal });
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
      case "evidence": setRecon(ev.recon); setSignals(ev.signals); break;
      case "agent:start": setAgents((a) => ({ ...a, [ev.agent]: { text: "", done: false } })); break;
      case "agent:delta": setAgents((a) => ({ ...a, [ev.agent]: { text: (a[ev.agent]?.text ?? "") + ev.text, done: false } })); break;
      case "agent:end": setAgents((a) => ({ ...a, [ev.agent]: { text: a[ev.agent]?.text ?? "", done: true } })); break;
      case "verdict": setVerdict(ev); break;
      case "done": setStage("done"); break;
      case "error": setError(ev.message); setStage("error"); break;
    }
  }

  const idle = stage === "idle" && !recon;

  return (
    <div className="min-h-screen">
      <header className="flex h-14 items-center justify-between border-b border-border px-6">
        <div className="flex items-center gap-2.5">
          <Logo />
          <span className="text-[15px] font-semibold tracking-tight">Vigil</span>
          <span className="ml-2 rounded border border-border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">supply chain</span>
        </div>
        <div className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
          <span className="h-1.5 w-1.5 rounded-full bg-primary" /> gemini-4-argon
        </div>
      </header>

      <main className={cn("mx-auto max-w-6xl px-6", idle ? "pt-[22vh]" : "pt-8")}>
        {idle && (
          <div className="mb-8 text-center">
            <h1 className="text-4xl font-medium tracking-tight">Inspect a release before it runs.</h1>
            <p className="mt-3 text-sm text-muted-foreground">Agents check npm packages for worm propagation, token theft and maintainer takeover.</p>
          </div>
        )}

        <form onSubmit={scan} className={cn("mx-auto flex items-center gap-2 rounded-lg border border-border bg-card p-1.5 pl-4 focus-within:ring-2 focus-within:ring-ring", idle ? "max-w-xl" : "max-w-none")}>
          <span className="font-mono text-xs text-muted-foreground">npm</span>
          <input
            value={spec}
            onChange={(e) => setSpec(e.target.value)}
            placeholder="package or package@version"
            spellCheck={false}
            autoFocus
            className="h-9 flex-1 bg-transparent font-mono text-sm outline-none placeholder:text-muted-foreground/60"
          />
          {running ? (
            <button type="button" onClick={() => ctrl.current?.abort()} className="inline-flex h-9 items-center gap-2 rounded-md bg-secondary px-3 text-sm hover:bg-accent">
              <Square className="h-3.5 w-3.5" /> Stop
            </button>
          ) : (
            <button type="submit" disabled={!spec.trim()} className="inline-flex h-9 items-center gap-2 rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground disabled:opacity-40">
              Scan <ArrowRight className="h-3.5 w-3.5" />
            </button>
          )}
        </form>

        {!idle && (
          <div className="mt-6 space-y-4 pb-16">
            <Pipeline stage={stage} target={target} />
            {error && <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>}
            {verdict && <VerdictCard v={verdict} />}
            <div className="grid gap-4 lg:grid-cols-2">
              <AgentPanel name="Provenance" state={agents["provenance"]} />
              <AgentPanel name="Code" state={agents["code"]} />
            </div>
            {recon && <ReconCard r={recon} />}
            {recon && <SignalTable signals={signals} />}
          </div>
        )}
      </main>
    </div>
  );
}

function Pipeline({ stage, target }: { stage: Stage; target: string }) {
  const steps = [
    { k: "collect", l: "Collect" },
    { k: "agents", l: "Analyze" },
    { k: "verdict", l: "Decide" },
  ];
  const order = ["collect", "agents", "verdict", "done"];
  const cur = order.indexOf(stage);
  return (
    <div className="flex items-center justify-between rounded-lg border border-border bg-card px-4 py-3">
      <span className="truncate font-mono text-sm">{target}</span>
      <div className="flex items-center gap-5">
        {steps.map((s, i) => {
          const done = cur > i || stage === "done";
          const active = cur === i;
          return (
            <div key={s.k} className={cn("flex items-center gap-1.5 text-xs", done ? "text-foreground" : active ? "text-primary" : "text-muted-foreground")}>
              {done ? <Check className="h-3.5 w-3.5 text-primary" /> : active && stage !== "error" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Circle className="h-3 w-3" />}
              {s.l}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function VerdictCard({ v }: { v: Verdict }) {
  const tone = v.verdict === "block" ? "text-destructive" : v.verdict === "review" ? "text-warning" : "text-success";
  const bar = v.verdict === "block" ? "bg-destructive" : v.verdict === "review" ? "bg-warning" : "bg-success";
  return (
    <section className="rounded-lg border border-border bg-card">
      <div className="flex flex-wrap items-center gap-6 border-b border-border p-5">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Verdict</div>
          <div className={cn("text-2xl font-semibold uppercase tracking-tight", tone)}>{v.verdict}</div>
        </div>
        <div className="w-40">
          <div className="flex justify-between font-mono text-[10px] uppercase tracking-wider text-muted-foreground"><span>Risk</span><span>{v.risk}</span></div>
          <div className="mt-2 h-1.5 rounded-full bg-muted"><div className={cn("h-full rounded-full", bar)} style={{ width: `${Math.min(100, Math.max(0, v.risk))}%` }} /></div>
        </div>
        <p className="min-w-[240px] flex-1 text-sm text-muted-foreground">{v.summary}</p>
      </div>
      <div className="grid gap-px bg-border md:grid-cols-[1fr_280px]">
        <div className="bg-card p-5">
          {v.findings.length === 0 && <div className="text-sm text-muted-foreground">No findings.</div>}
          <ul className="space-y-3">
            {v.findings.map((f, i) => (
              <li key={i} className="flex gap-3">
                <span className={cn("mt-0.5 h-fit rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase", sevClass[f.severity] ?? sevClass.low)}>{f.severity}</span>
                <div className="min-w-0">
                  <div className="text-sm font-medium">{f.title}</div>
                  <div className="text-sm text-muted-foreground">{f.detail}</div>
                  {f.evidence && <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground/80">{f.evidence}</div>}
                </div>
              </li>
            ))}
          </ul>
        </div>
        <div className="bg-card p-5">
          <div className="mb-3 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Actions</div>
          <ol className="space-y-2 text-sm">
            {v.actions.map((a, i) => <li key={i} className="flex gap-2"><span className="font-mono text-muted-foreground">{i + 1}</span>{a}</li>)}
          </ol>
        </div>
      </div>
    </section>
  );
}

function AgentPanel({ name, state }: { name: string; state: { text: string; done: boolean } | undefined }) {
  return (
    <section className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <span className="text-sm font-medium">{name} agent</span>
        <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
          {!state ? "queued" : state.done ? "complete" : "running"}
        </span>
      </div>
      <div className="min-h-[140px] whitespace-pre-wrap p-4 text-[13px] leading-relaxed text-muted-foreground">
        {state?.text || (state && !state.done ? <span className="inline-block h-3.5 w-1.5 animate-pulse bg-primary" /> : null)}
      </div>
    </section>
  );
}

const fmt = (n: number) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}K` : `${n}`);
const ago = (d?: string | null) => (d ? new Date(d).toISOString().slice(0, 16).replace("T", " ") : "—");

function ReconCard({ r }: { r: Recon }) {
  const changedPublisher = r.previousPublisher && r.publisher !== r.previousPublisher;
  const lostProv = r.previousHadProvenance && !r.hasProvenance;
  const newHooks = Object.keys(r.scripts).filter((k) => r.scripts[k] !== r.previousScripts?.[k]);
  const rows: [string, React.ReactNode, boolean?][] = [
    ["Version", `${r.version}${r.previousVersion ? `  ← ${r.previousVersion}` : ""}`],
    ["Published", ago(r.publishedAt)],
    ["Publisher", `${r.publisher ?? "—"}${changedPublisher ? `  (was ${r.previousPublisher})` : ""}`, !!changedPublisher],
    ["Provenance", r.hasProvenance ? "attested" : lostProv ? "missing — previously attested" : "none", lostProv],
    ["Weekly downloads", r.weeklyDownloads != null ? fmt(r.weeklyDownloads) : "—"],
    ["Maintainers", r.maintainers.length],
    ["Files", `${r.fileCount} · ${fmt(r.tarballSize)}B`],
    ["Lifecycle hooks", Object.keys(r.scripts).length ? Object.entries(r.scripts).map(([k, v]) => `${k}: ${v}`).join("\n") : "none", newHooks.length > 0],
  ];
  return (
    <section className="rounded-lg border border-border bg-card">
      <div className="border-b border-border px-4 py-2.5 text-sm font-medium">Registry</div>
      <dl className="grid sm:grid-cols-2">
        {rows.map(([k, v, flag]) => (
          <div key={k} className="flex gap-4 border-b border-border px-4 py-2.5 last:border-0 sm:[&:nth-last-child(2)]:border-0">
            <dt className="w-36 shrink-0 text-xs text-muted-foreground">{k}</dt>
            <dd className={cn("min-w-0 whitespace-pre-wrap break-all font-mono text-xs", flag && "text-warning")}>{v}</dd>
          </div>
        ))}
      </dl>
      {r.addedFiles.length > 0 && (
        <div className="border-t border-border px-4 py-3">
          <div className="mb-2 text-xs text-muted-foreground">New since {r.previousVersion}</div>
          <div className="flex flex-wrap gap-1.5">{r.addedFiles.map((f) => <span key={f} className="rounded bg-secondary px-1.5 py-0.5 font-mono text-[11px]">{f}</span>)}</div>
        </div>
      )}
    </section>
  );
}

function SignalTable({ signals }: { signals: Signal[] }) {
  return (
    <section className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <span className="text-sm font-medium">Static signals</span>
        <span className="font-mono text-xs text-muted-foreground">{signals.length}</span>
      </div>
      {signals.length === 0 ? (
        <div className="px-4 py-6 text-sm text-muted-foreground">No matches.</div>
      ) : (
        <div className="max-h-96 overflow-auto">
          <table className="w-full text-left text-xs">
            <tbody>
              {signals.map((s, i) => (
                <tr key={i} className="border-b border-border last:border-0">
                  <td className="w-20 px-4 py-2"><span className={cn("rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase", sevClass[s.severity])}>{s.severity}</span></td>
                  <td className="w-48 px-2 py-2">{s.label}</td>
                  <td className="w-56 truncate px-2 py-2 font-mono text-muted-foreground">{s.file}:{s.line}</td>
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
