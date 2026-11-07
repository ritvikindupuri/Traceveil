import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import type { User } from "@supabase/supabase-js";
import { ArrowRight, FileJson, Radio, ScrollText, ScanSearch, Swords, Network, ShieldCheck, Fingerprint, Lock, History } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { AccountDialog } from "@/components/armorix/AccountDialog";
import { Logo } from "@/components/armorix/Logo";
import { Button } from "@/components/ui/button";

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
  component: Landing,
});

const INPUTS = [{ i: FileJson, l: "Tool definitions" }, { i: Radio, l: "Live MCP endpoint" }, { i: ScrollText, l: "Agent transcript" }];
const AGENTS = [{ i: ScanSearch, l: "Semantic risk" }, { i: Swords, l: "Adversarial fuzzing" }, { i: Network, l: "Blast radius" }];
const FEATURES = [
  { i: ShieldCheck, t: "Runtime approval", d: "Allowlisted read tools, explicit approval per call." },
  { i: Fingerprint, t: "Drift detection", d: "SHA-256 baselines block changed tool definitions." },
  { i: Lock, t: "Fail-closed egress", d: "Trusted destinations only. No private hosts." },
  { i: History, t: "Private audit trail", d: "Server-written, owner-only records." },
];
const THREATS = ["Tool poisoning", "Prompt injection", "Shadowing", "Parameter escalation", "Credential scraping", "Exfiltration"];

function Landing() {
  const [user, setUser] = useState<User | null>(null);
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  useEffect(() => {
    void supabase.auth.getUser().then(({ data }) => setUser(data.user));
    const { data } = supabase.auth.onAuthStateChange((event, session) => {
      setUser(session?.user ?? null);
      if (event === "SIGNED_IN") void navigate({ to: "/console" });
    });
    return () => data.subscription.unsubscribe();
  }, [navigate]);

  const cta = user ? (
    <Button asChild size="lg"><Link to="/console">Open console <ArrowRight className="size-4" /></Link></Button>
  ) : (
    <Button size="lg" onClick={() => setOpen(true)}>Sign in <ArrowRight className="size-4" /></Button>
  );

  return (
    <div className="relative min-h-screen overflow-hidden">
      <div aria-hidden className="pointer-events-none absolute inset-0 opacity-[0.07] [background-image:linear-gradient(var(--foreground)_1px,transparent_1px),linear-gradient(90deg,var(--foreground)_1px,transparent_1px)] [background-size:48px_48px] [mask-image:radial-gradient(ellipse_at_top,black,transparent_70%)]" />
      <div aria-hidden className="ax-pulse pointer-events-none absolute -top-40 left-1/2 h-[480px] w-[480px] -translate-x-1/2 rounded-full bg-primary/15 blur-3xl" />

      <header className="relative mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
        <div className="flex items-center gap-2.5"><Logo /><span className="text-[15px] font-semibold">Armorix</span></div>
        {user ? <Button asChild variant="outline" size="sm"><Link to="/console">Console</Link></Button> : <Button variant="outline" size="sm" onClick={() => setOpen(true)}>Sign in</Button>}
      </header>

      <main className="relative mx-auto max-w-6xl px-6">
        <section className="flex flex-col items-center pb-14 pt-16 text-center sm:pt-24">
          <div className="ax-rise"><Logo className="h-16 w-16 drop-shadow-[0_0_24px_color-mix(in_oklab,var(--primary)_45%,transparent)]" /></div>
          <h1 className="ax-rise mt-8 max-w-3xl text-4xl font-semibold tracking-tight sm:text-6xl" style={{ animationDelay: ".08s" }}>
            Audit tools before <span className="text-primary">agents trust them.</span>
          </h1>
          <p className="ax-rise mt-5 max-w-xl text-muted-foreground" style={{ animationDelay: ".16s" }}>
            Agentic security for MCP servers and agent sessions.
          </p>
          <div className="ax-rise mt-8" style={{ animationDelay: ".24s" }}>{cta}</div>
        </section>

        <section className="ax-rise rounded-xl border border-border bg-card/60 p-4 backdrop-blur sm:p-8" style={{ animationDelay: ".32s" }}>
          <Flow />
        </section>

        <section className="mt-6 flex flex-wrap justify-center gap-2">
          {THREATS.map((t, i) => (
            <span key={t} className="ax-rise rounded-full border border-border bg-card px-3 py-1 font-mono text-[11px] text-muted-foreground" style={{ animationDelay: `${0.4 + i * 0.05}s` }}>{t}</span>
          ))}
        </section>

        <section className="grid gap-px overflow-hidden rounded-xl border border-border bg-border my-16 sm:grid-cols-2 lg:grid-cols-4">
          {FEATURES.map((f, i) => (
            <div key={f.t} className="ax-rise group bg-card p-6 transition-colors hover:bg-secondary" style={{ animationDelay: `${0.5 + i * 0.07}s` }}>
              <f.i className="size-5 text-primary transition-transform group-hover:-translate-y-0.5" />
              <div className="mt-4 text-sm font-medium">{f.t}</div>
              <div className="mt-1 text-xs text-muted-foreground">{f.d}</div>
            </div>
          ))}
        </section>

        <section className="mb-20 flex flex-col items-center gap-5 text-center">
          <div className="text-2xl font-semibold tracking-tight">Run your first audit.</div>
          {cta}
        </section>
      </main>

      <footer className="relative border-t border-border py-6 text-center font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Armorix</footer>
      <AccountDialog open={open} onOpenChange={setOpen} />
    </div>
  );
}

function Node({ icon: I, label, accent }: { icon: typeof FileJson; label: string; accent?: boolean }) {
  return (
    <div className={`flex items-center gap-2.5 rounded-lg border px-3 py-2.5 text-xs ${accent ? "border-primary/40 bg-primary/10 text-foreground" : "border-border bg-background/60 text-muted-foreground"}`}>
      <I className={`size-4 shrink-0 ${accent ? "text-primary" : ""}`} />
      <span className="truncate">{label}</span>
    </div>
  );
}

function Wire() {
  return (
    <svg aria-hidden viewBox="0 0 60 120" preserveAspectRatio="none" className="hidden h-full w-full md:block">
      {[20, 60, 100].map((y) => <path key={y} d={`M0 ${y} C30 ${y} 30 60 60 60`} fill="none" stroke="var(--primary)" strokeOpacity=".6" strokeWidth="1.2" className="ax-flow" vectorEffect="non-scaling-stroke" />)}
    </svg>
  );
}

function Flow() {
  return (
    <div className="grid items-center gap-4 md:grid-cols-[1fr_48px_1fr_48px_1fr_48px_auto]">
      <div className="space-y-2">{INPUTS.map((n) => <Node key={n.l} icon={n.i} label={n.l} />)}</div>
      <Wire />
      <div className="relative flex flex-col items-center justify-center rounded-lg border border-border bg-background/60 p-4 text-center">
        <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">Static signals</div>
        <div className="mt-3 flex gap-1">{Array.from({ length: 8 }).map((_, i) => <span key={i} className="ax-pulse h-6 w-1.5 rounded-full bg-primary/70" style={{ animationDelay: `${i * 0.15}s` }} />)}</div>
      </div>
      <Wire />
      <div className="space-y-2">{AGENTS.map((n) => <Node key={n.l} icon={n.i} label={n.l} accent />)}</div>
      <Wire />
      <div className="flex flex-col items-center gap-2 rounded-lg border border-primary/40 bg-primary/10 px-5 py-4">
        <Logo className="h-8 w-8" />
        <div className="flex gap-1 font-mono text-[10px] uppercase">
          <span className="text-success">allow</span><span className="text-muted-foreground">·</span><span className="text-warning">review</span><span className="text-muted-foreground">·</span><span className="text-destructive">block</span>
        </div>
      </div>
    </div>
  );
}
