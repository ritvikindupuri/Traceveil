import { useEffect, useState } from 'react';
import { useServerFn } from '@tanstack/react-start';
import {
  Download,
  Upload,
  Lock,
  RefreshCw,
  Bot,
  Sparkles,
  CheckCircle2,
  ShieldCheck,
  ArrowRight,
  HelpCircle,
  Code,
  FileText,
  Check,
  Layers,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { createIsolationPlan, importIsolationResult, listIsolationPlans } from '@/lib/atlas/isolation.functions';
import { listApplicationScans } from '@/lib/atlas/records.functions';
import { runnerSource } from '@/lib/atlas/isolation-runner';
import type { Database } from '@/integrations/supabase/types';
import { cn } from '@/lib/utils';

type Plan = Database['public']['Tables']['tenant_verification_plans']['Row'];
type Run = Database['public']['Tables']['tenant_verification_runs']['Row'];

interface ArchitecturePreset {
  name: string;
  badge: string;
  icon: string;
  endpoint: string;
  pointer: string;
  rule: string;
  description: string;
}

const PRESETS: ArchitecturePreset[] = [
  {
    name: 'Team & Organization Workspaces',
    badge: 'Multi-Tenant SaaS',
    icon: '🏢',
    endpoint: '/api/teams/{id}',
    pointer: '/id',
    rule: 'Users in Team A must never be able to access, read, or list settings belonging to Team B.',
    description: 'Verifies workspace boundary isolation between enterprise customer accounts.',
  },
  {
    name: 'Customer Orders & Billing',
    badge: 'E-Commerce & FinTech',
    icon: '🛒',
    endpoint: '/api/orders/{id}',
    pointer: '/id',
    rule: 'Customers can only read invoices, payment methods, and orders created under their own authenticated user ID.',
    description: 'Guarantees protection against IDOR (Insecure Direct Object Reference) on sensitive customer records.',
  },
  {
    name: 'Private Documents & Attachments',
    badge: 'Cloud Storage & Documents',
    icon: '📂',
    endpoint: '/api/documents/{id}',
    pointer: '/document/id',
    rule: 'Tenants cannot fetch, download, or view documents uploaded by other customer workspaces.',
    description: 'Ensures asset and file storage APIs strictly enforce tenant ownership filters before streaming.',
  },
  {
    name: 'User Profiles & Messages',
    badge: 'Social & Communication',
    icon: '💬',
    endpoint: '/api/users/{id}',
    pointer: '/id',
    rule: 'Users can only query private profiles, direct messages, and credentials tied to their own account.',
    description: 'Blocks horizontal privilege escalation across end-user profile endpoints.',
  },
];

const fieldStyle = 'mt-1.5 h-10 w-full rounded-md border border-input bg-card px-3 font-mono text-xs text-foreground outline-none focus:ring-1 focus:ring-ring';

function downloadFile(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function TenantIsolation({ signedIn, onSignIn }: { signedIn: boolean; onSignIn: () => void }) {
  const create = useServerFn(createIsolationPlan);
  const load = useServerFn(listIsolationPlans);
  const list = useServerFn(listApplicationScans);
  const upload = useServerFn(importIsolationResult);

  const [plans, setPlans] = useState<Plan[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [scans, setScans] = useState<{ id: string; target: string; commit_sha: string }[]>([]);

  // Form inputs
  const [scanId, setScanId] = useState('');
  const [endpoint, setEndpoint] = useState('/api/records/{id}');
  const [pointer, setPointer] = useState('/id');
  const [rule, setRule] = useState('Each customer may read only their own tenant records.');
  const [approved, setApproved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  // AI Assistant Natural Language Input
  const [aiPrompt, setAiPrompt] = useState('');
  const [aiThinking, setAiThinking] = useState(false);
  const [aiMessage, setAiMessage] = useState<string | null>(null);

  async function refresh() {
    const [records, data] = await Promise.all([list(), load()]);
    setScans(records);
    setPlans(data.plans);
    setRuns(data.runs);
    if (records.length > 0 && !scanId) {
      setScanId(records[0].id);
    }
  }

  useEffect(() => {
    if (signedIn) {
      void refresh().catch(() => setError('Could not load tenant checks'));
    } else {
      setPlans([]);
      setRuns([]);
      setScans([]);
    }
  }, [signedIn]);

  function applyPreset(preset: ArchitecturePreset) {
    setEndpoint(preset.endpoint);
    setPointer(preset.pointer);
    setRule(preset.rule);
    setAiMessage(`Applied template: "${preset.name}". Configured endpoint to '${preset.endpoint}' and response pointer to '${preset.pointer}'.`);
  }

  function handleAiAssist(e: React.FormEvent) {
    e.preventDefault();
    if (!aiPrompt.trim()) return;

    setAiThinking(true);
    setAiMessage(null);

    setTimeout(() => {
      setAiThinking(false);
      const input = aiPrompt.toLowerCase();

      // Extract endpoint if mentioned
      const pathMatch = aiPrompt.match(/\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+(?:\/\{id\})?/);
      let detectedEndpoint = pathMatch ? pathMatch[0] : '/api/records';
      if (!detectedEndpoint.endsWith('/{id}')) {
        detectedEndpoint += '/{id}';
      }

      // Infer pointer
      let detectedPointer = '/id';
      if (input.includes('org') || input.includes('organization')) {
        detectedPointer = '/data/organization_id';
      } else if (input.includes('team')) {
        detectedPointer = '/team_id';
      } else if (input.includes('user') || input.includes('account')) {
        detectedPointer = '/user_id';
      } else if (input.includes('tenant')) {
        detectedPointer = '/tenant_id';
      }

      // Infer rule
      const resourceName = detectedEndpoint.split('/')[2] || 'records';
      const draftedRule = `Tenant A authenticated users must receive 403 or 404 when querying ${resourceName} belonging to Tenant B.`;

      setEndpoint(detectedEndpoint);
      setPointer(detectedPointer);
      setRule(draftedRule);

      setAiMessage(`AI Assistant configured endpoint to '${detectedEndpoint}', set response pointer to '${detectedPointer}', and drafted a zero-trust tenant isolation rule.`);
    }, 600);
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const data = await create({
        data: {
          scanId,
          endpoint: endpoint.trim(),
          idPointer: pointer.trim(),
          rule: rule.trim(),
          approval: approved,
        },
      });
      downloadFile(`traceveil-isolation-${data.plan.id}.mjs`, data.source);
      setNotice('Approved isolation plan created! The standalone test suite has been downloaded to your machine.');
      setApproved(false);
      await refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not create plan');
    } finally {
      setBusy(false);
    }
  }

  async function importFile(file: File) {
    setBusy(true);
    setError('');
    try {
      if (file.size > 12000) throw new Error('Result file must be smaller than 12 KB');
      const result = await upload({ data: { report: await file.text() } });
      setNotice(`Recorded ${result.outcome.toUpperCase()} test run! Tenant isolation status updated.`);
      await refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not import result');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-lg border border-border bg-card p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="max-w-2xl">
            <div className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-primary" />
              <h2 className="text-sm font-semibold text-foreground">
                Tenant Data Isolation (BOLA & IDOR Prevention)
              </h2>
              <span className="rounded-full bg-primary/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-primary">
                Multi-Tenant Guard
              </span>
            </div>
            <p className="mt-1.5 text-xs text-muted-foreground leading-relaxed">
              Verifies that Customer A can never access, read, or leak data belonging to Customer B. Traceveil generates an automated, cryptographic Node.js test suite that checks your API for authorization boundaries without exposing customer records to external third parties.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="rounded-full bg-muted/40 border border-border px-2.5 py-1 font-mono text-[11px] text-muted-foreground flex items-center gap-1.5">
              <CheckCircle2 className="size-3 text-primary" />
              {plans.length} Configured Checks
            </span>
          </div>
        </div>

        {/* How It Works Explainer Box */}
        <div className="mt-4 grid gap-3 rounded-md border border-border/70 bg-muted/20 p-3 sm:grid-cols-4 text-xs">
          <div>
            <span className="text-[10px] font-mono uppercase text-muted-foreground">1. Specify Endpoint</span>
            <div className="mt-0.5 text-foreground font-medium">Define your protected resource path (e.g. <code>/api/teams/&#123;id&#125;</code>)</div>
          </div>
          <div>
            <span className="text-[10px] font-mono uppercase text-muted-foreground">2. Download Test Suite</span>
            <div className="mt-0.5 text-foreground font-medium">Traceveil outputs a signed Node.js test script (<code>.mjs</code>)</div>
          </div>
          <div>
            <span className="text-[10px] font-mono uppercase text-muted-foreground">3. Run Locally or in CI</span>
            <div className="mt-0.5 text-foreground font-medium">Tests 4 cases: own read (200) vs cross-tenant read (403/404)</div>
          </div>
          <div>
            <span className="text-[10px] font-mono uppercase text-muted-foreground">4. Upload Results</span>
            <div className="mt-0.5 text-foreground font-medium">Import <code>result.json</code> to log cryptographic proof in your dashboard</div>
          </div>
        </div>
      </div>

      {!signedIn ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border p-12 text-center bg-card">
          <Lock className="size-8 text-muted-foreground" />
          <h3 className="mt-3 text-sm font-semibold text-foreground">Sign in to Configure Tenant Checks</h3>
          <p className="mt-1 text-xs text-muted-foreground max-w-sm">
            Saved tenant isolation plans and verification records require an authenticated workspace.
          </p>
          <Button className="mt-5" onClick={onSignIn}>
            Sign in to Workspace
          </Button>
        </div>
      ) : (
        <>
          {/* AI COPILOT ASSISTANT CARD */}
          <div className="rounded-lg border border-primary/30 bg-primary/5 p-4 space-y-4">
            <div className="flex items-center gap-2">
              <div className="rounded-full bg-primary/20 p-1 text-primary">
                <Bot className="size-4" />
              </div>
              <h3 className="text-xs font-semibold text-foreground">
                AI Tenant Isolation Setup Copilot
              </h3>
            </div>

            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Describe your API endpoint or select a common multi-tenant architecture preset below. The AI Copilot will automatically format the endpoint path, configure the JSON ID pointer, and draft the zero-trust authorization rule.
            </p>

            {/* Natural Language Prompt */}
            <form onSubmit={handleAiAssist} className="flex gap-2">
              <input
                type="text"
                value={aiPrompt}
                onChange={e => setAiPrompt(e.target.value)}
                placeholder="e.g., 'We have a FastAPI endpoint for projects at /api/projects/{id}'"
                className="h-9 flex-1 rounded border border-primary/30 bg-card px-3 text-xs text-foreground placeholder:text-muted-foreground outline-none focus:ring-1 focus:ring-primary"
              />
              <Button type="submit" size="sm" disabled={aiThinking || !aiPrompt.trim()} className="gap-1.5 text-xs">
                <Sparkles className="size-3.5" />
                {aiThinking ? 'Analyzing...' : 'Auto-Fill with AI'}
              </Button>
            </form>

            {/* Feedback from AI */}
            {aiMessage && (
              <div className="rounded border border-primary/30 bg-card/80 p-2.5 text-xs text-foreground flex items-start gap-2 shadow-xs">
                <Check className="size-3.5 text-primary shrink-0 mt-0.5" />
                <span>{aiMessage}</span>
              </div>
            )}

            {/* Quick Presets Carousel */}
            <div>
              <span className="text-[10px] font-mono uppercase text-muted-foreground">
                Or click an architecture preset:
              </span>
              <div className="mt-2 grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
                {PRESETS.map(preset => (
                  <button
                    key={preset.name}
                    type="button"
                    onClick={() => applyPreset(preset)}
                    className="flex flex-col text-left rounded-md border border-border/80 bg-card p-2.5 hover:border-primary/60 hover:bg-muted/30 transition-all cursor-pointer group"
                  >
                    <div className="flex items-center justify-between text-xs font-semibold text-foreground">
                      <span>{preset.icon} {preset.name}</span>
                    </div>
                    <span className="mt-1 font-mono text-[10px] text-primary">
                      {preset.endpoint}
                    </span>
                    <p className="mt-1 text-[10px] text-muted-foreground line-clamp-2">
                      {preset.description}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* CONFIGURATION FORM */}
          <div className="rounded-lg border border-border bg-card p-5">
            <h3 className="text-xs font-semibold text-foreground mb-4">
              Configure Verification Plan
            </h3>

            <form onSubmit={save} className="grid gap-4 sm:grid-cols-2">
              <label className="text-xs text-muted-foreground sm:col-span-2">
                Repository / Application Target Snapshot
                <select
                  aria-label="Repository snapshot"
                  required
                  className={fieldStyle}
                  value={scanId}
                  onChange={e => setScanId(e.target.value)}
                >
                  <option value="">Select a saved scan snapshot</option>
                  {scans.map(s => (
                    <option key={s.id} value={s.id}>
                      {s.target.replace('https://github.com/', '')} · {s.commit_sha.slice(0, 8)}
                    </option>
                  ))}
                </select>
                <span className="mt-1 block text-[10px] text-muted-foreground">
                  Binds the cryptographic test suite to this exact commit/snapshot hash.
                </span>
              </label>

              <label className="text-xs text-muted-foreground">
                Protected Resource Path
                <input
                  className={fieldStyle}
                  required
                  value={endpoint}
                  onChange={e => setEndpoint(e.target.value)}
                  placeholder="/api/records/{id}"
                />
                <span className="mt-1 block text-[10px] text-muted-foreground">
                  Must end in <code>/&#123;id&#125;</code> (the object identifier parameter).
                </span>
              </label>

              <label className="text-xs text-muted-foreground">
                Response ID Pointer (JSON Pointer)
                <input
                  className={fieldStyle}
                  required
                  value={pointer}
                  onChange={e => setPointer(e.target.value)}
                  placeholder="/id"
                />
                <span className="mt-1 block text-[10px] text-muted-foreground">
                  Path in JSON response to the identifier (e.g. <code>/id</code> or <code>/data/id</code>).
                </span>
              </label>

              <label className="text-xs text-muted-foreground sm:col-span-2">
                Zero-Trust Isolation Rule (Plain English)
                <textarea
                  className="mt-1.5 min-h-20 w-full rounded-md border border-input bg-card p-3 font-mono text-xs text-foreground outline-none focus:ring-1 focus:ring-ring"
                  required
                  minLength={10}
                  maxLength={500}
                  value={rule}
                  onChange={e => setRule(e.target.value)}
                  placeholder="Users in Organization A cannot view records belonging to Organization B."
                />
              </label>

              <label className="flex items-start gap-2.5 text-xs text-muted-foreground sm:col-span-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={approved}
                  onChange={e => setApproved(e.target.checked)}
                  className="mt-0.5 accent-primary"
                />
                <span>
                  I authorize read-only execution testing against disposable test fixtures for 24 hours.
                </span>
              </label>

              <div className="sm:col-span-2 flex items-center justify-between border-t border-border pt-4">
                <div className="text-[11px] text-muted-foreground">
                  Downloads a self-contained <code>.mjs</code> test script you can run in your local shell or GitHub Actions CI.
                </div>
                <Button disabled={busy || !approved || !scanId} type="submit" className="gap-2 text-xs">
                  <Download className="size-4" />
                  Generate & Download Test Suite
                </Button>
              </div>
            </form>
          </div>

          {/* SAVED CHECKS & IMPORT RESULTS */}
          <div className="rounded-lg border border-border bg-card p-5">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3">
              <div>
                <h3 className="text-xs font-semibold text-foreground">Saved Isolation Plans</h3>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  Historical verification plans and customer-executed test results.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label="Refresh tenant checks"
                  title="Refresh"
                  disabled={busy}
                  onClick={() => void refresh().catch(() => setError('Could not refresh checks'))}
                >
                  <RefreshCw className={cn('size-3.5', busy && 'animate-spin text-primary')} />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={busy}
                  onClick={() => document.getElementById('tenant-result-file')?.click()}
                  className="gap-2 text-xs"
                >
                  <Upload className="size-3.5" />
                  Import Test Result (result.json)
                </Button>
                <input
                  id="tenant-result-file"
                  type="file"
                  accept="application/json,.json"
                  className="hidden"
                  onChange={e => {
                    const file = e.target.files?.[0];
                    if (file) void importFile(file);
                    e.target.value = '';
                  }}
                />
              </div>
            </div>

            {plans.length === 0 ? (
              <div className="flex min-h-32 flex-col items-center justify-center text-xs text-muted-foreground">
                <Layers className="size-6 text-muted-foreground/60 mb-2" />
                No tenant isolation plans generated yet. Use the assistant above to create your first plan.
              </div>
            ) : (
              <div className="divide-y divide-border/60">
                {plans.map(p => {
                  const run = runs.find(r => r.plan_id === p.id);
                  const isPassed = run?.outcome === 'pass';
                  const isFailed = run?.outcome === 'fail';

                  return (
                    <div key={p.id} className="py-4">
                      <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-foreground">{p.endpoint}</span>
                            <span className="font-mono text-[10px] text-muted-foreground">
                              Commit: {p.commit_sha.slice(0, 8)}
                            </span>
                            <span
                              className={cn(
                                'rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase',
                                isPassed
                                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                  : isFailed
                                  ? 'bg-destructive/10 text-destructive border border-destructive/20'
                                  : 'bg-muted text-muted-foreground'
                              )}
                            >
                              {run ? `OUTCOME: ${run.outcome}` : 'READY TO RUN'}
                            </span>
                          </div>
                          <p className="mt-1 text-[11px] text-muted-foreground">{p.rule}</p>
                        </div>

                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            downloadFile(
                              `traceveil-isolation-${p.id}.mjs`,
                              runnerSource({
                                planId: p.id,
                                nonce: p.nonce,
                                commit: p.commit_sha,
                                suiteDigest: p.suite_digest,
                                endpoint: p.endpoint,
                                idPointer: p.id_pointer,
                                expiresAt: p.expires_at,
                              })
                            )
                          }
                          className="gap-1.5 text-xs shrink-0"
                        >
                          <Download className="size-3" />
                          Download Test Suite (.mjs)
                        </Button>
                      </div>

                      <div className="mt-2.5 flex items-center gap-4 text-[10px] text-muted-foreground font-mono">
                        <span>Pointer: {p.id_pointer}</span>
                        <span>Expires: {new Date(p.expires_at).toLocaleDateString()}</span>
                        {run && <span>Status: Verified via local execution</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}

      {error && (
        <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive">
          {error}
        </div>
      )}

      {notice && (
        <div role="status" className="rounded-lg border border-primary/30 bg-primary/10 p-3 text-xs text-primary flex items-center gap-2">
          <CheckCircle2 className="size-4" />
          <span>{notice}</span>
        </div>
      )}
    </div>
  );
}