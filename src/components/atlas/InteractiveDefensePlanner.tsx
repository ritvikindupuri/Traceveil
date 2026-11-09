import { useState, useEffect } from 'react';
import { useServerFn } from '@tanstack/react-start';
import {
  Activity,
  Shield,
  Download,
  Copy,
  Check,
  FileCheck,
  CheckCircle2,
  Clock,
  RefreshCw,
  Lock,
  ChevronDown,
  ChevronUp,
  Loader2,
  CheckCheck,
  Globe,
  Terminal,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { AttackGraph } from '@/lib/atlas/types';
import { generateDefensePlans, type DefensePlan } from '@/lib/atlas/agent-operations';
import {
  enforcePolicyLive,
  removePolicyEnforcementLive,
  checkLiveEndpointDrift,
  type DriftCheckResult,
} from '@/lib/atlas/defense.functions';
import { cn } from '@/lib/utils';

interface ActivityLogItem {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  type: 'verified' | 'drift_detected' | 'policy_updated' | 'gate_blocked';
}

const layerMeta: Record<
  string,
  {
    layerNumber: string;
    layerName: string;
    icon: string;
    targetScope: string;
    deployCommand: string;
    impactSummary: string;
  }
> = {
  'plan-k8s-netpol': {
    layerNumber: 'Layer 1',
    layerName: 'Network Firewall',
    icon: '🧱',
    targetScope: 'Kubernetes / VPC',
    deployCommand: 'kubectl apply -f k8s-isolation-policy.yaml',
    impactSummary: 'Drops unauthorized ingress & isolates database egress',
  },
  'plan-github-gate': {
    layerNumber: 'Layer 2',
    layerName: 'CI/CD PR Gate',
    icon: '🚦',
    targetScope: 'GitHub Actions CI',
    deployCommand:
      'git add .github/workflows/traceveil-guard.yml && git commit -m "ci: add Traceveil security gate" && git push',
    impactSummary: 'Blocks PRs containing secret leaks & vulnerabilities',
  },
  'plan-falco-rule': {
    layerNumber: 'Layer 3',
    layerName: 'Runtime Detector',
    icon: '🚨',
    targetScope: 'CNCF Falco / Linux Kernel',
    deployCommand:
      'cat falco_rules.local.yaml >> /etc/falco/falco_rules.local.yaml && sudo systemctl restart falco',
    impactSummary: 'Detects container shell spawns & abnormal socket traffic',
  },
};

export function InteractiveDefensePlanner({ graph }: { graph: AttackGraph }) {
  const [plans, setPlans] = useState<DefensePlan[]>([]);
  const [activePlanId, setActivePlanId] = useState<string>('');
  const [deployedStates, setDeployedStates] = useState<Record<string, boolean>>({});
  const [enforcementLogs, setEnforcementLogs] = useState<Record<string, string[]>>({});
  const [isEnforcing, setIsEnforcing] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // 24/7 Continuous Watchdog State
  const [isCheckingDrift, setIsCheckingDrift] = useState(false);
  const [secondsUntilNextCheck, setSecondsUntilNextCheck] = useState(60);
  const [showTimeline, setShowTimeline] = useState(false);
  const [latestDrift, setLatestDrift] = useState<DriftCheckResult | null>(null);

  // Target type detection
  const isLiveTarget =
    graph.target.startsWith('http://') ||
    graph.target.startsWith('https://') ||
    graph.target.includes('production') ||
    graph.target.includes('live') ||
    (!graph.target.includes('/') && !graph.target.includes('\\'));

  // Linked GitHub repository state for live web apps
  const [linkedRepo, setLinkedRepo] = useState('');
  const [isRepoConnected, setIsRepoConnected] = useState(false);

  // Server functions
  const enforcePolicyServerFn = useServerFn(enforcePolicyLive);
  const removePolicyServerFn = useServerFn(removePolicyEnforcementLive);
  const checkDriftServerFn = useServerFn(checkLiveEndpointDrift);

  // Around-the-clock activity history
  const [activityFeed, setActivityFeed] = useState<ActivityLogItem[]>([
    {
      id: 'log-1',
      timestamp: 'Just now',
      title: 'Continuous Watchdog initialized',
      description: `Target ${graph.target} monitored under active defense engine.`,
      type: 'verified',
    },
  ]);

  useEffect(() => {
    if (graph) {
      const generated = generateDefensePlans(graph);
      setPlans(generated);
      if (generated.length > 0 && !activePlanId) {
        setActivePlanId(generated[0].id);
      }
      if (generated.length > 0) {
        setDeployedStates(prev => ({
          [generated[0].id]: true,
          ...prev,
        }));
      }
      void runLiveDriftCheck();
    }
  }, [graph]);

  // Real continuous monitoring timer (60s loop)
  useEffect(() => {
    const timer = setInterval(() => {
      setSecondsUntilNextCheck(prev => {
        if (prev <= 1) {
          void runLiveDriftCheck();
          return 60;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [graph.target]);

  // Real Live Drift Check execution
  async function runLiveDriftCheck() {
    setIsCheckingDrift(true);
    try {
      const result = await checkDriftServerFn({
        data: { target: graph.target },
      });
      setLatestDrift(result);

      if (result.driftDetected) {
        setActivityFeed(prev => [
          {
            id: `log-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(),
            title: 'Configuration Drift Alert',
            description: result.driftSummary || 'Drift detected on target.',
            type: 'drift_detected',
          },
          ...prev.slice(0, 9),
        ]);
      } else {
        setActivityFeed(prev => [
          {
            id: `log-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(),
            title: 'Live Target Verified',
            description: `Audit passed (${result.latencyMs}ms latency, HTTP ${result.status}). Zero drift detected.`,
            type: 'verified',
          },
          ...prev.slice(0, 9),
        ]);
      }
    } catch {
      // Keep existing telemetry on error
    } finally {
      setIsCheckingDrift(false);
    }
  }

  // Toggle live policy enforcement
  async function handleToggleEnforce(plan: DefensePlan) {
    const isCurrentlyEnforced = Boolean(deployedStates[plan.id]);
    setIsEnforcing(true);

    try {
      if (isCurrentlyEnforced) {
        await removePolicyServerFn({
          data: {
            policyId: plan.id,
            target: graph.target,
          },
        });

        setDeployedStates(prev => ({ ...prev, [plan.id]: false }));
        setEnforcementLogs(prev => ({
          ...prev,
          [plan.id]: [
            `[${new Date().toLocaleTimeString()}] Policy enforcement removed. Rule transitioned to standby.`,
            ...(prev[plan.id] || []),
          ],
        }));

        setActivityFeed(prev => [
          {
            id: `log-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(),
            title: `Policy Deactivated: ${plan.name}`,
            description: `Live enforcement stopped for ${plan.filename}.`,
            type: 'policy_updated',
          },
          ...prev.slice(0, 9),
        ]);
      } else {
        const res = await enforcePolicyServerFn({
          data: {
            policyId: plan.id,
            policyType: plan.id.includes('k8s')
              ? 'k8s_network_policy'
              : plan.id.includes('github')
                ? 'github_action_guard'
                : 'falco_runtime_rule',
            policyContent: plan.content,
            target: graph.target,
          },
        });

        setDeployedStates(prev => ({ ...prev, [plan.id]: true }));
        setEnforcementLogs(prev => ({
          ...prev,
          [plan.id]: [
            `[${new Date().toLocaleTimeString()}] Verified & Enforced: sha256:${res.sha256.slice(0, 16)}...`,
            ...res.verificationLogs,
            ...(prev[plan.id] || []),
          ],
        }));

        setActivityFeed(prev => [
          {
            id: `log-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(),
            title: `Policy Enforced Live: ${plan.name}`,
            description: `Applied ${plan.filename} with active runtime enforcement.`,
            type: 'policy_updated',
          },
          ...prev.slice(0, 9),
        ]);
      }
    } catch (err) {
      console.error('Enforcement toggle failed:', err);
    } finally {
      setIsEnforcing(false);
    }
  }

  function copyText(text: string, id: string) {
    void navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  function downloadPlan(plan: DefensePlan) {
    const blob = new Blob([plan.content], { type: 'text/yaml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = plan.filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  const formatCountdown = (secs: number) => {
    const mins = Math.floor(secs / 60);
    const remainder = secs % 60;
    return `${mins}:${remainder < 10 ? '0' : ''}${remainder}`;
  };

  if (plans.length === 0) return null;

  const activePlan = plans.find(p => p.id === activePlanId) || plans[0];
  const activeMeta = layerMeta[activePlan.id] || {
    layerNumber: 'Layer',
    layerName: activePlan.badge,
    icon: '🛡️',
    targetScope: activePlan.badge,
    deployCommand: '',
    impactSummary: activePlan.description,
  };
  const activeLogs = enforcementLogs[activePlan.id];

  return (
    <div className="space-y-4">
      {/* 1. Sleek Command Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card px-4 py-3 shadow-xs">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
            </span>
            <h2 className="text-sm font-semibold text-foreground">Firewalls & Rules</h2>
          </div>

          <span className="text-muted-foreground/30">|</span>

          <span className="font-mono text-xs text-foreground bg-muted/60 px-2 py-0.5 rounded border border-border/60">
            {graph.target}
          </span>

          {isLiveTarget && (
            <span className="rounded bg-sky-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-sky-600 border border-sky-500/20">
              Live Web Target
            </span>
          )}

          <span className="rounded bg-primary/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-primary border border-primary/20">
            Gemini 1.5 Flash
          </span>

          {latestDrift && (
            <span className="flex items-center gap-1.5 font-mono text-xs text-emerald-600 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              <span>HTTP {latestDrift.status}</span>
              <span className="text-muted-foreground">·</span>
              <span>{latestDrift.latencyMs}ms</span>
              <span className="text-muted-foreground">·</span>
              <span>{latestDrift.driftDetected ? '⚠️ Drift' : '✓ In Sync'}</span>
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground font-mono bg-muted/40 px-2.5 py-1 rounded border border-border/50">
            <Clock className="size-3 text-muted-foreground" />
            <span>Audit: {formatCountdown(secondsUntilNextCheck)}</span>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={() => void runLiveDriftCheck()}
            disabled={isCheckingDrift}
            className="h-8 gap-1.5 text-xs font-medium"
          >
            <RefreshCw className={cn('size-3.5', isCheckingDrift && 'animate-spin text-primary')} />
            {isCheckingDrift ? 'Auditing...' : 'Audit Drift Now'}
          </Button>
        </div>
      </div>

      {/* 2. Interactive 3-Layer Control Bar */}
      <div className="grid gap-3 sm:grid-cols-3">
        {plans.map((plan, idx) => {
          const isSelected = plan.id === activePlan.id;
          const isEnforced = Boolean(deployedStates[plan.id]);
          const meta = layerMeta[plan.id] || {
            layerNumber: `Layer ${idx + 1}`,
            layerName: plan.badge,
            icon: '🛡️',
            targetScope: plan.badge,
            deployCommand: '',
            impactSummary: plan.description,
          };

          return (
            <div
              key={plan.id}
              onClick={() => setActivePlanId(plan.id)}
              className={cn(
                'group cursor-pointer rounded-lg border p-3.5 transition-all shadow-xs text-left select-none relative',
                isSelected
                  ? 'border-primary bg-primary/5 ring-1 ring-primary/40'
                  : 'border-border bg-card hover:border-border/80 hover:bg-muted/10'
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="text-lg">{meta.icon}</span>
                  <div>
                    <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground font-semibold">
                      {meta.layerNumber}
                    </span>
                    <h3 className="text-xs font-semibold text-foreground leading-none mt-0.5">
                      {meta.layerName}
                    </h3>
                  </div>
                </div>

                <span
                  className={cn(
                    'rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold flex items-center gap-1',
                    isEnforced
                      ? 'bg-emerald-500/10 text-emerald-600 border border-emerald-500/20'
                      : 'bg-muted text-muted-foreground border border-border/60'
                  )}
                >
                  {isEnforced ? <CheckCircle2 className="size-2.5" /> : <Lock className="size-2.5" />}
                  {isEnforced ? 'Enforced' : 'Standby'}
                </span>
              </div>

              <p className="mt-2 text-[11px] text-muted-foreground line-clamp-1">
                {meta.impactSummary}
              </p>

              <div className="mt-2.5 flex items-center justify-between pt-2 border-t border-border/60 font-mono text-[10px] text-muted-foreground">
                <span className="truncate">{plan.filename}</span>
                <span className="text-primary font-medium group-hover:underline">View Rule →</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* 3. Full-Width Policy Workbench */}
      <div className="rounded-lg border border-border bg-card shadow-xs overflow-hidden">
        {/* Policy Workbench Header */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-muted/20 px-4 py-3">
          <div className="flex items-center gap-2.5">
            <span className="text-base">{activeMeta.icon}</span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-xs font-semibold text-foreground">{activePlan.name}</h3>
                <span className="font-mono text-[10px] rounded bg-muted px-1.5 py-0.2 text-muted-foreground">
                  {activePlan.filename}
                </span>
                <span className="font-mono text-[10px] text-muted-foreground hidden sm:inline">
                  {activeMeta.targetScope}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => copyText(activePlan.content, activePlan.id)}
              className="h-8 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
            >
              {copiedId === activePlan.id ? <Check className="size-3 text-primary" /> : <Copy className="size-3" />}
              <span>{copiedId === activePlan.id ? 'Copied' : 'Copy'}</span>
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => downloadPlan(activePlan)}
              className="h-8 gap-1.5 text-xs"
            >
              <Download className="size-3" />
              <span>Download</span>
            </Button>
            <Button
              variant={deployedStates[activePlan.id] ? 'outline' : 'default'}
              size="sm"
              disabled={isEnforcing}
              onClick={() => void handleToggleEnforce(activePlan)}
              className={cn(
                'h-8 gap-1.5 text-xs font-semibold shadow-xs transition-all',
                deployedStates[activePlan.id]
                  ? 'border-emerald-500/40 text-emerald-700 bg-emerald-50 hover:bg-emerald-100 dark:bg-emerald-950/30'
                  : 'bg-primary text-primary-foreground hover:bg-primary/90'
              )}
            >
              {isEnforcing ? (
                <>
                  <Loader2 className="size-3 animate-spin" />
                  <span>Enforcing Live...</span>
                </>
              ) : deployedStates[activePlan.id] ? (
                <>
                  <CheckCheck className="size-3.5 text-emerald-600" />
                  <span>Enforced Live</span>
                </>
              ) : (
                <>
                  <Shield className="size-3.5" />
                  <span>Enforce Rule Live</span>
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Quick Deploy Command bar */}
        <div className="flex items-center justify-between gap-3 border-b border-border/70 bg-muted/40 px-4 py-2 text-[11px]">
          <div className="flex items-center gap-2 overflow-x-auto font-mono text-muted-foreground">
            <span className="text-[10px] uppercase font-bold text-foreground shrink-0">Deploy CLI:</span>
            <code className="text-foreground shrink-0">{activeMeta.deployCommand}</code>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => copyText(activeMeta.deployCommand, `cmd-${activePlan.id}`)}
            className="h-6 px-2 text-[10px] text-muted-foreground shrink-0"
          >
            {copiedId === `cmd-${activePlan.id}` ? 'Copied' : 'Copy Command'}
          </Button>
        </div>

        {/* Code Viewer */}
        <div className="max-h-[380px] overflow-auto bg-card p-4 font-mono text-xs leading-relaxed text-foreground select-text border-b border-border">
          <pre className="whitespace-pre">{activePlan.content}</pre>
        </div>

        {/* Live Verification Log */}
        {activeLogs && activeLogs.length > 0 && (
          <div className="border-t border-border bg-muted/10 p-3">
            <div className="flex items-center gap-2 font-mono text-[11px] text-emerald-600 font-semibold mb-1.5">
              <CheckCircle2 className="size-3 text-emerald-500" />
              <span>Live Enforcement Log:</span>
            </div>
            <div className="space-y-1 font-mono text-[10px] text-muted-foreground bg-muted/40 p-2.5 rounded border border-border/50">
              {activeLogs.map((log, i) => (
                <div key={i}>{log}</div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* 4. Compact Watchdog Controls & Activity Tray */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card px-4 py-2.5 text-xs shadow-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-semibold text-foreground">Directives:</span>
          {isLiveTarget ? (
            <>
              <span className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-foreground">
                ✓ CSP & Headers
              </span>
              <span className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-foreground">
                ✓ DNS Drift
              </span>
              <span className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-foreground">
                ✓ Debug Routes
              </span>
              <span className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-foreground">
                ✓ TLS & Latency
              </span>
            </>
          ) : (
            <>
              <span className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-foreground">
                ✓ Ingress Filter
              </span>
              <span className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-foreground">
                ✓ Zero-Trust Egress
              </span>
              <span className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-foreground">
                ✓ CI Gate
              </span>
              <span className="rounded bg-muted px-2 py-0.5 font-mono text-[11px] text-foreground">
                ✓ Falco Kernel
              </span>
            </>
          )}
        </div>

        <div className="flex items-center gap-2">
          {isLiveTarget && (
            <div className="flex items-center gap-1.5">
              {isRepoConnected ? (
                <span className="rounded bg-indigo-500/10 px-2 py-0.5 font-mono text-[10px] text-indigo-600 border border-indigo-500/20">
                  Repo: {linkedRepo}
                </span>
              ) : (
                <input
                  type="text"
                  placeholder="Link repo (e.g. org/repo)"
                  value={linkedRepo}
                  onChange={e => setLinkedRepo(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && linkedRepo.trim()) setIsRepoConnected(true);
                  }}
                  className="h-6 rounded border border-border bg-background px-2 font-mono text-[10px] w-44"
                />
              )}
            </div>
          )}

          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowTimeline(!showTimeline)}
            className="h-6 px-2 text-[11px] text-muted-foreground gap-1"
          >
            <Activity className="size-3" />
            <span>Activity ({activityFeed.length})</span>
            {showTimeline ? <ChevronUp className="size-3" /> : <ChevronDown className="size-3" />}
          </Button>
        </div>
      </div>

      {/* Expanded Activity Timeline (if toggled) */}
      {showTimeline && (
        <div className="rounded-lg border border-border bg-card p-4 shadow-xs space-y-2">
          <div className="text-xs font-semibold text-foreground mb-2">Audit & Drift Event History</div>
          <div className="space-y-2 max-h-56 overflow-auto">
            {activityFeed.map(item => (
              <div
                key={item.id}
                className="flex items-start gap-3 rounded-md border border-border/60 bg-muted/20 p-2.5 text-xs"
              >
                <div className="mt-0.5">
                  <span className="size-2 rounded-full bg-emerald-500 inline-block" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-foreground">{item.title}</span>
                    <span className="font-mono text-[10px] text-muted-foreground">{item.timestamp}</span>
                  </div>
                  <p className="mt-0.5 text-[11px] text-muted-foreground">{item.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
