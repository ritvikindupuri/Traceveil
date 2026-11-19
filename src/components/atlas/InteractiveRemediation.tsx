import { useState, useEffect } from 'react';
import { useServerFn } from '@tanstack/react-start';
import {
  Wrench,
  CheckCircle2,
  Copy,
  Download,
  Check,
  Sparkles,
  FileCode,
  ShieldCheck,
  Terminal,
  Layers,
  Code2,
  ArrowRight,
  ChevronDown,
  ShieldAlert,
  Globe,
  Database,
  Server,
  Radio,
  HardDrive,
  Cpu,
  Lock,
  GitPullRequest,
  GitBranch,
  ExternalLink,
  AlertTriangle,
  Loader2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { AttackGraph } from '@/lib/atlas/types';
import { generateRemediationPatches, type RemediationPatch } from '@/lib/atlas/agent-operations';
import { generateCorrectedDrawIoXml, getArchitecturalRemediationGuide } from '@/lib/atlas/corrected-diagram';
import { decodeXmlEntities, sanitizeComponentName } from '@/lib/atlas/clean-text';
import { executeLiveRemediationPR, type LiveRemediationResult } from '@/lib/atlas/remediation.functions';
import { cn } from '@/lib/utils';

function getTopologyNodeIcon(label: string) {
  const l = (label || '').toLowerCase();
  if (l.includes('internet') || l.includes('public') || l.includes('user') || l.includes('client') || l.includes('world') || l.includes('external')) return Globe;
  if (l.includes('waf') || l.includes('shield') || l.includes('firewall') || l.includes('guard')) return ShieldCheck;
  if (l.includes('database') || l.includes('rds') || l.includes('sql') || l.includes('postgres') || l.includes('mysql') || l.includes('mongo') || l.includes('dynamo')) return Database;
  if (l.includes('storage') || l.includes('s3') || l.includes('bucket') || l.includes('blob') || l.includes('disk')) return HardDrive;
  if (l.includes('load balancer') || l.includes('alb') || l.includes('nlb') || l.includes('gateway') || l.includes('proxy')) return Layers;
  if (l.includes('traffic') || l.includes('route') || l.includes('edge') || l.includes('dns') || l.includes('stream') || l.includes('ingress')) return Radio;
  if (l.includes('lambda') || l.includes('compute') || l.includes('container') || l.includes('k8s') || l.includes('pod') || l.includes('backend') || l.includes('app') || l.includes('workload')) return Cpu;
  if (l.includes('auth') || l.includes('iam') || l.includes('secret') || l.includes('key')) return Lock;
  return Server;
}

function parseTopologyNode(rawNode: string) {
  const clean = decodeXmlEntities(rawNode);

  // Check for [Private Subnet (...)] prefix
  const subnetMatch = clean.match(/^\[([^\]]+)\]\s*(.*)$/);
  if (subnetMatch) {
    return {
      prefix: subnetMatch[1],
      label: subnetMatch[2],
      isSubnet: true,
    };
  }

  // Check for (Exposed Public IP) suffix
  const exposedMatch = clean.match(/^(.*?)\s*\((Exposed Public IP|Public Reads Allowed)\)$/i);
  if (exposedMatch) {
    return {
      label: exposedMatch[1],
      suffix: exposedMatch[2],
      isExposed: true,
    };
  }

  return { label: clean };
}

function DiagramRemediationStudio({
  graph,
  patches,
}: {
  graph: AttackGraph;
  patches: RemediationPatch[];
}) {
  const findings = graph.findings || [];
  const [selectedPatchId, setSelectedPatchId] = useState<string>(patches[0]?.id || '');

  function downloadCorrectedDrawIoDiagram() {
    const xml = generateCorrectedDrawIoXml(graph);
    const blob = new Blob([xml], { type: 'application/xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const baseName = graph.target.replace('diagram://', '').replace(/\.(drawio|xml|pkt)$/, '') || 'architecture';
    a.download = `traceveil-hardened-${baseName}.drawio`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const activePatch = patches.find(p => p.id === selectedPatchId) || patches[0];
  const activeFinding = findings.find(f => f.id === activePatch?.findingId);
  const guide = activeFinding
    ? getArchitecturalRemediationGuide(activeFinding.rule || 'database-exposure', activePatch?.title || '')
    : null;

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* 1. Single Clean Header with ONE prominent Download Button */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-5 shadow-xs">
        <div className="flex items-center gap-3.5">
          <div className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-emerald-500/15 text-emerald-600 ring-1 ring-emerald-500/30">
            <CheckCircle2 className="size-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-semibold text-foreground">
                Hardened Architecture Diagram Ready
              </h2>
              <span className="rounded bg-emerald-500/15 px-2 py-0.5 font-mono text-[9px] font-bold text-emerald-600 uppercase">
                {findings.length} Fixes Applied
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              All architectural faults have been resolved with Zero-Trust boundaries (private subnets, WAF, public access blocks).
            </p>
          </div>
        </div>

        <Button
          size="default"
          onClick={downloadCorrectedDrawIoDiagram}
          className="gap-2 text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white shadow-md h-10 px-5"
        >
          <Download className="size-4" />
          <span>Download Corrected draw.io (.drawio)</span>
        </Button>
      </div>

      {/* 2. Clean Fix Selector Pills (One-click toggle between fixes) */}
      {patches.length > 0 && (
        <div className="space-y-2">
          <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
            Architectural Fixes Applied in Download
          </span>
          <div className="flex flex-wrap gap-2">
            {patches.map((p, idx) => {
              const isSelected = p.id === (activePatch?.id || '');
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setSelectedPatchId(p.id)}
                  className={cn(
                    "flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs transition border font-medium",
                    isSelected
                      ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 ring-1 ring-emerald-500/30 shadow-xs"
                      : "border-border bg-card hover:bg-muted/40 text-muted-foreground"
                  )}
                >
                  <span className="flex size-5 items-center justify-center rounded-full bg-muted text-[10px] font-mono">
                    {idx + 1}
                  </span>
                  <span>{p.title}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* 3. Selected Fix: Clean Before vs After Topology Comparison */}
      {guide && (
        <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-xs">
          <div className="flex items-center justify-between border-b border-border/80 pb-3">
            <div>
              <h3 className="text-sm font-bold text-foreground">
                {activePatch?.title}
              </h3>
              <p className="text-xs text-muted-foreground mt-0.5">
                {activePatch?.suggestion}
              </p>
            </div>
            <span className="rounded bg-emerald-500/15 px-2 py-0.5 font-mono text-[9px] font-bold text-emerald-600 uppercase">
              Corrected in Export
            </span>
          </div>

          {/* Side by side Before / After flow */}
          <div className="grid gap-4 md:grid-cols-2">
            {/* Before Card */}
            <div className="rounded-xl border border-destructive/30 bg-destructive/[0.03] p-4 space-y-3 shadow-xs">
              <div className="flex items-center justify-between border-b border-destructive/15 pb-2.5">
                <span className="text-xs font-bold text-destructive flex items-center gap-1.5">
                  <ShieldAlert className="size-4" />
                  Before (Original Diagram)
                </span>
                <span className="rounded bg-destructive/15 px-1.5 py-0.5 text-[9px] font-bold text-destructive uppercase tracking-wider">
                  Vulnerable
                </span>
              </div>

              {/* Clean Node Flow Sequence */}
              <div className="flex flex-wrap items-center gap-2 py-1">
                {guide.beforeTopology.nodes.map((node, nIdx) => {
                  const isLast = nIdx === guide.beforeTopology.nodes.length - 1;
                  const parsed = parseTopologyNode(node);
                  const NodeIcon = getTopologyNodeIcon(parsed.label);

                  return (
                    <div key={nIdx} className="flex items-center gap-2">
                      <div
                        className={cn(
                          "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all",
                          isLast
                            ? "border-destructive/40 bg-destructive/15 text-destructive font-semibold shadow-xs"
                            : "border-border/80 bg-background text-foreground/90 shadow-2xs"
                        )}
                      >
                        <NodeIcon
                          className={cn(
                            "size-3.5 shrink-0",
                            isLast ? "text-destructive" : "text-muted-foreground"
                          )}
                        />
                        <span className="truncate max-w-[220px]">{parsed.label}</span>
                        {parsed.suffix && (
                          <span className="rounded bg-destructive/20 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-destructive">
                            {parsed.suffix}
                          </span>
                        )}
                      </div>
                      {!isLast && (
                        <ArrowRight className="size-3.5 text-destructive/60 shrink-0" />
                      )}
                    </div>
                  );
                })}
              </div>

              <div className="rounded-lg bg-destructive/10 p-2.5 border border-destructive/20 text-xs text-destructive leading-relaxed">
                <span className="font-semibold">Risk Impact: </span>
                <span>{guide.beforeTopology.riskCallout}</span>
              </div>
            </div>

            {/* After Card */}
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/[0.03] p-4 space-y-3 shadow-xs">
              <div className="flex items-center justify-between border-b border-emerald-500/20 pb-2.5">
                <span className="text-xs font-bold text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                  <ShieldCheck className="size-4" />
                  After (Zero-Trust Remediated)
                </span>
                <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-[9px] font-bold text-emerald-600 uppercase tracking-wider">
                  Secured
                </span>
              </div>

              {/* Clean Node Flow Sequence */}
              <div className="flex flex-wrap items-center gap-2 py-1">
                {guide.afterTopology.nodes.map((node, nIdx) => {
                  const isLast = nIdx === guide.afterTopology.nodes.length - 1;
                  const parsed = parseTopologyNode(node);
                  const NodeIcon = getTopologyNodeIcon(parsed.label);

                  return (
                    <div key={nIdx} className="flex items-center gap-2">
                      <div
                        className={cn(
                          "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all",
                          isLast
                            ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-800 dark:text-emerald-300 font-semibold shadow-xs"
                            : "border-border/80 bg-background text-foreground/90 shadow-2xs"
                        )}
                      >
                        <NodeIcon
                          className={cn(
                            "size-3.5 shrink-0",
                            isLast ? "text-emerald-600 dark:text-emerald-400" : "text-emerald-600/70 dark:text-emerald-400/70"
                          )}
                        />
                        {parsed.prefix && (
                          <span className="rounded bg-emerald-500/25 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-emerald-800 dark:text-emerald-200">
                            {parsed.prefix}
                          </span>
                        )}
                        <span className="truncate max-w-[220px]">{parsed.label}</span>
                      </div>
                      {!isLast && (
                        <ArrowRight className="size-3.5 text-emerald-600/60 shrink-0" />
                      )}
                    </div>
                  );
                })}
              </div>

              <div className="rounded-lg bg-emerald-500/10 p-2.5 border border-emerald-500/20 text-xs text-emerald-800 dark:text-emerald-300 leading-relaxed">
                <span className="font-semibold">Security Benefit: </span>
                <span>{guide.afterTopology.benefitCallout}</span>
              </div>
            </div>
          </div>

          {/* Manual steps in collapsed details */}
          <details className="group rounded-lg border border-border/80 bg-muted/20 p-3 text-xs">
            <summary className="flex cursor-pointer list-none items-center justify-between text-muted-foreground hover:text-foreground font-medium">
              <span>How to make this change manually in diagrams.net / draw.io (Optional)</span>
              <ChevronDown className="size-4 transition-transform group-open:rotate-180" />
            </summary>
            <ol className="mt-3 space-y-1.5 pl-4 list-decimal text-muted-foreground text-[11px]">
              {guide.drawIoSteps.map((step, sIdx) => (
                <li key={sIdx}>{step}</li>
              ))}
            </ol>
          </details>
        </div>
      )}
    </div>
  );
}

function CodeRemediationStudio({
  graph,
  patches,
}: {
  graph: AttackGraph;
  patches: RemediationPatch[];
}) {
  const [selectedPatchId, setSelectedPatchId] = useState<string>(patches[0]?.id || '');
  const [appliedState, setAppliedState] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // GitHub Repository Binding (Auto-detected for GitHub scans, configurable for Live Web Apps)
  const isGithubTarget = graph.target.includes('github.com');
  const [repoUrl, setRepoUrl] = useState<string>(() => {
    if (isGithubTarget) return graph.target;
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem(`traceveil_linked_repo_${graph.target}`);
      if (saved) return saved;
    }
    return '';
  });
  const [isEditingRepo, setIsEditingRepo] = useState(false);
  const [savedRepoNotice, setSavedRepoNotice] = useState(false);

  // PR Generation State
  const executePRServerFn = useServerFn(executeLiveRemediationPR);
  const [runningPatchId, setRunningPatchId] = useState<string | null>(null);
  const [batchRunning, setBatchRunning] = useState(false);
  const [prResults, setPrResults] = useState<Record<string, LiveRemediationResult>>({});
  const [customToken, setCustomToken] = useState('');
  const [showTokenInput, setShowTokenInput] = useState(false);

  const appliedCount = Object.values(appliedState).filter(Boolean).length;
  const totalCount = patches.length;
  const progressPercent = totalCount > 0 ? Math.round((appliedCount / totalCount) * 100) : 100;

  const activePatch = patches.find(p => p.id === selectedPatchId) || patches[0];
  const isApplied = Boolean(appliedState[activePatch?.id]);
  const activePRResult = activePatch ? prResults[activePatch.id] : undefined;

  const cleanRepoName = repoUrl
    .trim()
    .replace(/^https?:\/\/github\.com\//, '')
    .replace(/^git@github\.com:/, '')
    .replace(/\.git$/, '')
    .replace(/\/$/, '') || 'your-org/your-repo';

  function saveLinkedRepo(url: string) {
    const trimmed = url.trim();
    setRepoUrl(trimmed);
    if (typeof window !== 'undefined') {
      localStorage.setItem(`traceveil_linked_repo_${graph.target}`, trimmed);
    }
    setIsEditingRepo(false);
    setSavedRepoNotice(true);
    setTimeout(() => setSavedRepoNotice(false), 2500);
  }

  async function handleCreatePR(patch: RemediationPatch) {
    const effectiveRepo = repoUrl.trim();
    if (!effectiveRepo) {
      setIsEditingRepo(true);
      return;
    }

    setRunningPatchId(patch.id);
    try {
      const res = await executePRServerFn({
        data: {
          repoUrl: effectiveRepo,
          patchId: patch.id,
          title: patch.title,
          filePath: patch.filePath,
          line: patch.line,
          diff: patch.diff,
          remediatedCode: patch.remediatedCode,
          customToken: customToken.trim() || undefined,
        },
      });
      setPrResults(prev => ({ ...prev, [patch.id]: res }));
      if (res.ok && res.isRealPR) {
        setAppliedState(prev => ({ ...prev, [patch.id]: true }));
      }
    } catch (err: unknown) {
      setPrResults(prev => ({
        ...prev,
        [patch.id]: {
          ok: false,
          isRealPR: false,
          prUrl: `https://github.com/${cleanRepoName}/pulls`,
          branchName: 'failed',
          commitSha: 'failed',
          logs: [
            {
              type: 'error',
              output: [err instanceof Error ? err.message : 'Failed to execute PR agent.'],
            },
          ],
          status: 'failed',
          error: err instanceof Error ? err.message : 'Unknown error during PR creation',
        },
      }));
    } finally {
      setRunningPatchId(null);
    }
  }

  async function handleCreateAllPRs() {
    if (!repoUrl.trim()) {
      setIsEditingRepo(true);
      return;
    }
    setBatchRunning(true);
    for (const p of patches) {
      await handleCreatePR(p);
    }
    setBatchRunning(false);
  }

  function toggleApply(patchId: string) {
    setAppliedState(prev => ({
      ...prev,
      [patchId]: !prev[patchId],
    }));
  }

  function copyDiff(diff: string, id: string) {
    void navigator.clipboard.writeText(diff);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  function downloadPatch(patch: RemediationPatch) {
    const blob = new Blob([patch.diff], { type: 'text/x-diff' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `traceveil-${patch.id}.patch`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function downloadAllPatches() {
    const combined = patches
      .map(p => `# Patch for ${p.title}\n# Target: ${p.filePath}:${p.line}\n${p.diff}\n`)
      .join('\n---\n\n');
    const blob = new Blob([combined], { type: 'text/x-diff' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `traceveil-all-remediations-${graph.commit ? graph.commit.slice(0, 8) : 'manual'}.patch`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* 1. Header with Draftable PR Creation */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-primary/30 bg-primary/5 p-5 shadow-xs">
        <div className="flex items-center gap-3.5">
          <div className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-primary/15 text-primary ring-1 ring-primary/30">
            <GitPullRequest className="size-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-foreground">
                Autonomous Remediation &amp; Pull Request Studio
              </h2>
              <span className="rounded-full bg-primary/15 px-2 py-0.5 font-mono text-[9px] font-bold text-primary uppercase">
                {totalCount} {totalCount === 1 ? 'Fix' : 'Fixes'} Ready
              </span>
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Target: <strong className="font-mono text-foreground">{graph.target}</strong> · Synthesize verified code patches and draft live GitHub Pull Requests.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="default"
            disabled={batchRunning}
            onClick={handleCreateAllPRs}
            className="gap-1.5 text-xs shadow-xs bg-primary text-primary-foreground hover:bg-primary/90 cursor-pointer"
          >
            {batchRunning ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <GitPullRequest className="size-3.5" />
            )}
            <span>{batchRunning ? 'Creating Pull Requests...' : 'Agent Auto-Fix: Open PRs for All'}</span>
          </Button>

          <Button
            size="sm"
            variant="outline"
            onClick={downloadAllPatches}
            className="gap-1.5 text-xs"
          >
            <Download className="size-3.5" />
            <span>Download All .patch</span>
          </Button>
        </div>
      </div>

      {/* 2. Target GitHub Repository Binding (Configurable for Live Web Apps) */}
      {!isGithubTarget ? (
        <div className="rounded-xl border border-border bg-card p-4 shadow-2xs space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2.5">
              <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <GitBranch className="size-4" />
              </div>
              <div>
                <h3 className="text-xs font-semibold text-foreground">
                  Link Target GitHub Repository for Pull Requests
                </h3>
                <p className="text-[11px] text-muted-foreground">
                  Connect your source codebase to enable the agent to push fix branches and open draft Pull Requests for this live application.
                </p>
              </div>
            </div>

            {savedRepoNotice && (
              <span className="flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-600 border border-emerald-500/20">
                <Check className="size-3" /> Linked to {cleanRepoName}
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[280px]">
              <input
                type="text"
                value={repoUrl}
                onChange={e => setRepoUrl(e.target.value)}
                placeholder="e.g. https://github.com/your-org/your-app"
                className="h-9 w-full rounded-md border border-input bg-background px-3 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:ring-1 focus:ring-primary"
              />
            </div>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => saveLinkedRepo(repoUrl)}
              className="h-9 gap-1.5 text-xs cursor-pointer"
            >
              <Check className="size-3.5" />
              <span>Link Repository</span>
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex items-center justify-between rounded-lg border border-border/80 bg-muted/20 px-4 py-2.5 text-xs">
          <div className="flex items-center gap-2">
            <GitBranch className="size-3.5 text-primary" />
            <span className="text-muted-foreground">Connected GitHub Codebase:</span>
            {isEditingRepo ? (
              <input
                type="text"
                value={repoUrl}
                onChange={e => setRepoUrl(e.target.value)}
                onBlur={() => saveLinkedRepo(repoUrl)}
                className="h-6 w-72 rounded border border-input bg-background px-2 font-mono text-xs text-foreground"
                autoFocus
              />
            ) : (
              <strong className="font-mono text-foreground">{cleanRepoName}</strong>
            )}
          </div>
          <button
            type="button"
            onClick={() => setIsEditingRepo(v => !v)}
            className="text-[11px] text-muted-foreground hover:text-foreground cursor-pointer underline"
          >
            {isEditingRepo ? 'Done' : 'Change repo'}
          </button>
        </div>
      )}

      {/* 2. Horizontal Finding Selector Pills */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs text-muted-foreground px-1">
          <span className="font-medium text-foreground">Select Vulnerability to Inspect Fix:</span>
          <span className="font-mono text-[11px]">
            {appliedCount} of {totalCount} Resolved ({progressPercent}%)
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          {patches.map((p, idx) => {
            const isSelected = p.id === (activePatch?.id || '');
            const resolved = Boolean(appliedState[p.id]);

            return (
              <button
                key={p.id}
                type="button"
                onClick={() => setSelectedPatchId(p.id)}
                className={cn(
                  'flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium border transition-all cursor-pointer',
                  isSelected
                    ? 'border-primary bg-primary/10 text-foreground ring-1 ring-primary/40 font-semibold shadow-xs'
                    : 'border-border/80 bg-card hover:bg-muted/40 text-muted-foreground hover:text-foreground',
                  resolved && 'border-emerald-500/40 bg-emerald-500/5'
                )}
              >
                <span
                  className={cn(
                    'size-4 rounded-full flex items-center justify-center font-mono text-[10px] shrink-0',
                    resolved
                      ? 'bg-emerald-500 text-white'
                      : isSelected
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted text-muted-foreground'
                  )}
                >
                  {resolved ? '✓' : idx + 1}
                </span>
                <span className="truncate max-w-[200px]">{sanitizeComponentName(p.title, 36)}</span>
                <span className="text-[10px] font-mono text-muted-foreground/70 truncate max-w-[100px]">
                  {p.filePath.split('/').pop()}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* 3. Active Finding Detailed Studio Card */}
      {activePatch && (
        <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-xs">
          {/* Active Card Top Row */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/80 pb-3.5">
            <div>
              <div className="flex items-center gap-2">
                <span className="flex size-5 items-center justify-center rounded-full bg-primary/10 font-mono text-xs font-semibold text-primary">
                  {patches.findIndex(p => p.id === activePatch.id) + 1}
                </span>
                <h3 className="text-sm font-semibold text-foreground">
                  {sanitizeComponentName(activePatch.title, 55)}
                </h3>
                {isApplied && (
                  <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-2 py-0.5 text-[10px] font-bold text-emerald-600">
                    <CheckCircle2 className="size-3" />
                    RESOLVED
                  </span>
                )}
              </div>
              <div className="mt-1 flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
                <FileCode className="size-3 text-primary" />
                <span>Target: {activePatch.filePath}:{activePatch.line}</span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant={isApplied ? 'secondary' : 'default'}
                onClick={() => toggleApply(activePatch.id)}
                className={cn(
                  'h-8 gap-1.5 text-xs font-medium transition-all shadow-xs',
                  isApplied
                    ? 'border border-emerald-500/40 text-emerald-700 bg-emerald-50/50 hover:bg-emerald-100/50 dark:text-emerald-400 dark:bg-emerald-500/10'
                    : 'bg-primary text-primary-foreground hover:bg-primary/90'
                )}
              >
                <CheckCircle2 className={cn('size-3.5', isApplied ? 'text-emerald-600' : 'text-primary-foreground')} />
                <span>{isApplied ? 'Resolved' : 'Mark as Resolved'}</span>
              </Button>

              <Button
                size="sm"
                variant="outline"
                onClick={() => downloadPatch(activePatch)}
                className="h-8 gap-1.5 text-xs"
                title="Download this single patch file"
              >
                <Download className="size-3.5" />
                <span>.patch</span>
              </Button>
            </div>
          </div>

          {/* Agent Suggestion & Rationale */}
          <div className="rounded-lg border border-primary/20 bg-primary/5 p-3.5 text-xs space-y-1.5">
            <div className="flex items-center gap-2 font-semibold text-foreground">
              <Sparkles className="size-4 text-primary" />
              <span>Architectural Fix &amp; Security Rationale</span>
            </div>
            <p className="text-muted-foreground leading-relaxed pl-6">
              {activePatch.suggestion}
            </p>
            <p className="text-[11px] text-muted-foreground/80 pl-6 border-t border-primary/10 pt-1.5">
              <strong>Rationale:</strong> {activePatch.explanation}
            </p>
          </div>

          {/* High-Contrast Code Patch Diff */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-foreground flex items-center gap-1.5">
                <Code2 className="size-3.5 text-primary" />
                Hardened Code Diff ({activePatch.filePath})
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => copyDiff(activePatch.diff, activePatch.id)}
                className="h-6 gap-1 px-2 text-[11px] text-muted-foreground hover:text-foreground"
              >
                {copiedId === activePatch.id ? <Check className="size-3 text-primary" /> : <Copy className="size-3" />}
                <span>{copiedId === activePatch.id ? 'Copied Diff!' : 'Copy Diff'}</span>
              </Button>
            </div>

            <div className="overflow-x-auto rounded-lg border border-border bg-muted/20 p-3 font-mono text-xs text-foreground">
              {activePatch.diff.split('\n').map((line, lIdx) => {
                const isAddition = line.startsWith('+') && !line.startsWith('+++');
                const isDeletion = line.startsWith('-') && !line.startsWith('---');
                const isHeader = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');

                return (
                  <div
                    key={lIdx}
                    className={cn(
                      'leading-relaxed px-2 py-0.5 rounded-sm',
                      isAddition && 'bg-emerald-500/10 text-emerald-600 font-semibold',
                      isDeletion && 'bg-destructive/10 text-destructive line-through opacity-85',
                      isHeader && 'text-muted-foreground text-[10px] font-mono',
                      !isAddition && !isDeletion && !isHeader && 'text-muted-foreground'
                    )}
                  >
                    {line}
                  </div>
                );
              })}
            </div>
          </div>

          {/* 5. Autonomous Pull Request Generator Card (Replaces PowerShell CLI) */}
          <div className="rounded-xl border border-border/80 bg-muted/15 p-4 space-y-3.5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <GitPullRequest className="size-4" />
                </div>
                <div>
                  <h4 className="text-xs font-bold text-foreground">
                    Autonomous GitHub Pull Request Generator
                  </h4>
                  <p className="text-[11px] text-muted-foreground">
                    The agent pushes a dedicated fix branch and opens a verified draft Pull Request on <code className="font-mono text-primary font-semibold">{cleanRepoName}</code>.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="default"
                  disabled={runningPatchId === activePatch.id}
                  onClick={() => handleCreatePR(activePatch)}
                  className="gap-1.5 text-xs bg-primary text-primary-foreground hover:bg-primary/90 shadow-xs font-semibold cursor-pointer"
                >
                  {runningPatchId === activePatch.id ? (
                    <Loader2 className="size-3.5 animate-spin" />
                  ) : (
                    <GitPullRequest className="size-3.5" />
                  )}
                  <span>
                    {runningPatchId === activePatch.id
                      ? 'Synthesizing PR...'
                      : activePRResult?.isRealPR
                        ? 'Re-Open PR'
                        : 'Create GitHub Pull Request'}
                  </span>
                </Button>

                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setShowTokenInput(v => !v)}
                  className="h-8 text-[11px] text-muted-foreground hover:text-foreground cursor-pointer"
                  title="Configure custom GitHub Personal Access Token"
                >
                  <Lock className="size-3" />
                  <span>{showTokenInput ? 'Hide Token' : 'Custom Token'}</span>
                </Button>
              </div>
            </div>

            {/* Optional Custom Token Drawer */}
            {showTokenInput && (
              <div className="rounded-lg border border-border bg-card p-3 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-foreground">GitHub Personal Access Token (PAT)</span>
                  <span className="text-[10px] text-muted-foreground">Saved credentials in vault will be used if left blank</span>
                </div>
                <input
                  type="password"
                  value={customToken}
                  onChange={e => setCustomToken(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxx (needs 'repo' scope)"
                  className="h-8 w-full rounded border border-input bg-background px-2.5 font-mono text-xs focus:ring-1 focus:ring-primary"
                />
              </div>
            )}

            {/* Pull Request Output Banner */}
            {activePRResult && (
              <div
                className={cn(
                  'rounded-lg border p-3.5 text-xs space-y-2.5',
                  activePRResult.isRealPR
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-950 dark:text-emerald-100'
                    : activePRResult.status === 'needs_auth'
                      ? 'border-amber-500/40 bg-amber-500/10 text-amber-950 dark:text-amber-100'
                      : 'border-destructive/40 bg-destructive/10 text-destructive'
                )}
              >
                {activePRResult.isRealPR ? (
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                      <div>
                        <span className="font-bold text-xs">
                          Pull Request #{activePRResult.prNumber} Opened Successfully!
                        </span>
                        <div className="font-mono text-[10px] text-emerald-800 dark:text-emerald-300 mt-0.5">
                          Branch: {activePRResult.branchName} · Commit: {activePRResult.commitSha}
                        </div>
                      </div>
                    </div>

                    <Button
                      size="sm"
                      variant="default"
                      onClick={() => window.open(activePRResult.prUrl, '_blank')}
                      className="gap-1.5 text-xs bg-emerald-600 hover:bg-emerald-700 text-white shadow-xs font-semibold cursor-pointer"
                    >
                      <ExternalLink className="size-3.5" />
                      <span>View Live PR on GitHub</span>
                    </Button>
                  </div>
                ) : activePRResult.status === 'needs_auth' ? (
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="size-4 text-amber-600 shrink-0" />
                        <span className="font-bold text-xs">
                          GitHub Token with 'repo' Scope Required for Live Push
                        </span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            window.open(
                              `https://github.com/${cleanRepoName}/compare?expand=1`,
                              '_blank'
                            )
                          }
                          className="h-7 gap-1 text-[11px] bg-background text-foreground"
                        >
                          <ExternalLink className="size-3" />
                          <span>Draft PR on GitHub Web</span>
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => downloadPatch(activePatch)}
                          className="h-7 gap-1 text-[11px] bg-background text-foreground"
                        >
                          <Download className="size-3" />
                          <span>Download .patch</span>
                        </Button>
                      </div>
                    </div>
                    <p className="text-[11px] text-amber-800 dark:text-amber-200 leading-relaxed">
                      To automatically commit and open PRs directly via the agent, click <strong>GitHub Credentials</strong> in the top header or expand <strong>Custom Token</strong> above to enter your Personal Access Token.
                    </p>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="size-4 text-destructive shrink-0" />
                    <span>Error creating Pull Request: {activePRResult.error || 'Check repository access.'}</span>
                  </div>
                )}

                {/* Collapsible Agent Execution Log */}
                {activePRResult.logs && activePRResult.logs.length > 0 && (
                  <details className="rounded border border-border/60 bg-background/60 p-2.5 text-[11px] font-mono">
                    <summary className="cursor-pointer text-muted-foreground hover:text-foreground font-semibold flex items-center justify-between">
                      <span>View Agent Git Execution Terminal Trace</span>
                      <ChevronDown className="size-3" />
                    </summary>
                    <div className="mt-2 space-y-1.5 text-foreground leading-relaxed">
                      {activePRResult.logs.map((log, lIdx) => (
                        <div key={lIdx} className="space-y-0.5">
                          {log.command && (
                            <div className="text-primary font-bold">$ {log.command}</div>
                          )}
                          {log.output.map((out, oIdx) => (
                            <div key={oIdx} className="text-muted-foreground pl-2 text-[10px]">
                              {out}
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  </details>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function InteractiveRemediation({ graph }: { graph: AttackGraph }) {
  const [patches, setPatches] = useState<RemediationPatch[]>([]);

  // Diagram vs Live App vs Repository target detection
  const isDiagram = Boolean(
    graph?.target &&
      (graph.target.startsWith('diagram://') ||
        graph.target.includes('.drawio') ||
        graph.target.includes('.pkt') ||
        graph.target.includes('architecture'))
  );

  useEffect(() => {
    if (graph) {
      const generated = generateRemediationPatches(graph);
      setPatches(generated);
    }
  }, [graph]);

  if (patches.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-8 text-center shadow-xs">
        <div className="mx-auto flex size-12 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-500">
          <CheckCircle2 className="size-6" />
        </div>
        <h3 className="mt-3 text-sm font-semibold">No Remediations Required</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          All inspected components and configurations adhere to least-privilege security baselines.
        </p>
      </div>
    );
  }

  if (isDiagram) {
    return <DiagramRemediationStudio graph={graph} patches={patches} />;
  }

  return <CodeRemediationStudio graph={graph} patches={patches} />;
}
