import { useState, useEffect, useRef } from 'react';
import {
  Wrench,
  CheckCircle2,
  Copy,
  Download,
  Check,
  Sparkles,
  FileCode,
  ArrowRight,
  ShieldCheck,
  Bot,
  GitPullRequest,
  GitMerge,
  Terminal,
  ExternalLink,
  Loader2,
  Play,
  RotateCcw,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { AttackGraph } from '@/lib/atlas/types';
import { generateRemediationPatches, type RemediationPatch } from '@/lib/atlas/agent-operations';
import { executeLiveRemediationPR } from '@/lib/atlas/remediation.functions';
import { cn } from '@/lib/utils';

export type AgentStepLog = {
  command?: string;
  output: string[];
  type?: 'cmd' | 'info' | 'success' | 'warn' | 'error';
};

export type AgentRun = {
  status: 'idle' | 'running' | 'completed' | 'error';
  logs: AgentStepLog[];
  currentStep: number;
  totalSteps: number;
  branchName?: string;
  prNumber?: number;
  prUrl?: string;
  commitSha?: string;
  isRealPR?: boolean;
};

export function InteractiveRemediation({ graph }: { graph: AttackGraph }) {
  const [patches, setPatches] = useState<RemediationPatch[]>([]);
  const [appliedState, setAppliedState] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedLogsId, setCopiedLogsId] = useState<string | null>(null);

  // Live app GitHub repository linking & agent state
  const isLiveApp = Boolean(graph?.target && !graph.target.startsWith('https://github.com'));
  const [repoUrl, setRepoUrl] = useState<string>(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('traceveil_remediation_repo');
      if (stored) return stored;
    }
    return !isLiveApp && graph?.target ? graph.target : '';
  });

  const [promptRepoForPatch, setPromptRepoForPatch] = useState<string | null>(null);
  const [agentRuns, setAgentRuns] = useState<Record<string, AgentRun>>({});
  const [terminalsOpen, setTerminalsOpen] = useState<Record<string, boolean>>({});
  const activeTimers = useRef<Record<string, NodeJS.Timeout[]>>({});
  const terminalScrollRefs = useRef<Record<string, HTMLDivElement | null>>({});

  useEffect(() => {
    if (graph) {
      const generated = generateRemediationPatches(graph);
      setPatches(generated);
    }
    return () => {
      // Clear any pending timers on unmount
      Object.values(activeTimers.current).forEach(timers => timers.forEach(t => clearTimeout(t)));
    };
  }, [graph]);

  // Save repo URL to localStorage
  function updateRepoUrl(val: string) {
    setRepoUrl(val);
    if (typeof window !== 'undefined') {
      localStorage.setItem('traceveil_remediation_repo', val);
    }
  }

  const appliedCount = Object.values(appliedState).filter(Boolean).length;
  const totalCount = patches.length;
  const progressPercent = totalCount > 0 ? Math.round((appliedCount / totalCount) * 100) : 100;
  const isAnyAgentRunning = Object.values(agentRuns).some(r => r.status === 'running');

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

  function copyTerminalLogs(patchId: string) {
    const run = agentRuns[patchId];
    if (!run) return;
    const text = run.logs
      .map(l => (l.command ? `$ ${l.command}\n` : '') + l.output.join('\n'))
      .join('\n');
    void navigator.clipboard.writeText(text);
    setCopiedLogsId(patchId);
    setTimeout(() => setCopiedLogsId(null), 2000);
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
    a.download = `traceveil-all-remediations-${graph.commit.slice(0, 8)}.patch`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Autonomous Agent Workflow: Real Live GitHub Branch, AST Patch, Commit & PR
  async function startAgentRemediation(patch: RemediationPatch, overrideRepo?: string) {
    const targetRepo = (overrideRepo || repoUrl).trim();
    if (!targetRepo) {
      setPromptRepoForPatch(patch.id);
      return;
    }

    setPromptRepoForPatch(null);
    setTerminalsOpen(prev => ({ ...prev, [patch.id]: true }));

    // Extract owner and repo
    const clean = targetRepo.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '').replace(/\/$/, '');
    const [owner, repoName] = clean.includes('/') ? clean.split('/') : ['org', clean || 'web-app'];

    // Cancel any previous timers for this patch
    if (activeTimers.current[patch.id]) {
      activeTimers.current[patch.id].forEach(t => clearTimeout(t));
    }
    activeTimers.current[patch.id] = [];

    // Initialize with live starting logs
    setAgentRuns(prev => ({
      ...prev,
      [patch.id]: {
        status: 'running',
        logs: [
          {
            type: 'info',
            output: [
              `[TRACEVEIL REMEDIATION AGENT] Initializing autonomous container worktree...`,
              `Target GitHub Codebase: https://github.com/${owner}/${repoName}`,
              `Target Security Finding: ${patch.title} in ${patch.filePath}`,
              `Connecting to GitHub REST API...`,
            ],
          },
        ],
        currentStep: 1,
        totalSteps: 6,
        branchName: `traceveil/fix-${patch.id.replace('patch-', '')}`,
      },
    }));

    try {
      const result = await executeLiveRemediationPR({
        data: {
          repoUrl: targetRepo,
          patchId: patch.id,
          title: patch.title,
          filePath: patch.filePath,
          line: patch.line,
          diff: patch.diff,
          remediatedCode: patch.remediatedCode,
        },
      });

      // Stream the real execution logs into the terminal
      let step = 0;
      const interval = setInterval(() => {
        if (step < result.logs.length) {
          const item = result.logs[step];
          setAgentRuns(prev => {
            const current = prev[patch.id];
            if (!current) return prev;
            return {
              ...prev,
              [patch.id]: {
                ...current,
                logs: [...current.logs, item],
                currentStep: step + 2,
                totalSteps: result.logs.length + 1,
              },
            };
          });

          const el = terminalScrollRefs.current[patch.id];
          if (el) el.scrollTop = el.scrollHeight;
          step++;
        } else {
          clearInterval(interval);
          setAgentRuns(prev => {
            const current = prev[patch.id];
            if (!current) return prev;
            return {
              ...prev,
              [patch.id]: {
                ...current,
                status: result.status === 'failed' ? 'error' : 'completed',
                prNumber: result.prNumber,
                prUrl: result.prUrl,
                isRealPR: result.isRealPR,
                branchName: result.branchName,
                commitSha: result.commitSha,
              },
            };
          });
          setAppliedState(prev => ({ ...prev, [patch.id]: true }));
        }
      }, 250);
    } catch (err: unknown) {
      setAgentRuns(prev => {
        const current = prev[patch.id];
        return {
          ...prev,
          [patch.id]: {
            ...current,
            status: 'error',
            logs: [
              ...(current?.logs || []),
              {
                type: 'error',
                output: [
                  `[EXECUTION ERROR] ${err instanceof Error ? err.message : 'Failed to reach GitHub API.'}`,
                ],
              },
            ],
          },
        };
      });
    }
  }

  // Remediate all patches sequentially
  function runAllAgents() {
    if (!repoUrl.trim()) {
      if (patches[0]) setPromptRepoForPatch(patches[0].id);
      return;
    }
    let delay = 0;
    patches.forEach(p => {
      if (!appliedState[p.id]) {
        setTimeout(() => {
          startAgentRemediation(p);
        }, delay);
        delay += 6000;
      }
    });
  }

  if (patches.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border p-12 text-center">
        <ShieldCheck className="size-10 text-emerald-400" />
        <h3 className="mt-4 text-sm font-semibold">Zero Outstanding Remediations</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          All inspected repository files adhere to least-privilege security configurations.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Remediation Health & Progress Header */}
      <div className="rounded-lg border border-border bg-card p-5 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Wrench className="size-4 text-primary" />
              <h2 className="text-sm font-semibold">Autonomous Remediation Studio</h2>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              Traceveil AI Agents inspect security exposures, apply code fixes, open Pull Requests, and auto-merge them.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Button
              variant="outline"
              size="sm"
              onClick={downloadAllPatches}
              className="gap-2 text-xs"
            >
              <Download className="size-3.5" />
              Download All Patches (.patch)
            </Button>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mt-5 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Remediation Status</span>
            <span className="font-mono font-medium text-foreground">
              {appliedCount} of {totalCount} Remediations Applied ({progressPercent}%)
            </span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
            <div
              className="h-full bg-primary transition-all duration-500 ease-out"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>
      </div>

      {/* Live App GitHub Linking Bar (Prominent for Live Web Applications) */}
      {isLiveApp && (
        <div className="rounded-lg border border-primary/20 bg-primary/5 p-4 shadow-xs">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <Bot className="size-5" />
              </div>
              <div className="min-w-0">
                <h3 className="text-xs font-semibold text-foreground flex items-center gap-2">
                  <span>Live App GitHub Auto-Remediation</span>
                  <span className="rounded bg-primary/15 px-1.5 py-0.5 font-mono text-[9px] font-bold text-primary uppercase">
                    Agent Powered
                  </span>
                </h3>
                <p className="text-[11px] text-muted-foreground truncate">
                  Target: <strong className="font-mono text-foreground">{graph.target}</strong> · Connect the GitHub repository to let the agent apply patches and merge PRs live.
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
              <div className="relative flex-1 sm:w-72">
                <input
                  type="url"
                  placeholder="https://github.com/owner/repository"
                  value={repoUrl}
                  onChange={e => updateRepoUrl(e.target.value)}
                  className="h-8 w-full rounded border border-input bg-card px-2.5 font-mono text-xs text-foreground outline-none focus:ring-1 focus:ring-ring"
                />
              </div>
              <Button
                size="sm"
                disabled={!repoUrl.trim() || isAnyAgentRunning}
                onClick={runAllAgents}
                className="h-8 gap-1.5 text-xs bg-primary text-primary-foreground hover:bg-primary/90"
              >
                {isAnyAgentRunning ? (
                  <>
                    <Loader2 className="size-3 animate-spin" />
                    <span>Agent Running...</span>
                  </>
                ) : (
                  <>
                    <Play className="size-3" />
                    <span>Auto-Remediate All via Agent</span>
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* List of Actionable Code Patches */}
      <div className="space-y-5">
        {patches.map((patch, idx) => {
          const isApplied = Boolean(appliedState[patch.id]);
          const run = agentRuns[patch.id];
          const isRunning = run?.status === 'running';
          const isCompleted = run?.status === 'completed';
          const isTerminalOpen = Boolean(terminalsOpen[patch.id]);
          const isPromptingRepo = promptRepoForPatch === patch.id;

          return (
            <div
              key={patch.id}
              className={cn(
                'rounded-lg border transition-all shadow-xs overflow-hidden',
                isApplied
                  ? 'border-emerald-500/40 bg-card'
                  : 'border-border bg-card hover:border-border/80'
              )}
            >
              {/* Header */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/80 p-4">
                <div className="flex items-center gap-3">
                  <span className="flex size-6 items-center justify-center rounded-full bg-muted font-mono text-xs font-semibold text-muted-foreground">
                    {idx + 1}
                  </span>
                  <div>
                    <h3 className="text-xs font-semibold text-foreground flex items-center gap-2">
                      {patch.title}
                      {isApplied && (
                        <span className="flex items-center gap-1 rounded bg-emerald-500/15 px-2 py-0.5 text-[10px] font-bold text-emerald-600">
                          <CheckCircle2 className="size-3" />
                          {run?.prNumber ? `MERGED (PR #${run.prNumber})` : 'REMEDIATED'}
                        </span>
                      )}
                    </h3>
                    <div className="mt-1 flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
                      <FileCode className="size-3" />
                      <span>{patch.filePath}:{patch.line}</span>
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => copyDiff(patch.diff, patch.id)}
                    className="gap-1.5 text-xs text-muted-foreground hover:text-foreground"
                  >
                    {copiedId === patch.id ? <Check className="size-3 text-primary" /> : <Copy className="size-3" />}
                    {copiedId === patch.id ? 'Copied' : 'Copy Diff'}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => downloadPatch(patch)}
                    className="gap-1.5 text-xs"
                  >
                    <Download className="size-3" />
                    .patch
                  </Button>

                  {/* Primary Action Button: Agent Auto-Fix & PR for Live Web Apps */}
                  <Button
                    variant={isApplied ? 'outline' : 'default'}
                    size="sm"
                    disabled={isRunning}
                    onClick={() => {
                      if (isApplied && !isPromptingRepo) {
                        toggleApply(patch.id);
                      } else {
                        startAgentRemediation(patch);
                      }
                    }}
                    className={cn(
                      'gap-1.5 text-xs font-medium transition-all shadow-xs',
                      isApplied
                        ? 'border-emerald-500/40 text-emerald-700 bg-emerald-50/50 hover:bg-emerald-100/50'
                        : 'bg-primary text-primary-foreground hover:bg-primary/90'
                    )}
                  >
                    {isRunning ? (
                      <>
                        <Loader2 className="size-3 animate-spin" />
                        <span>Agent Running...</span>
                      </>
                    ) : isApplied ? (
                      <>
                        <CheckCircle2 className="size-3 text-emerald-600" />
                        <span>{run?.prNumber ? `PR #${run.prNumber} Merged` : 'Resolved'}</span>
                      </>
                    ) : (
                      <>
                        <Bot className="size-3.5" />
                        <span>Agent Auto-Fix (PR & Merge)</span>
                      </>
                    )}
                  </Button>

                  {/* Terminal Toggle Button if run exists */}
                  {run && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() =>
                        setTerminalsOpen(prev => ({ ...prev, [patch.id]: !prev[patch.id] }))
                      }
                      className="gap-1 text-xs text-muted-foreground hover:text-foreground"
                    >
                      <Terminal className="size-3" />
                      <span>Terminal</span>
                      {isTerminalOpen ? <ChevronUp className="size-3" /> : <ChevronDown className="size-3" />}
                    </Button>
                  )}
                </div>
              </div>

              {/* Inline GitHub Repo Input Prompt if needed */}
              {isPromptingRepo && !isRunning && (
                <div className="border-b border-border bg-muted/30 p-4">
                  <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                    <div className="flex-1">
                      <label className="block text-[11px] font-medium text-foreground mb-1">
                        Enter GitHub Repository URL for <span className="font-mono text-primary">{graph.target}</span>:
                      </label>
                      <input
                        type="url"
                        placeholder="https://github.com/owner/repository"
                        value={repoUrl}
                        onChange={e => updateRepoUrl(e.target.value)}
                        className="h-8 w-full rounded border border-input bg-card px-3 font-mono text-xs outline-none focus:ring-1 focus:ring-ring"
                      />
                    </div>
                    <div className="flex items-center gap-2 pt-2 sm:pt-4">
                      <Button
                        size="sm"
                        disabled={!repoUrl.trim()}
                        onClick={() => startAgentRemediation(patch, repoUrl)}
                        className="h-8 gap-1.5 text-xs bg-primary text-primary-foreground hover:bg-primary/90"
                      >
                        <Play className="size-3" />
                        Launch Agent (Apply & Merge PR)
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setPromptRepoForPatch(null)}
                        className="h-8 text-xs"
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                </div>
              )}

              {/* LIVE AGENT RUNNER TERMINAL (NO BLACK SCREENS - CLEAN DEVELOPER CONSOLE) */}
              {run && isTerminalOpen && (
                <div className="border-b border-border bg-muted/15 p-4">
                  <div className="rounded-lg border border-border bg-card shadow-xs overflow-hidden">
                    {/* Console Title Bar with 🔴 🟡 🟢 dots */}
                    <div className="flex items-center justify-between border-b border-border bg-muted/40 px-3.5 py-2">
                      <div className="flex items-center gap-2">
                        <div className="flex items-center gap-1.5">
                          <span className="size-2.5 rounded-full bg-rose-400/80 inline-block" />
                          <span className="size-2.5 rounded-full bg-amber-400/80 inline-block" />
                          <span className="size-2.5 rounded-full bg-emerald-400/80 inline-block" />
                        </div>
                        <span className="ml-2 font-mono text-[11px] font-semibold text-foreground flex items-center gap-1.5">
                          <Terminal className="size-3.5 text-primary" />
                          <span>Traceveil Remediation Agent — Autonomous Runner</span>
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        {isRunning && (
                          <span className="flex items-center gap-1 text-[10px] font-mono text-primary animate-pulse">
                            <Loader2 className="size-3 animate-spin" />
                            <span>Step {run.currentStep}/{run.totalSteps}</span>
                          </span>
                        )}
                        {isCompleted && (
                          <span className="flex items-center gap-1 text-[10px] font-mono font-semibold text-emerald-600">
                            <Check className="size-3" />
                            <span>PR #{run.prNumber} Merged</span>
                          </span>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyTerminalLogs(patch.id)}
                          className="h-6 px-2 text-[10px] text-muted-foreground hover:text-foreground"
                        >
                          {copiedLogsId === patch.id ? 'Copied' : 'Copy Output'}
                        </Button>
                      </div>
                    </div>

                    {/* Console Output Body */}
                    <div
                      ref={el => {
                        terminalScrollRefs.current[patch.id] = el;
                      }}
                      className="p-4 font-mono text-[11px] leading-relaxed text-foreground bg-card max-h-72 overflow-y-auto space-y-2 select-text"
                    >
                      {run.logs.map((log, lIdx) => (
                        <div key={lIdx} className="space-y-0.5">
                          {log.command && (
                            <div className="flex items-start gap-2 text-foreground font-semibold">
                              <span className="text-primary font-bold select-none">$</span>
                              <span>{log.command}</span>
                            </div>
                          )}
                          {log.output.map((outLine, oIdx) => {
                            const isSuccess = outLine.includes('[SUCCESS]') || outLine.includes('✓') || outLine.includes('[REMEDIATION COMPLETE]');
                            const isInfo = outLine.startsWith('[TRACEVEIL') || outLine.startsWith('[ANALYSIS]') || outLine.startsWith('[PR CREATED]');
                            const isPr = outLine.includes('Pull request #');

                            return (
                              <div
                                key={oIdx}
                                className={cn(
                                  'pl-4 text-[11px]',
                                  isSuccess && 'text-emerald-600 font-semibold',
                                  isInfo && 'text-primary font-medium',
                                  isPr && 'text-indigo-600 font-semibold',
                                  !isSuccess && !isInfo && !isPr && 'text-muted-foreground'
                                )}
                              >
                                {outLine}
                              </div>
                            );
                          })}
                        </div>
                      ))}

                      {isRunning && (
                        <div className="flex items-center gap-1 pl-4 text-primary font-mono text-[11px]">
                          <span className="inline-block size-2 rounded-full bg-primary animate-ping" />
                          <span className="text-muted-foreground">Agent executing next command...</span>
                        </div>
                      )}
                    </div>

                    {/* Console Footer: Real PR or Local Patch Status */}
                    {isCompleted && run.prUrl && (
                      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs">
                        <div className="flex items-center gap-2 text-emerald-800 font-medium">
                          <GitMerge className="size-4 text-emerald-600" />
                          {run.isRealPR && run.prNumber ? (
                            <span>Live Pull Request <strong>#{run.prNumber}</strong> created on GitHub. Vulnerability resolved at source.</span>
                          ) : (
                            <span>AST security patch verified. Click 'Download .patch' to apply locally, or save a GitHub PAT to create remote PRs.</span>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          <a
                            href={run.prUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 font-mono text-[11px] text-emerald-700 hover:text-emerald-900 underline font-semibold"
                          >
                            <span>{run.isRealPR ? 'View on GitHub' : 'View Repo on GitHub'}</span>
                            <ExternalLink className="size-3" />
                          </a>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => downloadPatch(patch)}
                            className="h-6 gap-1 px-2 text-[10px] text-muted-foreground hover:text-foreground"
                          >
                            <Download className="size-3" />
                            <span>Download .patch</span>
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => startAgentRemediation(patch)}
                            className="h-6 gap-1 px-2 text-[10px] text-muted-foreground hover:text-foreground"
                          >
                            <RotateCcw className="size-3" />
                            <span>Re-run Agent</span>
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Diff Viewer */}
              <div className="p-4">
                <p className="mb-3 text-xs text-muted-foreground leading-relaxed">
                  <strong>Impact:</strong> {patch.explanation}
                </p>

                <div className="overflow-x-auto rounded-lg border border-border bg-muted/20 p-3 font-mono text-xs text-foreground">
                  {patch.diff.split('\n').map((line, lIdx) => {
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

                <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[10px] text-muted-foreground border-t border-border/50 pt-2">
                  <span>To apply this fix manually, download the patch and run: <code className="text-foreground bg-muted px-1.5 py-0.5 rounded font-mono">git apply traceveil-{patch.id}.patch</code></span>
                  <span className="font-mono text-primary">Target: {patch.filePath}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
