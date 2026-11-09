import { useState, useEffect } from 'react';
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
  Info,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { AttackGraph } from '@/lib/atlas/types';
import { generateRemediationPatches, type RemediationPatch } from '@/lib/atlas/agent-operations';
import { cn } from '@/lib/utils';

export function InteractiveRemediation({ graph }: { graph: AttackGraph }) {
  const [patches, setPatches] = useState<RemediationPatch[]>([]);
  const [appliedState, setAppliedState] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedPsId, setCopiedPsId] = useState<string | null>(null);
  const [copiedAllPs, setCopiedAllPs] = useState(false);

  // Diagram vs Live App vs Repository target detection
  const isDiagram = Boolean(
    graph?.target &&
      (graph.target.startsWith('diagram://') ||
        graph.target.includes('.drawio') ||
        graph.target.includes('.pkt') ||
        graph.target.includes('architecture'))
  );
  const isLiveApp = !isDiagram && Boolean(graph?.target && !graph.target.startsWith('https://github.com'));

  useEffect(() => {
    if (graph) {
      const generated = generateRemediationPatches(graph);
      setPatches(generated);
    }
  }, [graph]);

  const appliedCount = Object.values(appliedState).filter(Boolean).length;
  const totalCount = patches.length;
  const progressPercent = totalCount > 0 ? Math.round((appliedCount / totalCount) * 100) : 100;

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

  function copyPowerShell(cmd: string, id: string) {
    void navigator.clipboard.writeText(cmd);
    setCopiedPsId(id);
    setTimeout(() => setCopiedPsId(null), 2000);
  }

  function copyAllPowerShellCommands() {
    const header = `# ========================================================\n# Traceveil Security Remediation Script (PowerShell)\n# Target: ${graph.target}\n# Generated: ${new Date().toISOString()}\n# ========================================================\n\nWrite-Host "Starting Traceveil Security Remediation..." -ForegroundColor Cyan\n\n`;
    const body = patches
      .map(
        (p, idx) =>
          `# [${idx + 1}/${patches.length}] ${p.title}\n# Suggestion: ${p.suggestion}\n# Target File: ${p.filePath}:${p.line}\n${p.powershellCommand}\n`
      )
      .join('\n');
    const footer = `\nWrite-Host "[✓] Traceveil remediation commands executed." -ForegroundColor Green\n`;
    void navigator.clipboard.writeText(header + body + footer);
    setCopiedAllPs(true);
    setTimeout(() => setCopiedAllPs(false), 2000);
  }

  function downloadPowerShellScript() {
    const header = `# ========================================================\n# Traceveil Security Remediation Script (PowerShell)\n# Target: ${graph.target}\n# Generated: ${new Date().toISOString()}\n# ========================================================\n\nWrite-Host "Starting Traceveil Security Remediation..." -ForegroundColor Cyan\n\n`;
    const body = patches
      .map(
        (p, idx) =>
          `# [${idx + 1}/${patches.length}] ${p.title}\n# Suggestion: ${p.suggestion}\n# Target File: ${p.filePath}:${p.line}\n${p.powershellCommand}\n`
      )
      .join('\n');
    const footer = `\nWrite-Host "[✓] Traceveil remediation script completed." -ForegroundColor Green\n`;
    const blob = new Blob([header + body + footer], { type: 'application/x-powershell' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `traceveil-remediations-${graph.commit ? graph.commit.slice(0, 8) : 'manual'}.ps1`;
    a.click();
    URL.revokeObjectURL(url);
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

  function downloadSinglePolicyFile(patch: RemediationPatch) {
    const filename = patch.filePath.split('/').pop() || `${patch.id}.txt`;
    const blob = new Blob([patch.remediatedCode], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

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

  return (
    <div className="space-y-6">
      {/* Remediation Health & Progress Header */}
      <div className="rounded-lg border border-border bg-card p-5 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Wrench className="size-4 text-primary" />
              <h2 className="text-sm font-semibold">Remediation & Hardening Studio</h2>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {isDiagram
                ? 'Expert suggestions, Terraform (.tf), Cisco IOS (.cfg), and Kubernetes (.yaml) policies with ready-to-run PowerShell commands.'
                : 'Actionable security suggestions, configuration diffs, and copy-and-paste PowerShell commands. Run commands directly in your own terminal.'}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="default"
              size="sm"
              onClick={copyAllPowerShellCommands}
              className="gap-1.5 text-xs bg-primary text-primary-foreground hover:bg-primary/90"
            >
              {copiedAllPs ? <Check className="size-3.5" /> : <Terminal className="size-3.5" />}
              <span>{copiedAllPs ? 'Copied All Commands!' : 'Copy All PowerShell Fixes'}</span>
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={downloadPowerShellScript}
              className="gap-1.5 text-xs"
            >
              <Download className="size-3.5" />
              <span>Export Script (.ps1)</span>
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={downloadAllPatches}
              className="gap-1.5 text-xs text-muted-foreground hover:text-foreground"
            >
              <Download className="size-3.5" />
              <span>{isDiagram ? 'Download Policies' : 'Download .patch'}</span>
            </Button>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mt-5 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Hardening Progress</span>
            <span className="font-mono font-medium text-foreground">
              {appliedCount} of {totalCount} Remediations Resolved ({progressPercent}%)
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

      {/* Cloud & Network Architecture Guidance Bar */}
      {isDiagram && (
        <div className="rounded-lg border border-primary/20 bg-primary/5 p-4 shadow-xs">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <Layers className="size-5" />
              </div>
              <div className="min-w-0">
                <h3 className="text-xs font-semibold text-foreground flex items-center gap-2">
                  <span>Architecture Remediation Guidance</span>
                  <span className="rounded bg-primary/15 px-1.5 py-0.5 font-mono text-[9px] font-bold text-primary uppercase">
                    Diagram Mode
                  </span>
                </h3>
                <p className="text-[11px] text-muted-foreground truncate">
                  Architecture Model: <strong className="font-mono text-foreground">{graph.target.replace('diagram://', '')}</strong> · Copy and paste the PowerShell / CLI commands below to apply hardening policies.
                </p>
              </div>
            </div>

            <Button
              size="sm"
              variant="outline"
              onClick={copyAllPowerShellCommands}
              className="h-8 gap-1.5 text-xs border-primary/30 text-primary hover:bg-primary/10"
            >
              {copiedAllPs ? <Check className="size-3" /> : <Terminal className="size-3" />}
              <span>{copiedAllPs ? 'Copied All Commands' : 'Copy All PowerShell Fixes'}</span>
            </Button>
          </div>
        </div>
      )}

      {/* Live App Guidance Bar */}
      {isLiveApp && (
        <div className="rounded-lg border border-primary/20 bg-primary/5 p-4 shadow-xs">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <ShieldCheck className="size-5" />
              </div>
              <div className="min-w-0">
                <h3 className="text-xs font-semibold text-foreground flex items-center gap-2">
                  <span>Live Web App Security Guidance</span>
                  <span className="rounded bg-primary/15 px-1.5 py-0.5 font-mono text-[9px] font-bold text-primary uppercase">
                    Direct Terminal Fixes
                  </span>
                </h3>
                <p className="text-[11px] text-muted-foreground truncate">
                  Target: <strong className="font-mono text-foreground">{graph.target}</strong> · Each finding includes an agent recommendation and a copy-and-paste PowerShell command.
                </p>
              </div>
            </div>

            <Button
              size="sm"
              variant="outline"
              onClick={copyAllPowerShellCommands}
              className="h-8 gap-1.5 text-xs border-primary/30 text-primary hover:bg-primary/10"
            >
              {copiedAllPs ? <Check className="size-3" /> : <Terminal className="size-3" />}
              <span>{copiedAllPs ? 'Copied All Commands' : 'Copy All PowerShell Fixes'}</span>
            </Button>
          </div>
        </div>
      )}

      {/* List of Actionable Security Fixes */}
      <div className="space-y-5">
        {patches.map((patch, idx) => {
          const isApplied = Boolean(appliedState[patch.id]);

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
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/80 p-4 bg-muted/10">
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
                          RESOLVED
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
                  {/* Copy PowerShell Command Button */}
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => copyPowerShell(patch.powershellCommand, patch.id)}
                    className="gap-1.5 text-xs text-primary border-primary/30 hover:bg-primary/10"
                  >
                    {copiedPsId === patch.id ? <Check className="size-3 text-primary" /> : <Terminal className="size-3" />}
                    <span>{copiedPsId === patch.id ? 'Copied Command!' : 'Copy PowerShell'}</span>
                  </Button>

                  {/* Copy Diff Button */}
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => copyDiff(patch.diff, patch.id)}
                    className="gap-1.5 text-xs text-muted-foreground hover:text-foreground"
                  >
                    {copiedId === patch.id ? <Check className="size-3 text-primary" /> : <Copy className="size-3" />}
                    <span>{copiedId === patch.id ? 'Copied Diff' : 'Copy Diff'}</span>
                  </Button>

                  {/* Download Policy / Patch */}
                  {isDiagram ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => downloadSinglePolicyFile(patch)}
                      className="gap-1.5 text-xs text-muted-foreground hover:text-foreground"
                    >
                      <Download className="size-3" />
                      <span>.{patch.filePath.split('.').pop() || 'cfg'}</span>
                    </Button>
                  ) : (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => downloadPatch(patch)}
                      className="gap-1.5 text-xs text-muted-foreground hover:text-foreground"
                    >
                      <Download className="size-3" />
                      <span>.patch</span>
                    </Button>
                  )}

                  {/* Mark as Resolved / Remediated Toggle */}
                  <Button
                    variant={isApplied ? 'secondary' : 'default'}
                    size="sm"
                    onClick={() => toggleApply(patch.id)}
                    className={cn(
                      'gap-1.5 text-xs font-medium transition-all shadow-xs',
                      isApplied
                        ? 'border border-emerald-500/40 text-emerald-700 bg-emerald-50/50 hover:bg-emerald-100/50'
                        : 'bg-primary text-primary-foreground hover:bg-primary/90'
                    )}
                  >
                    <CheckCircle2 className={cn('size-3.5', isApplied ? 'text-emerald-600' : 'text-primary-foreground')} />
                    <span>{isApplied ? 'Marked as Resolved' : 'Mark as Resolved'}</span>
                  </Button>
                </div>
              </div>

              {/* Body: Suggestion & Action Plan */}
              <div className="p-4 space-y-4">
                {/* 1. AGENT SUGGESTION CALLOUT */}
                <div className="rounded-lg border border-primary/20 bg-primary/5 p-3.5 text-xs space-y-1.5">
                  <div className="flex items-center gap-2 font-semibold text-foreground">
                    <Sparkles className="size-4 text-primary" />
                    <span>Agent Suggestion & Root Cause</span>
                  </div>
                  <p className="text-muted-foreground leading-relaxed pl-6">
                    {patch.suggestion}
                  </p>
                  <p className="text-[11px] text-muted-foreground/80 pl-6 border-t border-primary/10 pt-1.5">
                    <strong>Technical Rationale:</strong> {patch.explanation}
                  </p>
                </div>

                {/* 2. COPY & PASTE POWERSHELL COMMAND BOX */}
                <div className="rounded-lg border border-border bg-card shadow-xs overflow-hidden">
                  <div className="flex items-center justify-between border-b border-border bg-muted/40 px-3.5 py-2">
                    <div className="flex items-center gap-2">
                      <Terminal className="size-3.5 text-primary" />
                      <span className="font-mono text-[11px] font-semibold text-foreground">
                        PowerShell Command (Copy & Paste to Run)
                      </span>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => copyPowerShell(patch.powershellCommand, patch.id)}
                      className="h-6 gap-1 px-2 text-[10px] text-primary hover:text-primary hover:bg-primary/10"
                    >
                      {copiedPsId === patch.id ? <Check className="size-3" /> : <Copy className="size-3" />}
                      <span>{copiedPsId === patch.id ? 'Copied' : 'Copy Command'}</span>
                    </Button>
                  </div>
                  <div className="p-3.5 bg-muted/15 font-mono text-xs text-foreground overflow-x-auto leading-relaxed select-text">
                    <pre className="whitespace-pre-wrap">{patch.powershellCommand}</pre>
                  </div>
                  <div className="border-t border-border/60 bg-muted/30 px-3.5 py-1.5 text-[10px] text-muted-foreground flex items-center justify-between">
                    <span>Run this command in Windows PowerShell or pwsh terminal to apply or verify this remediation.</span>
                    <span className="font-mono text-primary">File: {patch.filePath}</span>
                  </div>
                </div>

                {/* 3. CODE / CONFIGURATION DIFF */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-foreground flex items-center gap-1.5">
                      <Code2 className="size-3.5 text-muted-foreground" />
                      Hardened Configuration / Patch Diff
                    </span>
                    <button
                      onClick={() => copyDiff(patch.diff, patch.id)}
                      className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                    >
                      {copiedId === patch.id ? <Check className="size-3 text-primary" /> : <Copy className="size-3" />}
                      <span>{copiedId === patch.id ? 'Copied' : 'Copy Diff'}</span>
                    </button>
                  </div>

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
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
