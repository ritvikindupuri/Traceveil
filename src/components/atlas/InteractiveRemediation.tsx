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
  ArrowRight,
  ChevronDown,
  ShieldAlert,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { AttackGraph } from '@/lib/atlas/types';
import { generateRemediationPatches, type RemediationPatch } from '@/lib/atlas/agent-operations';
import { generateCorrectedDrawIoXml, getArchitecturalRemediationGuide } from '@/lib/atlas/corrected-diagram';
import { cn } from '@/lib/utils';

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
            {/* Before */}
            <div className="rounded-lg border border-destructive/25 bg-destructive/[0.03] p-4 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-destructive flex items-center gap-1.5">
                  <ShieldAlert className="size-3.5" />
                  Before (Original Diagram)
                </span>
                <span className="rounded bg-destructive/15 px-1.5 py-0.5 text-[9px] font-bold text-destructive uppercase">
                  Vulnerable
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-1.5 py-1 font-mono text-[11px]">
                {guide.beforeTopology.nodes.map((node, nIdx) => (
                  <div key={nIdx} className="flex items-center gap-1.5">
                    <span className={cn(
                      "px-2 py-0.5 rounded border text-[11px]",
                      nIdx === guide.beforeTopology.nodes.length - 1
                        ? "bg-destructive/20 text-destructive border-destructive/40 font-bold"
                        : "bg-background border-border text-foreground"
                    )}>
                      {node}
                    </span>
                    {nIdx < guide.beforeTopology.nodes.length - 1 && (
                      <ArrowRight className="size-3 text-destructive shrink-0" />
                    )}
                  </div>
                ))}
              </div>
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                {guide.beforeTopology.riskCallout}
              </p>
            </div>

            {/* After */}
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/[0.03] p-4 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                  <ShieldCheck className="size-3.5" />
                  After (Zero-Trust Remediated)
                </span>
                <span className="rounded bg-emerald-500/15 px-2 py-0.5 text-[9px] font-bold text-emerald-600 uppercase">
                  Secured
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-1.5 py-1 font-mono text-[11px]">
                {guide.afterTopology.nodes.map((node, nIdx) => (
                  <div key={nIdx} className="flex items-center gap-1.5">
                    <span className={cn(
                      "px-2 py-0.5 rounded border text-[11px]",
                      nIdx === guide.afterTopology.nodes.length - 1
                        ? "bg-emerald-500/20 text-emerald-700 dark:text-emerald-400 border-emerald-500/40 font-bold"
                        : "bg-background border-border text-foreground"
                    )}>
                      {node}
                    </span>
                    {nIdx < guide.afterTopology.nodes.length - 1 && (
                      <ArrowRight className="size-3 text-emerald-600 shrink-0" />
                    )}
                  </div>
                ))}
              </div>
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                {guide.afterTopology.benefitCallout}
              </p>
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
  const [copiedPsId, setCopiedPsId] = useState<string | null>(null);
  const [copiedAllPs, setCopiedAllPs] = useState(false);

  const appliedCount = Object.values(appliedState).filter(Boolean).length;
  const totalCount = patches.length;
  const progressPercent = totalCount > 0 ? Math.round((appliedCount / totalCount) * 100) : 100;

  const activePatch = patches.find(p => p.id === selectedPatchId) || patches[0];
  const isApplied = Boolean(appliedState[activePatch?.id]);

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
      {/* 1. Single Clean Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-primary/30 bg-primary/5 p-5 shadow-xs">
        <div className="flex items-center gap-3.5">
          <div className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-primary/15 text-primary ring-1 ring-primary/30">
            <Wrench className="size-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-foreground">
                Code Remediation &amp; Hardening Studio
              </h2>
              <span className="rounded-full bg-primary/15 px-2 py-0.5 font-mono text-[9px] font-bold text-primary uppercase">
                {totalCount} {totalCount === 1 ? 'Fix' : 'Fixes'} Available
              </span>
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Target: <strong className="font-mono text-foreground">{graph.target}</strong> · Precision source-code diffs and direct terminal hardening fixes.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="default"
            onClick={copyAllPowerShellCommands}
            className="gap-1.5 text-xs shadow-xs"
          >
            {copiedAllPs ? <Check className="size-3.5 text-emerald-400" /> : <Terminal className="size-3.5" />}
            <span>{copiedAllPs ? 'Copied All Commands!' : 'Copy All PowerShell Fixes'}</span>
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
                <span className="truncate max-w-[200px]">{p.title}</span>
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
                  {activePatch.title}
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

          {/* Collapsible PowerShell Terminal Command & Scripting */}
          <details className="group/terminal rounded-lg border border-border/70 bg-muted/15 p-3">
            <summary className="cursor-pointer text-xs font-medium text-muted-foreground hover:text-foreground flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Terminal className="size-3.5 text-primary" />
                PowerShell CLI Command (Direct Terminal Execution)
              </span>
              <ChevronDown className="size-3.5 transition-transform group-open/terminal:rotate-180" />
            </summary>
            <div className="mt-3 space-y-2 pt-2 border-t border-border/50">
              <div className="rounded border border-border bg-card overflow-hidden">
                <div className="flex items-center justify-between border-b border-border bg-muted/30 px-3 py-1.5">
                  <span className="font-mono text-[10px] font-semibold text-foreground">
                    PowerShell Command
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => copyPowerShell(activePatch.powershellCommand, activePatch.id)}
                    className="h-5 gap-1 px-1.5 text-[9px] text-primary"
                  >
                    {copiedPsId === activePatch.id ? <Check className="size-2.5" /> : <Copy className="size-2.5" />}
                    <span>{copiedPsId === activePatch.id ? 'Copied' : 'Copy'}</span>
                  </Button>
                </div>
                <pre className="p-2.5 font-mono text-[11px] overflow-x-auto text-foreground leading-relaxed whitespace-pre-wrap">
                  {activePatch.powershellCommand}
                </pre>
              </div>
              <p className="text-[10px] text-muted-foreground">
                Run this command in Windows PowerShell or pwsh terminal to apply or verify this remediation directly.
              </p>
            </div>
          </details>
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
