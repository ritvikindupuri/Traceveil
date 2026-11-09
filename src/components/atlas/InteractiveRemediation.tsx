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
              <h2 className="text-sm font-semibold">
                {isDiagram ? 'Architecture Remediation & Hardening Studio' : 'Remediation & Hardening Studio'}
              </h2>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {isDiagram
                ? 'Visual architectural fixes, step-by-step diagram modification instructions, and exportable corrected draw.io file.'
                : 'Actionable security suggestions, configuration diffs, and copy-and-paste PowerShell commands. Run commands directly in your own terminal.'}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {isDiagram ? (
              <>
                <Button
                  variant="default"
                  size="sm"
                  onClick={downloadCorrectedDrawIoDiagram}
                  className="gap-1.5 text-xs bg-emerald-600 hover:bg-emerald-700 text-white shadow-xs"
                >
                  <Download className="size-3.5" />
                  <span>Download Corrected draw.io (.drawio)</span>
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={downloadAllPatches}
                  className="gap-1.5 text-xs"
                >
                  <Download className="size-3.5" />
                  <span>Export Policies</span>
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={copyAllPowerShellCommands}
                  className="gap-1.5 text-xs text-muted-foreground hover:text-foreground"
                >
                  <Terminal className="size-3.5" />
                  <span>Copy PowerShell</span>
                </Button>
              </>
            ) : (
              <>
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
                  <span>Download .patch</span>
                </Button>
              </>
            )}
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
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4 shadow-xs">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-600">
                <Layers className="size-5" />
              </div>
              <div className="min-w-0">
                <h3 className="text-xs font-semibold text-foreground flex items-center gap-2">
                  <span>Architecture &amp; Diagram Remediation Studio</span>
                  <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-600 uppercase">
                    Diagram Mode
                  </span>
                </h3>
                <p className="text-[11px] text-muted-foreground truncate">
                  Target: <strong className="font-mono text-foreground">{graph.target.replace('diagram://', '')}</strong> · Download the corrected draw.io diagram file with zero-trust fixes applied, or review the visual before/after changes below.
                </p>
              </div>
            </div>

            <Button
              size="sm"
              variant="default"
              onClick={downloadCorrectedDrawIoDiagram}
              className="h-8 gap-1.5 text-xs bg-emerald-600 hover:bg-emerald-700 text-white shadow-xs"
            >
              <Download className="size-3.5" />
              <span>Download Corrected draw.io (.drawio)</span>
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
          const finding = graph.findings.find(f => f.id === patch.findingId);
          const guide = isDiagram ? getArchitecturalRemediationGuide(finding?.rule || 'database-exposure', patch.title) : null;

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
                      {isDiagram ? (
                        <>
                          <Layers className="size-3 text-emerald-600" />
                          <span>Architecture Model · Zero-Trust Subnet &amp; Perimeter Hardening</span>
                        </>
                      ) : (
                        <>
                          <FileCode className="size-3" />
                          <span>{patch.filePath}:{patch.line}</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  {isDiagram ? (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={downloadCorrectedDrawIoDiagram}
                        className="gap-1.5 text-xs text-emerald-600 border-emerald-500/30 hover:bg-emerald-500/10"
                      >
                        <Download className="size-3 text-emerald-600" />
                        <span>Download Corrected .drawio</span>
                      </Button>
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
                        <span>{isApplied ? 'Resolved in Diagram' : 'Mark as Resolved'}</span>
                      </Button>
                    </>
                  ) : (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyPowerShell(patch.powershellCommand, patch.id)}
                        className="gap-1.5 text-xs text-primary border-primary/30 hover:bg-primary/10"
                      >
                        {copiedPsId === patch.id ? <Check className="size-3 text-primary" /> : <Terminal className="size-3" />}
                        <span>{copiedPsId === patch.id ? 'Copied Command!' : 'Copy PowerShell'}</span>
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyDiff(patch.diff, patch.id)}
                        className="gap-1.5 text-xs text-muted-foreground hover:text-foreground"
                      >
                        {copiedId === patch.id ? <Check className="size-3 text-primary" /> : <Copy className="size-3" />}
                        <span>{copiedId === patch.id ? 'Copied Diff' : 'Copy Diff'}</span>
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => downloadPatch(patch)}
                        className="gap-1.5 text-xs text-muted-foreground hover:text-foreground"
                      >
                        <Download className="size-3" />
                        <span>.patch</span>
                      </Button>
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
                    </>
                  )}
                </div>
              </div>

              {/* Body */}
              <div className="p-4 space-y-4">
                {/* 1. AGENT SUGGESTION CALLOUT */}
                <div className="rounded-lg border border-primary/20 bg-primary/5 p-3.5 text-xs space-y-1.5">
                  <div className="flex items-center gap-2 font-semibold text-foreground">
                    <Sparkles className="size-4 text-primary" />
                    <span>Agent Architectural Suggestion &amp; Root Cause</span>
                  </div>
                  <p className="text-muted-foreground leading-relaxed pl-6">
                    {patch.suggestion}
                  </p>
                  <p className="text-[11px] text-muted-foreground/80 pl-6 border-t border-primary/10 pt-1.5">
                    <strong>Architectural Rationale:</strong> {patch.explanation}
                  </p>
                </div>

                {isDiagram && guide ? (
                  <>
                    {/* 2. VISUAL ARCHITECTURAL BEFORE & AFTER TOPOLOGY */}
                    <div className="space-y-3 rounded-lg border border-border bg-muted/10 p-3.5">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-xs text-foreground flex items-center gap-1.5">
                          <Layers className="size-3.5 text-primary" />
                          Visual Architecture Remediation Breakdown
                        </span>
                        <span className="text-[10px] text-muted-foreground font-mono">
                          Topology Flow Comparison
                        </span>
                      </div>

                      <div className="grid gap-3 lg:grid-cols-2">
                        {/* Before Card */}
                        <div className="rounded-md border border-destructive/30 bg-destructive/[0.04] p-3 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-semibold text-destructive flex items-center gap-1">
                              <ShieldAlert className="size-3.5" />
                              {guide.beforeTopology.title}
                            </span>
                            <span className="rounded bg-destructive/15 px-1.5 py-0.5 text-[9px] font-bold text-destructive uppercase">
                              Insecure
                            </span>
                          </div>
                          <p className="text-[11px] text-muted-foreground">
                            {guide.beforeTopology.description}
                          </p>
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
                          <div className="rounded bg-destructive/10 p-2 text-[10px] text-destructive leading-relaxed border border-destructive/20">
                            <strong>Threat Impact:</strong> {guide.beforeTopology.riskCallout}
                          </div>
                        </div>

                        {/* After Card */}
                        <div className="rounded-md border border-emerald-500/30 bg-emerald-500/[0.04] p-3 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                              <ShieldCheck className="size-3.5" />
                              {guide.afterTopology.title}
                            </span>
                            <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[9px] font-bold text-emerald-600 uppercase">
                              Zero-Trust Fixed
                            </span>
                          </div>
                          <p className="text-[11px] text-muted-foreground">
                            {guide.afterTopology.description}
                          </p>
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
                          <div className="rounded bg-emerald-500/10 p-2 text-[10px] text-emerald-700 dark:text-emerald-300 leading-relaxed border border-emerald-500/20">
                            <strong>Security Gain:</strong> {guide.afterTopology.benefitCallout}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* 3. STEP-BY-STEP DIAGRAM EDITING GUIDE */}
                    <div className="space-y-2.5 rounded-lg border border-border bg-card p-3.5">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-xs text-foreground flex items-center gap-1.5">
                          <Sparkles className="size-3.5 text-primary" />
                          Step-by-Step Diagram Editing Guide (for draw.io / diagrams.net)
                        </span>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={downloadCorrectedDrawIoDiagram}
                          className="h-6 gap-1 px-2 text-[10px] text-emerald-600 hover:text-emerald-700 hover:bg-emerald-500/10"
                        >
                          <Download className="size-3" />
                          <span>Get Finished .drawio</span>
                        </Button>
                      </div>

                      <ol className="space-y-1.5 text-xs text-muted-foreground">
                        {guide.drawIoSteps.map((step, sIdx) => (
                          <li key={sIdx} className="flex items-start gap-2.5">
                            <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-primary/10 font-mono text-[10px] font-bold text-primary mt-0.5">
                              {sIdx + 1}
                            </span>
                            <span className="leading-relaxed text-[11px] text-foreground/90">{step}</span>
                          </li>
                        ))}
                      </ol>
                    </div>

                    {/* 4. OPTIONAL COLLAPSIBLE CODE / IAC SECTION */}
                    <details className="group/code rounded-lg border border-border/70 bg-muted/15 p-3">
                      <summary className="cursor-pointer text-xs font-medium text-muted-foreground hover:text-foreground flex items-center justify-between">
                        <span className="flex items-center gap-1.5">
                          <Terminal className="size-3.5" />
                          Optional: View Infrastructure-as-Code (Terraform) &amp; PowerShell CLI Commands
                        </span>
                        <ChevronDown className="size-3.5 transition-transform group-open/code:rotate-180" />
                      </summary>
                      <div className="mt-3 space-y-3 pt-2 border-t border-border/50">
                        {/* PowerShell Command */}
                        <div className="rounded border border-border bg-card overflow-hidden">
                          <div className="flex items-center justify-between border-b border-border bg-muted/30 px-3 py-1.5">
                            <span className="font-mono text-[10px] font-semibold text-foreground">
                              PowerShell Command
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyPowerShell(patch.powershellCommand, patch.id)}
                              className="h-5 gap-1 px-1.5 text-[9px] text-primary"
                            >
                              {copiedPsId === patch.id ? <Check className="size-2.5" /> : <Copy className="size-2.5" />}
                              <span>{copiedPsId === patch.id ? 'Copied' : 'Copy'}</span>
                            </Button>
                          </div>
                          <pre className="p-2.5 font-mono text-[11px] overflow-x-auto text-foreground leading-relaxed whitespace-pre-wrap">
                            {patch.powershellCommand}
                          </pre>
                        </div>

                        {/* Terraform Diff */}
                        <div className="rounded border border-border bg-card overflow-hidden">
                          <div className="flex items-center justify-between border-b border-border bg-muted/30 px-3 py-1.5">
                            <span className="font-mono text-[10px] font-semibold text-foreground">
                              Configuration Patch: {patch.filePath}
                            </span>
                            <button
                              onClick={() => copyDiff(patch.diff, patch.id)}
                              className="text-[9px] text-muted-foreground hover:text-foreground flex items-center gap-1"
                            >
                              {copiedId === patch.id ? <Check className="size-2.5 text-primary" /> : <Copy className="size-2.5" />}
                              <span>{copiedId === patch.id ? 'Copied' : 'Copy Diff'}</span>
                            </button>
                          </div>
                          <div className="overflow-x-auto p-2 font-mono text-[10px]">
                            {patch.diff.split('\n').map((line, lIdx) => {
                              const isAddition = line.startsWith('+') && !line.startsWith('+++');
                              const isDeletion = line.startsWith('-') && !line.startsWith('---');
                              const isHeader = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');
                              return (
                                <div
                                  key={lIdx}
                                  className={cn(
                                    'px-1.5 py-0.2 rounded-xs leading-relaxed',
                                    isAddition && 'bg-emerald-500/10 text-emerald-600 font-semibold',
                                    isDeletion && 'bg-destructive/10 text-destructive line-through opacity-85',
                                    isHeader && 'text-muted-foreground opacity-60'
                                  )}
                                >
                                  {line}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    </details>
                  </>
                ) : (
                  <>
                    {/* Standard Repo / Live App Remediation */}
                    <div className="rounded-lg border border-border bg-card shadow-xs overflow-hidden">
                      <div className="flex items-center justify-between border-b border-border bg-muted/40 px-3.5 py-2">
                        <div className="flex items-center gap-2">
                          <Terminal className="size-3.5 text-primary" />
                          <span className="font-mono text-[11px] font-semibold text-foreground">
                            PowerShell Command (Copy &amp; Paste to Run)
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
                  </>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
