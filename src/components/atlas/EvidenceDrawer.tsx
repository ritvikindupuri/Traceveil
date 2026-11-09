import { useState } from 'react';
import {
  X,
  ShieldAlert,
  FileCode,
  ExternalLink,
  Copy,
  Check,
  Wrench,
  Lock,
  ArrowRight,
  ShieldCheck,
  AlertTriangle,
  Code2,
  Terminal,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { AttackGraph, Finding, Evidence } from '@/lib/atlas/types';
import { cn } from '@/lib/utils';

export function EvidenceDrawer({
  selection,
  graph,
  onClose,
  onNavigateToRemediation,
}: {
  selection: { ids: string[]; label: string };
  graph: AttackGraph;
  onClose: () => void;
  onNavigateToRemediation?: () => void;
}) {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Match evidence items
  const matchedEvidence: Evidence[] = graph.evidence.filter(e => selection.ids.includes(e.id));

  // Match findings associated with this selection
  const matchedFinding: Finding | undefined = graph.findings.find(
    f => f.title === selection.label || f.evidenceIds.some(id => selection.ids.includes(id))
  );

  // Match node
  const matchedNode = graph.nodes.find(
    n => n.label === selection.label || n.evidenceIds.some(id => selection.ids.includes(id))
  );

  function copyText(text: string, id: string) {
    void navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  // Generate plain-English explanation based on rule or context
  function getRiskExplanation(rule?: string): { summary: string; impact: string; fixAdvice: string } {
    switch (rule) {
      case 'public-cidr':
        return {
          summary: 'Unrestricted Public Network Ingress',
          impact:
            'A security group or firewall rule specifies 0.0.0.0/0 (or ::/0), exposing management ports (such as SSH 22, RDP 3389, or web endpoints) directly to the entire internet. Automated botnets continuously probe these ranges for brute-force attacks and 0-day exploits.',
          fixAdvice:
            'Replace 0.0.0.0/0 with the specific CIDR block of your corporate VPN, private VPC subnet (e.g. 10.0.0.0/16), or trusted gateway.',
        };
      case 'mutable-action':
        return {
          summary: 'CI/CD Supply Chain Poisoning Risk',
          impact:
            'This workflow step references a GitHub Action using a mutable tag (e.g. @v3) rather than an immutable 40-character commit SHA. If the action repository or author account is compromised, malicious code can be injected directly into your build runner.',
          fixAdvice:
            'Pin the action to an immutable full commit SHA (e.g. actions/checkout@24cb9080177205b6e8c946b17badbe402dac938f).',
        };
      case 'workflow-write':
        return {
          summary: 'Excessive GITHUB_TOKEN Privileges',
          impact:
            'The workflow declares permissions: write-all, giving the ephemeral runner unrestricted write access across repository contents, packages, issues, and security events. A poisoned dependency or step script can push rogue commits.',
          fixAdvice:
            'Enforce least-privilege by declaring explicit read permissions: contents: read, pull-requests: read.',
        };
      case 'privileged':
        return {
          summary: 'Privileged Container Kernel Escape Risk',
          impact:
            'Container is configured with privileged: true, disabling Linux namespace isolation and granting full host device access (CAP_SYS_ADMIN). Processes can mount host filesystems and escape container containment.',
          fixAdvice:
            'Set privileged: false, allowPrivilegeEscalation: false, and drop all unnecessary Linux capabilities.',
        };
      case 'root-user':
        return {
          summary: 'Root Execution in Container (UID 0)',
          impact:
            'The container process runs as root (UID 0). In the event of a remote code execution vulnerability, an attacker immediately obtains full root privileges within the container.',
          fixAdvice:
            'Add a non-root user (e.g. USER appuser) in your Dockerfile and run all workloads with unprivileged UIDs.',
        };
      case 'credential-pattern':
        return {
          summary: 'Hardcoded Secret / API Token in Source',
          impact:
            'A plaintext API key, private key, or credential token pattern was detected in the repository snapshot. Anyone with read access to the repository can replay this token.',
          fixAdvice:
            'Immediately revoke and rotate this credential, and migrate secret retrieval to runtime environment variables or a secrets manager.',
        };
      default:
        return {
          summary: matchedFinding?.title || 'Security Finding & Evidence Details',
          impact:
            'This entity represents an active finding or declared resource on your repository attack surface. Review the source code evidence below to evaluate exploitability.',
          fixAdvice: matchedFinding?.fix || 'Review least-privilege configurations for this resource.',
        };
    }
  }

  const riskInfo = getRiskExplanation(matchedFinding?.rule);
  const severity = matchedFinding?.severity || matchedNode?.severity;

  return (
    <aside className="atlas-evidence flex flex-col h-full bg-card border-l border-border select-text">
      {/* Drawer Header */}
      <div className="shrink-0 flex items-start justify-between gap-3 border-b border-border p-4 bg-muted/20">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[9px] uppercase tracking-wider text-primary font-semibold">
              Source Code Evidence
            </span>
            
          </div>

          <h2 className="mt-1.5 text-sm font-semibold text-foreground leading-snug break-words">
            {selection.label}
          </h2>

          {severity && (
            <div className="mt-2 flex items-center gap-2">
              <span
                className={cn(
                  'inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider',
                  severity === 'high'
                    ? 'bg-destructive/20 text-destructive border border-destructive/30'
                    : 'bg-warning/20 text-warning border border-warning/30'
                )}
              >
                <ShieldAlert className="size-3" />
                {severity} SEVERITY
              </span>
              {matchedFinding?.rule && (
                <span className="font-mono text-[10px] text-muted-foreground">
                  rule: {matchedFinding.rule}
                </span>
              )}
            </div>
          )}
        </div>

        <Button
          variant="ghost"
          size="icon"
          aria-label="Close evidence"
          onClick={onClose}
          className="size-7 shrink-0 text-muted-foreground hover:text-foreground"
        >
          <X className="size-4" />
        </Button>
      </div>

      {/* Drawer Scrollable Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-5">
        {/* Risk Explanation Card */}
        <div className="rounded-lg border border-border/80 bg-background/60 p-3.5 space-y-2.5">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
            <AlertTriangle className={cn('size-3.5', severity === 'high' ? 'text-destructive' : 'text-warning')} />
            <span>Why This Is Risky</span>
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground">
            {riskInfo.impact}
          </p>

          <div className="border-t border-border/50 pt-2 text-[11px] text-muted-foreground">
            <strong className="text-foreground">Remediation Target:</strong> {riskInfo.fixAdvice}
          </div>
        </div>

        {/* Source Code Evidence Blocks */}
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs font-medium text-foreground">
            <span className="flex items-center gap-1.5">
              <Code2 className="size-3.5 text-primary" />
              Source Evidence ({matchedEvidence.length})
            </span>
            <span className="font-mono text-[10px] text-muted-foreground">
              Commit {graph.commit.slice(0, 8)}
            </span>
          </div>

          {matchedEvidence.map(ev => {
            const fileName = ev.path.split('/').pop() || ev.path;

            return (
              <div key={ev.id} className="rounded-lg border border-border bg-card/80 overflow-hidden shadow-sm">
                {/* File Header */}
                <div className="flex items-center justify-between gap-2 border-b border-border/80 bg-muted/40 px-3 py-2 text-xs">
                  <a
                    href={ev.url}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1.5 font-mono text-[11px] text-primary hover:underline truncate"
                    title={ev.path}
                  >
                    <FileCode className="size-3.5 shrink-0" />
                    <span className="truncate">{ev.path}</span>
                    <span className="text-muted-foreground shrink-0">:{ev.line}</span>
                    <ExternalLink className="size-3 shrink-0 ml-0.5 opacity-70" />
                  </a>

                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      onClick={() => copyText(ev.path, `path-${ev.id}`)}
                      className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                      title="Copy file path"
                    >
                      {copiedId === `path-${ev.id}` ? (
                        <Check className="size-3 text-primary" />
                      ) : (
                        <Copy className="size-3" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Source Code Excerpt */}
                <div className="relative rounded-md border border-border bg-muted/20 p-3 font-mono text-xs text-foreground">
                  <div className="overflow-x-auto whitespace-pre text-foreground leading-relaxed">
                    {ev.excerpt}
                  </div>
                </div>

                {/* Footer Metadata */}
                <div className="flex items-center justify-between border-t border-border/60 bg-muted/20 px-3 py-1.5 font-mono text-[9px] text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Lock className="size-2.5 text-emerald-400" />
                    Evidence ID: {ev.id}
                  </span>
                  <span>{new Date(ev.collectedAt).toLocaleTimeString()}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Action Button: Jump to Remediation Studio */}
        {onNavigateToRemediation && (
          <div className="rounded-lg border border-primary/30 bg-primary/5 p-3 flex items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <Wrench className="size-3 text-primary" />
                <span>One-Click Code Fix</span>
              </div>
              <p className="mt-0.5 text-[11px] text-muted-foreground truncate">
                Generate and download code patch for this finding.
              </p>
            </div>
            <Button
              size="sm"
              onClick={onNavigateToRemediation}
              className="gap-1.5 text-xs shrink-0"
            >
              <span>Remediate</span>
              <ArrowRight className="size-3" />
            </Button>
          </div>
        )}
      </div>
    </aside>
  );
}
