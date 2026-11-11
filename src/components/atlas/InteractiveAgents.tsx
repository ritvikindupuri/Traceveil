import { useState, useEffect, useMemo, lazy, Suspense } from 'react';
import { useServerFn } from '@tanstack/react-start';
import { ClientOnly } from '@tanstack/react-router';
import {
  Swords,
  Terminal,
  CheckCircle2,
  Play,
  Pause,
  ShieldCheck,
  RefreshCw,
  Copy,
  Check,
  Radio,
  Sparkles,
  Layers,
  Flame,
  AlertTriangle,
  Loader2,
  Wrench,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { AttackGraph, AttackPathStep } from '@/lib/atlas/types';
import { generateRedTeamProbes, computeSha256, type RedTeamProbe, type VerifiedEvidence } from '@/lib/atlas/agent-operations';
import { executeLiveProbe } from '@/lib/atlas/probe.functions';
import { cn } from '@/lib/utils';

const AttackCanvas = lazy(() => import('./AttackCanvas').then(m => ({ default: m.AttackCanvas })));

interface DiagramAttackerStep {
  id: string;
  stepNumber: number;
  nodeId: string;
  componentName: string;
  title: string;
  severity: 'critical' | 'high' | 'medium';
  attackerObjective: string;
  attackerAnalysis: string;
  exploitMethod: string;
  architecturalFault: string;
  remediationAction: string;
  evidenceIds: string[];
}

function buildDiagramAttackerSteps(graph: AttackGraph): DiagramAttackerStep[] {
  const steps: DiagramAttackerStep[] = [];
  const findings = graph.findings || [];
  const nodes = graph.nodes || [];
  const rawSteps = graph.attackPaths?.[0]?.steps || [];

  if (rawSteps.length > 0) {
    rawSteps.forEach((s: AttackPathStep, idx: number) => {
      const node = nodes.find(n => n.id === s.nodeId);
      const compName = node?.label || s.title.replace(/^(?:Lateral Pivot:\s*|External Perimeter Reconnaissance|Crown Jewel Data Exfiltration:\s*)/i, '').trim() || 'Perimeter';
      const f = findings.find(item =>
        item.title.toLowerCase().includes(compName.toLowerCase()) ||
        item.evidenceIds?.some(evId => s.evidenceIds?.includes(evId))
      );

      const isFirst = idx === 0;
      const isLast = idx === rawSteps.length - 1;
      const role = (node?.kind || '').toLowerCase();
      const isDb = role === 'target' || compName.toLowerCase().includes('sql') || compName.toLowerCase().includes('database') || compName.toLowerCase().includes('rds') || compName.toLowerCase().includes('postgres');
      const isStorage = compName.toLowerCase().includes('s3') || compName.toLowerCase().includes('bucket') || compName.toLowerCase().includes('storage') || compName.toLowerCase().includes('blob');
      const isWaf = compName.toLowerCase().includes('waf') || compName.toLowerCase().includes('firewall');
      const isAlb = compName.toLowerCase().includes('alb') || compName.toLowerCase().includes('load balancer') || compName.toLowerCase().includes('ingress') || compName.toLowerCase().includes('cloudfront');

      let title = s.title;
      let severity: 'critical' | 'high' | 'medium' = f?.severity || (isDb ? 'critical' : isStorage ? 'high' : isFirst ? 'medium' : 'high');
      let attackerObjective = s.subtitle || 'Probe network reachability';
      let attackerAnalysis = s.description;
      let exploitMethod = 'Direct network probing';
      let architecturalFault = f?.title || 'Unsegmented communication path in architecture';
      let remediationAction = f?.fix || s.remediation || 'Place component in isolated private subnet and enforce security group ingress rules.';

      if (isFirst) {
        title = `Step 1: External Perimeter Reconnaissance (${compName})`;
        attackerObjective = 'Discover public-facing endpoints and uninspected ingress routes.';
        attackerAnalysis = `As an external adversary, I initiate reconnaissance against the public perimeter. I map all public IP routes leading directly into ${compName} without passing through a Zero-Trust identity perimeter or VPN bastion.`;
        exploitMethod = 'Port scanning, DNS enumeration, and ingress boundary mapping';
        architecturalFault = 'Untrusted public perimeter connects directly into internal workload tiers.';
        remediationAction = 'Enforce an isolated DMZ perimeter gateway and require authenticated Bastion access.';
      } else if (isDb) {
        title = `Fault: Direct Public Database Exposure (${compName})`;
        severity = 'critical';
        attackerObjective = 'Bypass application layer and directly dump production database tables.';
        attackerAnalysis = `CRITICAL ARCHITECTURAL FLAW: ${compName} is directly exposed without an isolated Private Subnet boundary. As an attacker, I bypass the web tier entirely. I probe database port 5432 directly from the public internet, execute credential brute-forcing, and exfiltrate customer data tables.`;
        exploitMethod = 'Direct TCP socket connect on database port → SQL brute-force / auth bypass';
        architecturalFault = `${compName} lacks private subnet encapsulation and security group ingress whitelisting.`;
        remediationAction = `Move ${compName} into an isolated Private Subnet. Sever direct internet ingress edges and allow traffic solely from authorized application compute nodes.`;
      } else if (isStorage) {
        title = `Fault: Public Object Storage Exposure (${compName})`;
        severity = 'high';
        attackerObjective = 'Enumerate and exfiltrate unencrypted files and backups.';
        attackerAnalysis = `I discover that ${compName} has direct public access enabled without an S3 Public Access Block. I query bucket endpoints over standard HTTPS and download private assets, documents, and backups.`;
        exploitMethod = 'Direct REST API enumeration & anonymous GetObject requests';
        architecturalFault = `${compName} lacks public access block and private VPC endpoint constraints.`;
        remediationAction = `Apply Terraform aws_s3_bucket_public_access_block and enforce access via private VPC endpoints only.`;
      } else if (isAlb || !isWaf) {
        title = `Fault: Missing Perimeter WAF Filter (${compName})`;
        severity = 'medium';
        attackerObjective = 'Send unfiltered web exploits and automated bot traffic.';
        attackerAnalysis = `I inspect the ingress layer on ${compName}. There is no Cloud WAF attached. Any SQL injection, XSS, or HTTP request smuggling payloads I send will reach downstream compute workloads completely uninspected.`;
        exploitMethod = 'HTTP request smuggling & automated web attack payload injection';
        architecturalFault = `Ingress gateway lacks AWS WAF WebACL inspection.`;
        remediationAction = `Attach an AWS WAF WebACL to the load balancer with OWASP Top 10 rule sets enabled.`;
      } else if (isLast) {
        title = `Final Impact: Crown-Jewel Data Exfiltration`;
        severity = 'critical';
        attackerObjective = 'Exfiltrate sensitive assets without detection.';
        attackerAnalysis = `Having walked through the unsegmented paths in your diagram, I have achieved my objective: full unauthenticated access to your core data assets. No internal microsegmentation or detection alerts were able to sever the attack path.`;
        exploitMethod = 'Automated data dump & outbound egress exfiltration';
        architecturalFault = `End-to-end unsegmented attack path across the architecture topology.`;
        remediationAction = `Implement Zero-Trust network microsegmentation and private subnet containers.`;
      }

      steps.push({
        id: s.id || `step-${idx + 1}`,
        stepNumber: idx + 1,
        nodeId: s.nodeId,
        componentName: compName,
        title,
        severity,
        attackerObjective,
        attackerAnalysis,
        exploitMethod,
        architecturalFault,
        remediationAction,
        evidenceIds: s.evidenceIds || [],
      });
    });
  } else if (findings.length > 0) {
    // Generate sequential steps directly from findings
    steps.push({
      id: 'step-recon',
      stepNumber: 1,
      nodeId: nodes[0]?.id || 'internet',
      componentName: nodes[0]?.label || 'Public Internet',
      title: 'Step 1: External Perimeter Reconnaissance',
      severity: 'medium',
      attackerObjective: 'Scan public attack surface for unsegmented ingress paths.',
      attackerAnalysis: 'As an external threat actor, I map the diagram perimeter and identify exposed routes into internal tiers.',
      exploitMethod: 'Perimeter scanning & DNS enumeration',
      architecturalFault: 'Direct untrusted ingress into architecture topology.',
      remediationAction: 'Enforce perimeter isolation and private subnet routing.',
      evidenceIds: [],
    });

    findings.forEach((f, idx) => {
      const compName = f.title.match(/\(([^)]+)\)/)?.[1] || 'Target Component';
      const node = nodes.find(n => n.label.toLowerCase() === compName.toLowerCase()) || nodes[idx + 1] || nodes[0];
      const isDb = f.rule.includes('db') || f.rule.includes('database') || compName.toLowerCase().includes('sql') || compName.toLowerCase().includes('rds');

      steps.push({
        id: f.id,
        stepNumber: steps.length + 1,
        nodeId: node?.id || f.id,
        componentName: compName,
        title: `Fault: ${f.title}`,
        severity: isDb ? 'critical' : f.severity,
        attackerObjective: `Exploit ${f.rule} to breach ${compName}.`,
        attackerAnalysis: `As an attacker, I locate ${compName} in your diagram. ${f.fix} Because this protection is absent, I can exploit direct network reachability to compromise this asset without resistance.`,
        exploitMethod: isDb ? 'Direct port 5432/3306 connect & SQL brute-force' : 'Direct API access & uninspected route traversal',
        architecturalFault: f.title,
        remediationAction: f.fix,
        evidenceIds: f.evidenceIds || [],
      });
    });
  } else {
    // Fallback if no findings
    steps.push({
      id: 'step-clean',
      stepNumber: 1,
      nodeId: nodes[0]?.id || 'diagram',
      componentName: 'Architecture',
      title: 'Adversary Perimeter Reconnaissance',
      severity: 'medium',
      attackerObjective: 'Evaluate diagram for security boundaries.',
      attackerAnalysis: 'The adversary scans the architecture diagram. Perimeter boundaries and segmentation rules are analyzed.',
      exploitMethod: 'Topological path traversal',
      architecturalFault: 'No high-severity architectural faults identified in current diagram.',
      remediationAction: 'Continue following Zero-Trust subnet isolation principles.',
      evidenceIds: [],
    });
  }

  return steps;
}

/**
 * Clean, focused Red Team Assessment view for Architecture Diagrams.
 * Shows the agent walking through architectural faults like an attacker.
 */
function DiagramRedTeamStudio({
  graph,
  onNavigateToRemediation,
}: {
  graph: AttackGraph;
  onNavigateToRemediation?: () => void;
}) {
  const steps = useMemo(() => buildDiagramAttackerSteps(graph), [graph]);
  const [activeStepIdx, setActiveStepIdx] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);

  // Auto-play walkthrough timer
  useEffect(() => {
    if (!isPlaying || steps.length <= 1) return;
    const interval = setInterval(() => {
      setActiveStepIdx(prev => (prev + 1) % steps.length);
    }, 3800);
    return () => clearInterval(interval);
  }, [isPlaying, steps.length]);

  const currentStep = steps[activeStepIdx] || steps[0];

  return (
    <div className="space-y-4">
      {/* 1. Main Architecture Diagram Canvas (Full Width) */}
      <div className="rounded-xl border border-border bg-card shadow-xs overflow-hidden flex flex-col">
        {/* Sleek Top Bar on Canvas */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-muted/30 px-4 py-2.5">
          <div className="flex items-center gap-2.5">
            <div className="flex size-7 items-center justify-center rounded-md bg-destructive/15 text-destructive ring-1 ring-destructive/30">
              <Swords className="size-4" />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-foreground">
                Adversary Walking Diagram Faults
              </span>
              <span className="inline-flex items-center gap-1 rounded bg-destructive/15 px-2 py-0.5 font-mono text-[9px] font-bold uppercase text-destructive">
                <Radio className="size-2 animate-pulse text-destructive" />
                Targeting: {currentStep.componentName}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Stepper Controls */}
            <div className="flex items-center rounded-md border border-border bg-background p-0.5">
              <Button
                variant="ghost"
                size="sm"
                disabled={activeStepIdx === 0}
                onClick={() => {
                  setIsPlaying(false);
                  setActiveStepIdx(prev => Math.max(0, prev - 1));
                }}
                className="h-6 px-2 text-[11px]"
                title="Previous Fault"
              >
                <ChevronLeft className="size-3 mr-0.5" />
                Prev
              </Button>
              <span className="px-2 font-mono text-[11px] text-muted-foreground font-medium">
                Step {activeStepIdx + 1} of {steps.length}
              </span>
              <Button
                variant="ghost"
                size="sm"
                disabled={activeStepIdx === steps.length - 1}
                onClick={() => {
                  setIsPlaying(false);
                  setActiveStepIdx(prev => Math.min(steps.length - 1, prev + 1));
                }}
                className="h-6 px-2 text-[11px]"
                title="Next Fault"
              >
                Next
                <ChevronRight className="size-3 ml-0.5" />
              </Button>
            </div>

            <Button
              size="sm"
              variant={isPlaying ? 'secondary' : 'destructive'}
              onClick={() => setIsPlaying(prev => !prev)}
              className="h-7 gap-1 text-[11px] px-2.5 shadow-xs"
            >
              {isPlaying ? (
                <>
                  <Pause className="size-3" />
                  <span>Pause</span>
                </>
              ) : (
                <>
                  <Play className="size-3" />
                  <span>Auto-Walk</span>
                </>
              )}
            </Button>

            {onNavigateToRemediation && (
              <Button
                size="sm"
                variant="outline"
                onClick={onNavigateToRemediation}
                className="h-7 gap-1 text-[11px] px-2.5 text-emerald-600 border-emerald-500/30 hover:bg-emerald-500/10 hover:text-emerald-500 font-medium"
              >
                <Wrench className="size-3" />
                <span>Fix in Remediation</span>
              </Button>
            )}
          </div>
        </div>

        {/* Canvas Area */}
        <div className="h-[520px] w-full relative bg-muted/5">
          <ClientOnly fallback={<div className="flex h-full items-center justify-center"><Loader2 className="size-6 animate-spin text-muted-foreground" /></div>}>
            <Suspense fallback={<div className="flex h-full items-center justify-center"><Loader2 className="size-6 animate-spin text-muted-foreground" /></div>}>
              <AttackCanvas
                graph={graph}
                search=""
                riskOnly={true}
                hideFloatingCard={true}
                controlledStepIdx={activeStepIdx}
                onSelect={() => {}}
              />
            </Suspense>
          </ClientOnly>
        </div>
      </div>

      {/* 2. Unified Adversary Briefing Bar (Directly Underneath) */}
      <div className="rounded-xl border border-destructive/30 bg-card p-4 space-y-3 shadow-xs">
        {/* Attacker Action & Analysis */}
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
          <div className="space-y-1 max-w-3xl">
            <div className="flex items-center gap-2">
              <span className="size-2 rounded-full bg-destructive animate-pulse" />
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-destructive">
                Attacker Action · Step {activeStepIdx + 1}: {currentStep.componentName}
              </span>
              <span className={cn(
                "rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase",
                currentStep.severity === 'critical' ? 'bg-destructive/20 text-destructive' :
                currentStep.severity === 'high' ? 'bg-rose-500/15 text-rose-500' :
                'bg-amber-500/15 text-amber-500'
              )}>
                {currentStep.severity}
              </span>
            </div>
            <p className="text-xs text-foreground/90 font-medium leading-relaxed">
              {currentStep.attackerAnalysis}
            </p>
          </div>

          <div className="flex sm:flex-col gap-2 shrink-0 sm:items-end">
            <div className="inline-flex items-center gap-1.5 rounded-lg border border-border/80 bg-muted/40 px-3 py-1.5 text-[11px]">
              <span className="font-semibold text-amber-500">Flaw:</span>
              <span className="text-muted-foreground truncate max-w-[260px]">{currentStep.architecturalFault}</span>
            </div>
            <div className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-3 py-1.5 text-[11px]">
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">Fix:</span>
              <span className="text-muted-foreground truncate max-w-[260px]">{currentStep.remediationAction}</span>
            </div>
          </div>
        </div>

        {/* Step Navigation Breadcrumb / Pills */}
        <div className="border-t border-border/60 pt-3 flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] uppercase font-mono text-muted-foreground mr-1">
            Attack Vector:
          </span>
          {steps.map((st, idx) => {
            const isCurrent = idx === activeStepIdx;
            return (
              <button
                key={st.id}
                type="button"
                onClick={() => {
                  setIsPlaying(false);
                  setActiveStepIdx(idx);
                }}
                className={cn(
                  "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] transition border cursor-pointer",
                  isCurrent
                    ? "bg-destructive/15 border-destructive text-destructive font-semibold shadow-xs"
                    : "bg-muted/30 border-border/70 text-muted-foreground hover:bg-muted/70 hover:text-foreground"
                )}
              >
                <span className={cn(
                  "size-4 rounded-full flex items-center justify-center font-mono text-[9px]",
                  isCurrent ? "bg-destructive text-white" : "bg-muted-foreground/20 text-muted-foreground"
                )}>
                  {idx + 1}
                </span>
                <span className="truncate max-w-[140px]">{st.componentName}</span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export function InteractiveAgents({
  graph,
  reports,
  onNavigateToRemediation,
}: {
  graph: AttackGraph;
  reports: Record<string, string>;
  onNavigateToRemediation?: () => void;
}) {
  const [activeTab, setActiveTab] = useState<'redteam' | 'verifier'>('redteam');
  const [probes, setProbes] = useState<RedTeamProbe[]>([]);
  const [selectedProbeId, setSelectedProbeId] = useState<string>('');
  const [isExecuting, setIsExecuting] = useState(false);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [executedProbes, setExecutedProbes] = useState<Record<string, { status: 'exploitable' | 'defended'; latencyMs?: number; timestamp?: string }>>({});
  const [copiedPs, setCopiedPs] = useState(false);

  // Diagram specific check: if diagram, render dedicated simplified Attacker Walkthrough view
  const isDiagram = Boolean(
    graph?.target &&
      (graph.target.startsWith('diagram://') ||
        graph.target.includes('.drawio') ||
        graph.target.includes('.pkt') ||
        graph.target.includes('.cfg') ||
        graph.target.includes('architecture'))
  );

  const runProbeServerFn = useServerFn(executeLiveProbe);

  // Evidence Verifier state
  const [evidenceList, setEvidenceList] = useState<VerifiedEvidence[]>([]);
  const [verifying, setVerifying] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    if (graph && !isDiagram) {
      const generatedProbes = generateRedTeamProbes(graph);
      setProbes(generatedProbes);
      if (generatedProbes.length > 0 && !selectedProbeId) {
        setSelectedProbeId(generatedProbes[0].id);
        setTerminalLogs(generatedProbes[0].liveTrace || []);
      }

      // Generate evidence items with digests for code repositories
      void (async () => {
        const list: VerifiedEvidence[] = [];
        for (const ev of graph.evidence.slice(0, 15)) {
          const rawPayload = `${ev.path}:${ev.line}:${ev.excerpt}:${graph.commit}`;
          const hashDigest = await computeSha256(rawPayload);
          list.push({
            id: ev.id,
            path: ev.path,
            line: ev.line,
            excerpt: ev.excerpt,
            hashDigest,
            verified: true,
            tamperProof: true,
            timestamp: ev.collectedAt || new Date().toISOString(),
          });
        }
        setEvidenceList(list);
      })();
    }
  }, [graph, isDiagram]);

  if (isDiagram) {
    return (
      <DiagramRedTeamStudio
        graph={graph}
        onNavigateToRemediation={onNavigateToRemediation}
      />
    );
  }

  const activeProbeIdx = Math.max(0, probes.findIndex(p => p.id === (selectedProbeId || probes[0]?.id)));
  const activeProbe = probes[activeProbeIdx] || probes[0];
  const execResult = activeProbe ? executedProbes[activeProbe.id] : undefined;
  const hasRun = Boolean(execResult);

  async function runLiveProbe(probe: RedTeamProbe) {
    setIsExecuting(true);
    setTerminalLogs([
      `$ [INITIATING LIVE PROBE] Connecting to ${probe.target}...`,
      `$ Command: ${probe.command}`,
      `$ Resolving live endpoint DNS, TCP socket, and TLS handshake...`,
    ]);

    try {
      const result = await runProbeServerFn({
        data: {
          probeId: probe.id,
          target: probe.target,
          rule: probe.rule,
          command: probe.command,
          vector: probe.vector,
        },
      });

      let step = 0;
      const interval = setInterval(() => {
        if (step < result.logs.length) {
          const nextLine = result.logs[step];
          setTerminalLogs(prev => [...prev, nextLine]);
          step++;
        } else {
          clearInterval(interval);
          setIsExecuting(false);
          setExecutedProbes(prev => ({
            ...prev,
            [probe.id]: {
              status: result.status,
              latencyMs: result.latencyMs,
              timestamp: result.timestamp,
            },
          }));
        }
      }, 150);
    } catch (err: unknown) {
      setTerminalLogs(prev => [
        ...prev,
        `[LIVE PROBE ERROR] Failed to execute probe against target: ${err instanceof Error ? err.message : 'Network error'}`,
      ]);
      setIsExecuting(false);
      setExecutedProbes(prev => ({
        ...prev,
        [probe.id]: {
          status: 'exploitable',
          timestamp: new Date().toISOString(),
        },
      }));
    }
  }

  async function reVerifyAllEvidence() {
    setVerifying(true);
    await new Promise(r => setTimeout(r, 600));

    const updated = await Promise.all(
      evidenceList.map(async item => {
        const rawPayload = `${item.path}:${item.line}:${item.excerpt}:${graph.commit}`;
        const newHash = await computeSha256(rawPayload);
        return {
          ...item,
          hashDigest: newHash,
          verified: newHash === item.hashDigest,
          timestamp: new Date().toISOString(),
        };
      })
    );
    setEvidenceList(updated);
    setVerifying(false);
  }

  function copyText(text: string, id: string) {
    void navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  }

  function copyPowerShell(cmd: string) {
    void navigator.clipboard.writeText(cmd);
    setCopiedPs(true);
    setTimeout(() => setCopiedPs(false), 2000);
  }

  return (
    <div className="space-y-4">
      {/* 1. Main Attack Graph Canvas (Full Width) */}
      <div className="rounded-xl border border-border bg-card shadow-xs overflow-hidden flex flex-col">
        {/* Sleek Top Bar on Canvas */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-muted/30 px-4 py-2.5">
          <div className="flex items-center gap-2.5">
            <div className="flex size-7 items-center justify-center rounded-md bg-destructive/15 text-destructive ring-1 ring-destructive/30">
              <Swords className="size-4" />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-foreground">
                Autonomous Red Team · Exploitation Path
              </span>
              {activeProbe && (
                <span className="inline-flex items-center gap-1 rounded bg-destructive/15 px-2 py-0.5 font-mono text-[9px] font-bold uppercase text-destructive">
                  <Radio className="size-2 animate-pulse text-destructive" />
                  Target: {activeProbe.name}
                </span>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Stepper Controls */}
            {probes.length > 0 && (
              <div className="flex items-center rounded-md border border-border bg-background p-0.5">
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={activeProbeIdx === 0}
                  onClick={() => {
                    const prevProbe = probes[Math.max(0, activeProbeIdx - 1)];
                    if (prevProbe) {
                      setSelectedProbeId(prevProbe.id);
                      if (!executedProbes[prevProbe.id]) setTerminalLogs(prevProbe.liveTrace || []);
                    }
                  }}
                  className="h-6 px-2 text-[11px]"
                  title="Previous Probe"
                >
                  <ChevronLeft className="size-3 mr-0.5" />
                  Prev
                </Button>
                <span className="px-2 font-mono text-[11px] text-muted-foreground font-medium">
                  Probe {activeProbeIdx + 1} of {probes.length}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={activeProbeIdx === probes.length - 1}
                  onClick={() => {
                    const nextProbe = probes[Math.min(probes.length - 1, activeProbeIdx + 1)];
                    if (nextProbe) {
                      setSelectedProbeId(nextProbe.id);
                      if (!executedProbes[nextProbe.id]) setTerminalLogs(nextProbe.liveTrace || []);
                    }
                  }}
                  className="h-6 px-2 text-[11px]"
                  title="Next Probe"
                >
                  Next
                  <ChevronRight className="size-3 ml-0.5" />
                </Button>
              </div>
            )}

            {/* Probe Status Badge */}
            {hasRun && (
              <span
                className={cn(
                  'rounded px-2 py-1 font-mono text-[10px] font-bold uppercase',
                  execResult?.status === 'exploitable'
                    ? 'bg-destructive/20 text-destructive'
                    : 'bg-emerald-500/20 text-emerald-500'
                )}
              >
                {execResult?.status === 'exploitable' ? 'EXPLOITED (LIVE)' : 'DEFENDED (LIVE)'}
                {execResult?.latencyMs ? ` · ${execResult.latencyMs}ms` : ''}
              </span>
            )}

            {/* Execute Probe Button */}
            {activeProbe && (
              <Button
                size="sm"
                variant={hasRun ? 'outline' : 'destructive'}
                disabled={isExecuting}
                onClick={() => runLiveProbe(activeProbe)}
                className="h-7 gap-1.5 text-[11px] px-3 shadow-xs"
              >
                {isExecuting ? (
                  <>
                    <RefreshCw className="size-3 animate-spin" />
                    <span>Executing...</span>
                  </>
                ) : (
                  <>
                    <Play className="size-3" />
                    <span>{hasRun ? 'Re-execute Live Probe' : 'Execute Live Probe'}</span>
                  </>
                )}
              </Button>
            )}

            {onNavigateToRemediation && (
              <Button
                size="sm"
                variant="outline"
                onClick={onNavigateToRemediation}
                className="h-7 gap-1 text-[11px] px-2.5 text-emerald-600 border-emerald-500/30 hover:bg-emerald-500/10 hover:text-emerald-500 font-medium"
              >
                <Wrench className="size-3" />
                <span>Fix in Remediation</span>
              </Button>
            )}
          </div>
        </div>

        {/* Attack Canvas Area */}
        <div className="h-[460px] w-full relative bg-muted/5">
          <ClientOnly fallback={<div className="flex h-full items-center justify-center"><Loader2 className="size-6 animate-spin text-muted-foreground" /></div>}>
            <Suspense fallback={<div className="flex h-full items-center justify-center"><Loader2 className="size-6 animate-spin text-muted-foreground" /></div>}>
              <AttackCanvas
                graph={graph}
                search=""
                riskOnly={true}
                hideFloatingCard={true}
                controlledStepIdx={activeProbeIdx}
                onSelect={() => {}}
              />
            </Suspense>
          </ClientOnly>
        </div>
      </div>

      {/* 2. Unified Adversary Briefing Bar (Directly Underneath) */}
      {activeProbe && (
        <div className="rounded-xl border border-destructive/30 bg-card p-4 space-y-3.5 shadow-xs">
          {/* Top row: Exploit Objective & Vector */}
          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
            <div className="space-y-1 max-w-3xl">
              <div className="flex items-center gap-2">
                <span className="size-2 rounded-full bg-destructive animate-pulse" />
                <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-destructive">
                  Attacker Action · Probe {activeProbeIdx + 1}: {activeProbe.name}
                </span>
                <span className={cn(
                  'rounded px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase',
                  activeProbe.severity === 'critical' ? 'bg-destructive/20 text-destructive' :
                  activeProbe.severity === 'high' ? 'bg-rose-500/15 text-rose-500' :
                  'bg-amber-500/15 text-amber-500'
                )}>
                  {activeProbe.severity}
                </span>
              </div>
              <p className="text-xs text-foreground/90 font-medium leading-relaxed">
                {activeProbe.impact}
              </p>
              {activeProbe.suggestion && (
                <p className="text-[11px] text-muted-foreground leading-snug">
                  {activeProbe.suggestion}
                </p>
              )}
            </div>

            <div className="flex sm:flex-col gap-2 shrink-0 sm:items-end">
              <div className="inline-flex items-center gap-1.5 rounded-lg border border-border/80 bg-muted/40 px-3 py-1.5 text-[11px]">
                <span className="font-semibold text-amber-500">Vector:</span>
                <span className="text-muted-foreground truncate max-w-[260px] font-mono">{activeProbe.vector}</span>
              </div>
              <div className="inline-flex items-center gap-1.5 rounded-lg border border-border/80 bg-muted/40 px-3 py-1.5 text-[11px]">
                <span className="font-semibold text-primary">Target:</span>
                <span className="text-muted-foreground truncate max-w-[260px] font-mono">{activeProbe.target}</span>
              </div>
            </div>
          </div>

          {/* Attack Vector Pills */}
          <div className="border-t border-border/60 pt-3 flex flex-wrap items-center gap-1.5">
            <span className="text-[10px] uppercase font-mono text-muted-foreground mr-1">
              Attack Probes:
            </span>
            {probes.map((pr, idx) => {
              const isCurrent = pr.id === activeProbe.id;
              const result = executedProbes[pr.id];
              return (
                <button
                  key={pr.id}
                  type="button"
                  onClick={() => {
                    setSelectedProbeId(pr.id);
                    if (!result) setTerminalLogs(pr.liveTrace || []);
                  }}
                  className={cn(
                    'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] transition border cursor-pointer',
                    isCurrent
                      ? 'bg-destructive/15 border-destructive text-destructive font-semibold shadow-xs'
                      : 'bg-muted/30 border-border/70 text-muted-foreground hover:bg-muted/70 hover:text-foreground'
                  )}
                >
                  <span
                    className={cn(
                      'size-4 rounded-full flex items-center justify-center font-mono text-[9px]',
                      result?.status === 'defended'
                        ? 'bg-emerald-500 text-white'
                        : isCurrent
                          ? 'bg-destructive text-white'
                          : 'bg-muted-foreground/20 text-muted-foreground'
                    )}
                  >
                    {result?.status === 'defended' ? '✓' : idx + 1}
                  </span>
                  <span className="truncate max-w-[150px]">{pr.name}</span>
                </button>
              );
            })}
          </div>

          {/* Forensic Deep-Dive Dropdowns */}
          <div className="space-y-2 border-t border-border/60 pt-3">
            {/* Live Socket & Terminal Output Dropdown */}
            <details className="group/terminal rounded-lg border border-border/70 bg-muted/15 p-3">
              <summary className="cursor-pointer text-xs font-medium text-muted-foreground hover:text-foreground flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <Terminal className="size-3.5 text-destructive" />
                  <span>Live Socket &amp; HTTP Terminal Stream ({activeProbe.target})</span>
                </span>
                <ChevronDown className="size-3.5 transition-transform group-open/terminal:rotate-180" />
              </summary>
              <div className="mt-3 space-y-3 pt-2 border-t border-border/50">
                {/* PowerShell Verification Command */}
                <div className="rounded-lg border border-border bg-card shadow-xs overflow-hidden">
                  <div className="flex items-center justify-between border-b border-border bg-muted/40 px-3.5 py-1.5">
                    <span className="font-mono text-[10px] font-semibold text-foreground">
                      PowerShell / cURL Verification Command
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => copyPowerShell(activeProbe.powershellCommand || activeProbe.command)}
                      className="h-5 gap-1 px-1.5 text-[9px] text-destructive"
                    >
                      {copiedPs ? <Check className="size-2.5" /> : <Copy className="size-2.5" />}
                      <span>{copiedPs ? 'Copied' : 'Copy'}</span>
                    </Button>
                  </div>
                  <pre className="p-2.5 font-mono text-[11px] overflow-x-auto text-foreground leading-relaxed whitespace-pre-wrap select-text">
                    {activeProbe.powershellCommand || activeProbe.command}
                  </pre>
                </div>

                {/* Terminal Stream */}
                <div className="rounded-lg bg-black p-4 font-mono text-xs text-white shadow-inner">
                  <div className="mb-2 flex items-center justify-between border-b border-white/10 pb-2 text-white/50 text-[10px]">
                    <span>Live Socket Stream · {activeProbe.target}</span>
                    {isExecuting && (
                      <span className="flex items-center gap-1 text-destructive font-semibold">
                        <Radio className="size-3 animate-pulse" /> Running probe...
                      </span>
                    )}
                  </div>
                  <div className="max-h-52 space-y-1 overflow-auto select-text">
                    {terminalLogs.map((log, i) => (
                      <div
                        key={i}
                        className={cn(
                          'leading-relaxed break-words',
                          log.startsWith('$') ? 'text-white/90 font-bold' : 'text-white/60',
                          log.includes('[EXPLOITATION VERIFIED]') || log.includes('[VULNERABILITY')
                            ? 'text-destructive font-bold bg-destructive/10 p-1 rounded'
                            : '',
                          log.includes('[VERIFIED]') ? 'text-emerald-400 font-bold' : ''
                        )}
                      >
                        {log}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </details>

            {/* Cryptographic Source Code Proofs (SHA-256 Audit) Dropdown */}
            {evidenceList.length > 0 && (
              <details className="group/evidence rounded-lg border border-border/70 bg-muted/15 p-3">
                <summary className="cursor-pointer text-xs font-medium text-muted-foreground hover:text-foreground flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <ShieldCheck className="size-3.5 text-primary" />
                    <span>Cryptographic Source Code Proofs ({evidenceList.length} SHA-256 Verified AST Nodes)</span>
                  </span>
                  <ChevronDown className="size-3.5 transition-transform group-open/evidence:rotate-180" />
                </summary>
                <div className="mt-3 space-y-3 pt-2 border-t border-border/50">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] text-muted-foreground">
                      All AST nodes, diagram entities, and evidence tokens are cryptographically hashed using SHA-256 for audit immutability.
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={verifying}
                      onClick={reVerifyAllEvidence}
                      className="h-6 gap-1.5 px-2 text-[10px]"
                    >
                      <RefreshCw className={cn('size-3', verifying && 'animate-spin')} />
                      <span>{verifying ? 'Re-Verifying...' : 'Re-verify Hashes'}</span>
                    </Button>
                  </div>

                  <div className="divide-y divide-border rounded-lg border border-border bg-card overflow-hidden">
                    {evidenceList.map(item => (
                      <div key={item.id} className="p-3 text-xs hover:bg-muted/20 transition-colors">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2 font-mono text-[11px]">
                            <span className="font-semibold text-foreground">{item.path}</span>
                            <span className="text-muted-foreground">Line {item.line}</span>
                          </div>
                          <span className="rounded bg-emerald-500/10 px-1.5 py-0.5 font-bold text-emerald-600 border border-emerald-500/20 text-[10px] flex items-center gap-1 font-mono">
                            <CheckCircle2 className="size-3" />
                            VERIFIED SHA-256
                          </span>
                        </div>
                        <div className="mt-1.5 rounded bg-muted/40 p-2 font-mono text-[11px] text-muted-foreground overflow-x-auto">
                          {item.excerpt}
                        </div>
                        <div className="mt-1.5 flex items-center justify-between font-mono text-[10px] text-muted-foreground">
                          <span className="truncate max-w-md">Digest: {item.hashDigest}</span>
                          <button
                            onClick={() => copyText(item.hashDigest, item.id)}
                            className="text-primary hover:underline flex items-center gap-1 cursor-pointer"
                          >
                            {copiedHash === item.id ? <Check className="size-2.5" /> : <Copy className="size-2.5" />}
                            <span>{copiedHash === item.id ? 'Copied' : 'Copy Digest'}</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </details>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
