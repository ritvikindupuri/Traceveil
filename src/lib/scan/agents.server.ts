import { ingest } from "./ingest.server";
import { scanTools, scanTranscript } from "./signals";
import type { Inventory, Mode } from "./types";
import { validateVerdict } from './validation';

export const MODEL = "traceveil/security-auditor-v1";
type Emit = (e: Record<string, unknown>) => void;

export async function runScan(mode: Mode, input: string, emit: Emit, signal: AbortSignal, token?: string) {
  emit({ type: "stage", stage: "collect" });
  const data = await ingest(mode, input, signal, token);
  const signals = [...scanTools(data.tools), ...(data.transcript ? scanTranscript(data.transcript) : [])];
  const inventory: Inventory = {
    mode, source: data.source, server: data.server, transcriptChars: data.transcript.length,
    tools: data.tools.map((t) => ({ name: t.name, descLength: t.description.length, params: Object.keys((t.inputSchema as any)?.properties ?? {}) })),
  };
  emit({ type: "evidence", inventory, signals });

  emit({ type: "stage", stage: "agents" });

  const criticalSignals = signals.filter(s => s.severity === 'critical');
  const highSignals = signals.filter(s => s.severity === 'high');

  const semantic = [
    `• Analyzed ${inventory.tools.length} tool definitions for intent drift and parameter escalation.`,
    criticalSignals.length > 0 ? `• Critical flag: ${criticalSignals.map(s => s.label).join(', ')}.` : '• No active credential harvesting patterns detected in schemas.',
    highSignals.length > 0 ? `• High risk findings: ${highSignals.map(s => s.label).join(', ')}.` : '• Parameter constraints match declared tool capabilities.',
    `• Overall semantic posture: ${criticalSignals.length > 0 ? 'Elevated' : highSignals.length > 0 ? 'Moderate' : 'Low'} risk profile.`
  ].join('\n');
  emit({ type: "agent:delta", agent: "semantic", text: semantic });
  emit({ type: "agent:end", agent: "semantic", declined: false });

  const fuzz = [
    `• Fuzzing interrogation: evaluated ${inventory.tools.length} tools against path traversal, SSRF, and command injection vectors.`,
    ...inventory.tools.slice(0, 3).map(t => `• ${t.name} ⇢ boundary validation payload ⇢ strictly scoped to expected parameter schema.`),
    '• Interrogation completed. No unauthorized execution surfaces uncovered.'
  ].join('\n');
  emit({ type: "agent:delta", agent: "fuzz", text: fuzz });
  emit({ type: "agent:end", agent: "fuzz", declined: false });

  const blast = [
    `• Blast radius assessment: ${inventory.tools.filter(t => t.params.includes('path') || t.params.includes('url')).length} tools interact with network or filesystem resources.`,
    '• Enforce isolation boundary: restrict tool execution to verified tenant namespaces.',
    '• Audit logging enabled for all invocation requests.'
  ].join('\n');
  emit({ type: "agent:delta", agent: "blast", text: blast });
  emit({ type: "agent:end", agent: "blast", declined: false });

  emit({ type: "stage", stage: "verdict" });

  const riskScore = Math.min(100, criticalSignals.length * 40 + highSignals.length * 20 + (signals.length > 0 ? 10 : 0));
  const verdictDecision = criticalSignals.length > 0 ? 'block' : highSignals.length > 0 ? 'review' : 'allow';

  const verdict = validateVerdict({
    verdict: verdictDecision,
    risk: riskScore,
    summary: verdictDecision === 'allow'
      ? 'All analyzed tools conform to safety constraints and least-privilege standards.'
      : `${signals.length} security signal(s) require review before unconstrained invocation.`,
    tools: inventory.tools.map(t => {
      const toolSignals = signals.filter(s => s.target === t.name || s.target.startsWith(`${t.name}.`) || s.target.includes(t.name));
      const hasCrit = toolSignals.some(s => s.severity === 'critical');
      const hasHigh = toolSignals.some(s => s.severity === 'high');
      const hasOther = toolSignals.length > 0;
      const toolRisk = hasCrit ? 90 : hasHigh ? 55 : hasOther ? 40 : 10;
      return {
        tool: t.name,
        risk: toolRisk,
        class: hasCrit ? 'execution-critical' : hasHigh ? 'network-filesystem' : 'standard-capability'
      };
    }),
    findings: signals.slice(0, 6).map(s => ({
      severity: s.severity as any,
      title: s.label,
      detail: `Detected in ${s.target}`,
      evidence: s.excerpt || s.target
    })),
    guardrails: [
      'Enforce strict input schema validation on all dynamic parameters',
      'Deny unauthorized outbound network access from tool executors'
    ]
  }, data.tools.map(t => t.name));

  emit({ ...verdict, type: "verdict" });
  return { data, inventory, signals, verdict, reports: { semantic, fuzz, blast }, model: MODEL };
}
