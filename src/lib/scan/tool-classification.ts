import type { Inventory, Sev, Signal, Verdict } from './types';

export type PartStatus = 'blocked' | 'review' | 'allowed';

export interface ClassifiedPart {
  name: string;
  type: 'tool' | 'finding' | 'guardrail';
  status: PartStatus;
  risk: number;
  badgeLabel: string;
  summary: string;
  explanation: string;
  signals: Signal[];
  findings: { severity: Sev; title: string; detail: string; evidence: string }[];
  rules: string[];
}

export interface ClassificationResult {
  blocked: ClassifiedPart[];
  review: ClassifiedPart[];
  allowed: ClassifiedPart[];
  all: ClassifiedPart[];
  counts: {
    blocked: number;
    review: number;
    allowed: number;
    total: number;
  };
}

/**
 * Classifies tools, components, and security signals into color-coded categories:
 * - Blocked (Red): Execution actively denied due to critical exploit vectors (RCE, token exfiltration, shell commands)
 * - Review (Amber): Sensitive capabilities requiring human-in-the-loop approval or parameter boundaries (SSRF, paths)
 * - Allowed (Green): Safe, read-only, or least-privilege compliant operations safe for autonomous agent execution
 */
export function classifyAuditParts(
  inventory: Inventory | null | undefined,
  verdict: Verdict | null | undefined,
  signals: Signal[] | undefined
): ClassificationResult {
  const toolNames = [
    ...new Set([
      ...(inventory?.tools?.map((t) => t.name) ?? []),
      ...(verdict?.tools?.map((t) => t.tool) ?? []),
    ]),
  ];

  const allSignals = signals ?? [];
  const allFindings = verdict?.findings ?? [];

  const classified: ClassifiedPart[] = [];

  for (const name of toolNames) {
    const verdictTool = verdict?.tools?.find((t) => t.tool === name);
    const toolSignals = allSignals.filter(
      (s) => s.target === name || s.target.startsWith(`${name}.`) || s.target.includes(name)
    );
    const toolFindings = allFindings.filter(
      (f) =>
        f.title.toLowerCase().includes(name.toLowerCase()) ||
        f.detail.toLowerCase().includes(name.toLowerCase()) ||
        f.evidence.toLowerCase().includes(name.toLowerCase())
    );

    const hasCriticalSignal = toolSignals.some((s) => s.severity === 'critical');
    const hasCriticalFinding = toolFindings.some((f) => f.severity === 'critical');
    const hasHighSignal = toolSignals.some((s) => s.severity === 'high');
    const hasHighFinding = toolFindings.some((f) => f.severity === 'high');
    const hasMedSignal = toolSignals.some((s) => s.severity === 'medium');

    // Calculate effective risk
    let risk = verdictTool?.risk ?? 10;
    if (hasCriticalSignal || hasCriticalFinding) {
      risk = Math.max(risk, 85);
    } else if (hasHighSignal || hasHighFinding) {
      risk = Math.max(risk, 55);
    } else if (hasMedSignal) {
      risk = Math.max(risk, 40);
    }

    // Determine status
    let status: PartStatus = 'allowed';
    let badgeLabel = 'Allowed · Safe to Execute';
    let summary = 'Safe for autonomous AI agent invocation.';
    let explanation =
      'Operates strictly within bounded parameters with zero dangerous execution primitives. Approved as safe for autonomous AI agent invocation.';

    const isBlocked =
      risk >= 70 ||
      hasCriticalSignal ||
      hasCriticalFinding;

    const isReview =
      !isBlocked &&
      (risk >= 40 ||
        hasHighSignal ||
        hasHighFinding ||
        hasMedSignal ||
        verdictTool?.class?.includes('elevated') ||
        verdictTool?.class?.includes('network'));

    const rules = [...new Set([...toolSignals.map((s) => s.rule)])];
    const lowerName = name.toLowerCase();

    if (isBlocked) {
      status = 'blocked';
      badgeLabel = 'Blocked · Execution Denied';
      summary = 'Critical security risk. Guardrail blocks agent tool calls to this function.';

      if (
        rules.some((r) => r.includes('secret') || r.includes('token') || r.includes('cred')) ||
        lowerName.includes('token') ||
        lowerName.includes('secret') ||
        lowerName.includes('key')
      ) {
        explanation =
          'Attempts to access, inspect, or transmit private credentials or authorization tokens. Guardrail blocks execution to prevent credential leakage and unauthorized privilege escalation.';
      } else if (
        rules.some((r) => r.includes('shell') || r.includes('command') || r.includes('exec') || r.includes('injection')) ||
        lowerName.includes('exec') ||
        lowerName.includes('cmd') ||
        lowerName.includes('bash') ||
        lowerName.includes('shell')
      ) {
        explanation =
          'Spawns arbitrary shell commands or process execution primitives without sandboxing. Blocked to prevent Remote Code Execution (RCE) via prompt injection.';
      } else if (risk >= 70) {
        explanation = `Risk score of ${risk}/100 exceeds the maximum safe ceiling (70). Guardrail actively blocks autonomous agent execution to prevent host compromise.`;
      } else {
        explanation =
          'Severe security risk or exploit surface detected. Tool invocation is blocked by runtime guardrails.';
      }
    } else if (isReview) {
      status = 'review';
      badgeLabel = 'Needs Review · Approval Required';
      summary = 'Sensitive capability detected. Requires operator verification or constraint scoping.';

      if (
        rules.some((r) => r.includes('exfil') || r.includes('redirect') || r.includes('ssrf')) ||
        lowerName.includes('fetch') ||
        lowerName.includes('url') ||
        lowerName.includes('http') ||
        lowerName.includes('webhook')
      ) {
        explanation =
          'Initiates outbound network requests or URL fetches. Operator review and destination allowlisting are required to prevent Server-Side Request Forgery (SSRF) and data egress.';
      } else if (
        rules.some((r) => r.includes('path') || r.includes('file')) ||
        lowerName.includes('file') ||
        lowerName.includes('read') ||
        lowerName.includes('write') ||
        lowerName.includes('fs')
      ) {
        explanation =
          'Accesses or queries local filesystem paths. Requires operator review to ensure operations are confined to authorized directory paths.';
      } else {
        explanation =
          'Sensitive parameters or elevated capabilities detected. Requires human confirmation or argument boundary verification before invocation.';
      }
    }

    classified.push({
      name,
      type: 'tool',
      status,
      risk,
      badgeLabel,
      summary,
      explanation,
      signals: toolSignals,
      findings: toolFindings,
      rules,
    });
  }

  // If no tools were found (e.g. transcript or raw prompt mode), classify standalone findings
  if (classified.length === 0 && allFindings.length > 0) {
    allFindings.forEach((f, idx) => {
      const isCritical = f.severity === 'critical';
      const isHigh = f.severity === 'high';
      const isMed = f.severity === 'medium';

      const status: PartStatus = isCritical ? 'blocked' : isHigh || isMed ? 'review' : 'allowed';
      const risk = isCritical ? 90 : isHigh ? 60 : isMed ? 40 : 15;

      classified.push({
        name: f.title,
        type: 'finding',
        status,
        risk,
        badgeLabel:
          status === 'blocked'
            ? 'Blocked · Critical Violation'
            : status === 'review'
            ? 'Needs Review · Finding'
            : 'Allowed · Low Severity',
        summary: f.detail,
        explanation:
          status === 'blocked'
            ? 'Critical vulnerability identified in agent session or payload. Guardrail mandates blocking related actions.'
            : status === 'review'
            ? 'Behavioral anomaly or sensitive action detected. Operator review required.'
            : 'Informational finding within tolerable security baseline.',
        signals: allSignals.slice(idx, idx + 1),
        findings: [f],
        rules: [],
      });
    });
  }

  const blocked = classified.filter((p) => p.status === 'blocked');
  const review = classified.filter((p) => p.status === 'review');
  const allowed = classified.filter((p) => p.status === 'allowed');

  return {
    blocked,
    review,
    allowed,
    all: classified,
    counts: {
      blocked: blocked.length,
      review: review.length,
      allowed: allowed.length,
      total: classified.length,
    },
  };
}
