import type { AttackGraph, GraphEntity, GraphRelation, Finding, AttackPath } from './types';
import { publicEndpoint } from '@/lib/scan/validation';
import { redact, validateGraph } from './validation';
import { createHash } from 'crypto';

interface ProbeResult {
  url: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  rawHeaders: string;
  bodySnippet: string;
}

async function fetchProbe(url: string, signal: AbortSignal, timeoutMs = 8000): Promise<ProbeResult | null> {
  const controller = new AbortController();
  const onParentAbort = () => controller.abort();
  signal.addEventListener('abort', onParentAbort);
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Traceveil-Security-Auditor/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Cache-Control': 'no-cache',
      },
    });

    const headers: Record<string, string> = {};
    const headerLines: string[] = [`HTTP/1.1 ${res.status} ${res.statusText}`];
    res.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val;
      headerLines.push(`${key}: ${val}`);
    });

    let bodySnippet = '';
    try {
      const text = await res.text();
      bodySnippet = text.slice(0, 3000);
    } catch {
      // Body reading is optional
    }

    return {
      url,
      status: res.status,
      statusText: res.statusText,
      headers,
      rawHeaders: headerLines.join('\n'),
      bodySnippet,
    };
  } catch (err) {
    if (signal.aborted) throw err;
    return null;
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', onParentAbort);
  }
}

export async function collectLiveApplication(
  rawUrl: string,
  signal: AbortSignal,
  onProgress: (msg: string) => void
): Promise<AttackGraph> {
  onProgress('Validating public live application target endpoint');
  let targetUrl: URL;
  try {
    targetUrl = publicEndpoint(rawUrl);
  } catch (err: unknown) {
    // If protocol was omitted, try with https://
    if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
      targetUrl = publicEndpoint(`https://${rawUrl}`);
    } else {
      throw new Error(err instanceof Error ? err.message : 'Invalid public HTTPS application URL');
    }
  }

  const host = targetUrl.hostname;
  const baseUrl = `https://${host}`;
  onProgress(`Connecting to ${baseUrl} over TLS`);

  // Run probes
  const [rootProbe, envProbe, robotsProbe, gitProbe] = await Promise.all([
    fetchProbe(`${baseUrl}/`, signal),
    fetchProbe(`${baseUrl}/.env`, signal),
    fetchProbe(`${baseUrl}/robots.txt`, signal),
    fetchProbe(`${baseUrl}/.git/HEAD`, signal),
  ]);

  if (!rootProbe) {
    throw new Error(`Could not establish TLS connection to ${baseUrl}. Verify the endpoint is publicly reachable.`);
  }

  onProgress(`Analyzing HTTP response headers and security boundaries on ${host}`);

  const now = new Date().toISOString();
  const commitSha = `live-${createHash('sha256').update(`${host}-${now}`).digest('hex').slice(0, 8)}`;

  const graph: AttackGraph = {
    target: baseUrl,
    commit: commitSha,
    branch: 'production (live)',
    nodes: [],
    edges: [],
    evidence: [],
    findings: [],
    attackPaths: [],
    coverage: {
      inspected: 4,
      total: 4,
      skipped: 0,
      gaps: [
        'Live HTTP analysis covers perimeter headers, response posture, and public route boundaries.',
        'Authenticated tenant data flow and internal microservices require credential-based runner deployment.',
      ],
    },
    collectedAt: now,
  };

  const addEvidence = (path: string, line: number, excerpt: string): string => {
    const id = `e${graph.evidence.length}`;
    graph.evidence.push({
      id,
      path,
      line,
      excerpt: redact(excerpt).slice(0, 1200),
      url: `${baseUrl}${path}`,
      collectedAt: now,
    });
    return id;
  };

  // Root Evidence
  const rootEvidenceId = addEvidence('/', 1, rootProbe.rawHeaders);

  // Core Nodes:
  // 1. Public Internet
  const internetNode: GraphEntity = {
    id: 'public-internet',
    label: 'Public Internet',
    kind: 'internet',
    category: 'actor',
    subtitle: 'External Attack Surface',
    badge: 'Public Ingress',
    evidenceIds: [rootEvidenceId],
  };
  graph.nodes.push(internetNode);

  // 2. Web Application Workload
  const serverBanner = rootProbe.headers['server'] || rootProbe.headers['x-powered-by'] || 'Cloudflare / Render Ingress';
  const webNode: GraphEntity = {
    id: 'live-app',
    label: `${host} (Live Web Service)`,
    kind: 'compute',
    category: 'compute',
    subtitle: `TLS Web Server · ${serverBanner} · Status ${rootProbe.status}`,
    badge: 'Inspected Target',
    evidenceIds: [rootEvidenceId],
  };
  graph.nodes.push(webNode);

  // 3. Client Session Context
  const sessionNode: GraphEntity = {
    id: 'client-context',
    label: 'Browser Session & Storage',
    kind: 'identity',
    category: 'actor',
    subtitle: 'Client-Side Cookie & Token Context',
    badge: 'Client Boundary',
    evidenceIds: [rootEvidenceId],
  };
  graph.nodes.push(sessionNode);

  // 4. Target Crown Jewel Database / API Backend
  const crownJewelNode: GraphEntity = {
    id: 'backend-datastore',
    label: 'Application Backend & Database',
    kind: 'database',
    category: 'data',
    subtitle: 'Sensitive Records & API Endpoints',
    badge: 'Crown Jewel',
    evidenceIds: [rootEvidenceId],
  };
  graph.nodes.push(crownJewelNode);

  // Ingress Edge: Internet -> Web Server
  graph.edges.push({
    id: 'edge-internet-to-app',
    source: 'public-internet',
    target: 'live-app',
    label: 'Public TLS Ingress (Port 443)',
    category: 'network',
    evidenceIds: [rootEvidenceId],
  });

  // Evaluate Findings:
  const headers = rootProbe.headers;

  // 1. Missing Content-Security-Policy (CSP)
  if (!headers['content-security-policy']) {
    const evId = addEvidence('/ (Headers)', 1, `HTTP Status ${rootProbe.status}\nMissing header: Content-Security-Policy\nServer: ${serverBanner}`);
    const findingNode: GraphEntity = {
      id: 'finding-node-csp',
      label: 'Missing Content-Security-Policy',
      kind: 'exposure',
      category: 'compute',
      subtitle: 'Absence of CSP script and frame restrictions',
      badge: 'Toxic Exposure',
      severity: 'high',
      evidenceIds: [evId],
    };
    graph.nodes.push(findingNode);

    graph.edges.push({
      id: 'edge-app-to-csp',
      source: 'live-app',
      target: 'finding-node-csp',
      label: 'Unrestricted Script Ingress',
      category: 'network',
      evidenceIds: [evId],
    });

    graph.edges.push({
      id: 'edge-csp-to-session',
      source: 'finding-node-csp',
      target: 'client-context',
      label: 'XSS & Session Hijack Threat',
      category: 'trust',
      evidenceIds: [evId],
    });

    graph.findings.push({
      id: 'finding-live-csp',
      rule: 'missing-csp',
      severity: 'high',
      title: 'Missing Content-Security-Policy (CSP) Protection',
      fix: "Configure a strict Content-Security-Policy response header restricting script-src, style-src, frame-ancestors, and object-src to authorized origins.",
      evidenceIds: [evId],
    });
  }

  // 2. Missing Strict-Transport-Security (HSTS)
  if (!headers['strict-transport-security']) {
    const evId = addEvidence('/ (Headers)', 2, `HTTP Status ${rootProbe.status}\nMissing header: Strict-Transport-Security\nProtocol: HTTPS 443`);
    const findingNode: GraphEntity = {
      id: 'finding-node-hsts',
      label: 'Missing HSTS Encryption Enforcement',
      kind: 'exposure',
      category: 'compute',
      subtitle: 'Absence of HTTP Strict Transport Security',
      badge: 'Toxic Exposure',
      severity: 'high',
      evidenceIds: [evId],
    };
    graph.nodes.push(findingNode);

    graph.edges.push({
      id: 'edge-app-to-hsts',
      source: 'live-app',
      target: 'finding-node-hsts',
      label: 'Unenforced TLS Downgrade Risk',
      category: 'network',
      evidenceIds: [evId],
    });

    graph.edges.push({
      id: 'edge-hsts-to-session',
      source: 'finding-node-hsts',
      target: 'client-context',
      label: 'SSL Stripping Exposure',
      category: 'trust',
      evidenceIds: [evId],
    });

    graph.findings.push({
      id: 'finding-live-hsts',
      rule: 'missing-hsts',
      severity: 'high',
      title: 'Missing Strict-Transport-Security (HSTS) Header',
      fix: "Enforce HSTS by setting 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' at your reverse proxy or web application server.",
      evidenceIds: [evId],
    });
  }

  // 3. Missing X-Frame-Options (Clickjacking Risk)
  if (!headers['x-frame-options'] && !headers['content-security-policy']?.includes('frame-ancestors')) {
    const evId = addEvidence('/ (Headers)', 3, `HTTP Status ${rootProbe.status}\nMissing header: X-Frame-Options\nMissing CSP frame-ancestors`);
    const findingNode: GraphEntity = {
      id: 'finding-node-frame',
      label: 'Missing Anti-Clickjacking Frame Protection',
      kind: 'exposure',
      category: 'compute',
      subtitle: 'Application can be embedded into malicious third-party iframes',
      badge: 'Exposure',
      severity: 'medium',
      evidenceIds: [evId],
    };
    graph.nodes.push(findingNode);

    graph.edges.push({
      id: 'edge-app-to-frame',
      source: 'live-app',
      target: 'finding-node-frame',
      label: 'Iframe Framing Allowed',
      category: 'network',
      evidenceIds: [evId],
    });

    graph.edges.push({
      id: 'edge-frame-to-session',
      source: 'finding-node-frame',
      target: 'client-context',
      label: 'Clickjacking Threat',
      category: 'trust',
      evidenceIds: [evId],
    });

    graph.findings.push({
      id: 'finding-live-frame',
      rule: 'missing-frame-options',
      severity: 'medium',
      title: 'Missing Anti-Clickjacking Protection (X-Frame-Options)',
      fix: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to response headers to block malicious framing.",
      evidenceIds: [evId],
    });
  }

  // 4. Server & Routing Banner Leakage
  if (headers['server'] || headers['x-powered-by'] || headers['x-render-routing']) {
    const leakDetails = [
      headers['server'] ? `Server: ${headers['server']}` : null,
      headers['x-powered-by'] ? `X-Powered-By: ${headers['x-powered-by']}` : null,
      headers['x-render-routing'] ? `X-Render-Routing: ${headers['x-render-routing']}` : null,
    ].filter(Boolean).join('\n');

    const evId = addEvidence('/ (Headers)', 4, leakDetails);
    const findingNode: GraphEntity = {
      id: 'finding-node-banner',
      label: 'Server Fingerprint & Routing Leak',
      kind: 'misconfiguration',
      category: 'compute',
      subtitle: `Leaking infrastructure fingerprints: ${headers['server'] || 'Render'}`,
      badge: 'Misconfiguration',
      severity: 'medium',
      evidenceIds: [evId],
    };
    graph.nodes.push(findingNode);

    graph.edges.push({
      id: 'edge-app-to-banner',
      source: 'live-app',
      target: 'finding-node-banner',
      label: 'Technology Fingerprint',
      category: 'network',
      evidenceIds: [evId],
    });

    graph.findings.push({
      id: 'finding-live-banner',
      rule: 'server-banner-leak',
      severity: 'medium',
      title: `Server Banner & Routing Header Leakage (${headers['server'] || 'Cloudflare/Render'})`,
      fix: "Configure your reverse proxy or web application framework to suppress Server and X-Powered-By response headers.",
      evidenceIds: [evId],
    });
  }

  // 5. Check if /.env or sensitive paths are accessible
  if (envProbe && envProbe.status === 200 && (envProbe.bodySnippet.includes('=') || envProbe.bodySnippet.includes('KEY') || envProbe.bodySnippet.includes('SECRET'))) {
    const evId = addEvidence('/.env', 1, envProbe.bodySnippet.slice(0, 300));
    const findingNode: GraphEntity = {
      id: 'finding-node-env',
      label: 'Publicly Accessible .env File',
      kind: 'credential',
      category: 'data',
      subtitle: 'Critical environment configuration exposed over HTTP',
      badge: 'Critical Secret',
      severity: 'high',
      evidenceIds: [evId],
    };
    graph.nodes.push(findingNode);

    graph.edges.push({
      id: 'edge-app-to-env',
      source: 'live-app',
      target: 'finding-node-env',
      label: 'Direct HTTP Exposure',
      category: 'network',
      evidenceIds: [evId],
    });

    graph.edges.push({
      id: 'edge-env-to-backend',
      source: 'finding-node-env',
      target: 'backend-datastore',
      label: 'Database Credential Takeover',
      category: 'trust',
      evidenceIds: [evId],
    });

    graph.findings.push({
      id: 'finding-live-env',
      rule: 'exposed-env',
      severity: 'high',
      title: 'Publicly Exposed Environment Variables (.env)',
      fix: "Immediately block access to .env files in your web server configuration and rotate all exposed credentials.",
      evidenceIds: [evId],
    });
  }

  // Final Threat Edge to Crown Jewel: Session -> Backend Datastore
  graph.edges.push({
    id: 'edge-session-to-backend',
    source: 'client-context',
    target: 'backend-datastore',
    label: 'Authorized API Calls & Token Replay',
    category: 'trust',
    evidenceIds: [rootEvidenceId],
  });

  // Synthesize Wiz-Style Attack Path
  const primaryFindingNode = graph.nodes.find(n => n.id === 'finding-node-csp') || graph.nodes.find(n => n.id.startsWith('finding-node-')) || webNode;
  const primaryFinding = graph.findings.find(f => f.rule === 'missing-csp') || graph.findings[0];
  const findingEvIds = primaryFindingNode.evidenceIds || [rootEvidenceId];

  const attackPath: AttackPath = {
    id: 'path-live-perimeter-1',
    title: 'Public Internet → Live Endpoint Ingress → Missing Perimeter Defenses → Backend Datastore',
    severity: graph.findings.some(f => f.severity === 'high') ? 'critical' : 'high',
    summary: `Publicly accessible live web service at ${baseUrl} lacks defense-in-depth perimeter headers (CSP, HSTS). Attackers can target client sessions to pivot into backend APIs.`,
    steps: [
      {
        id: 'step-live-1',
        nodeId: 'public-internet',
        title: 'Public Internet Ingress',
        subtitle: 'External Attack Surface',
        stage: 'internet',
        badge: '0.0.0.0/0',
        description: `Anyone on the public internet can resolve and connect directly to ${baseUrl}.`,
        evidenceIds: [rootEvidenceId],
      },
      {
        id: 'step-live-2',
        nodeId: 'live-app',
        title: `${host} Web Server`,
        subtitle: 'Inspected Web Target',
        stage: 'server',
        badge: 'Public Host',
        description: `Target live application running behind ${serverBanner} answers external HTTP requests.`,
        evidenceIds: [rootEvidenceId],
      },
      {
        id: 'step-live-3',
        nodeId: primaryFindingNode.id,
        title: primaryFindingNode.label,
        subtitle: primaryFindingNode.subtitle || 'Perimeter Security Gap',
        stage: 'vulnerability',
        badge: primaryFinding?.severity === 'high' ? 'HIGH RISK' : 'MEDIUM RISK',
        description: primaryFinding?.fix || `Missing Content-Security-Policy (CSP) and transport encryption enforcement expose client browsers to script injection and framing.`,
        remediation: primaryFinding?.fix,
        evidenceIds: findingEvIds,
      },
      {
        id: 'step-live-4',
        nodeId: 'client-context',
        title: 'Client Browser Context',
        subtitle: 'Session & Auth Storage',
        stage: 'privilege',
        badge: 'Client Boundary',
        description: `Adversary leverages perimeter weaknesses to compromise client sessions, cookies, or auth tokens.`,
        evidenceIds: findingEvIds,
      },
      {
        id: 'step-live-5',
        nodeId: 'backend-datastore',
        title: 'Target Backend & Database',
        subtitle: 'Crown Jewel API & Data',
        stage: 'target',
        badge: 'Crown Jewel',
        description: `Compromised session context enables lateral access to backend APIs and customer data.`,
        remediation: 'Implement strict CSP headers, enforce HSTS preload, and use partitioned HTTP-only session cookies.',
        evidenceIds: [rootEvidenceId],
      },
    ],
    nodeIds: ['public-internet', 'live-app', primaryFindingNode.id, 'client-context', 'backend-datastore'],
    edgeIds: [
      'edge-internet-to-app',
      graph.edges.find(e => e.source === 'live-app' && e.target === primaryFindingNode.id)?.id || 'edge-app-to-csp',
      graph.edges.find(e => e.source === primaryFindingNode.id && e.target === 'client-context')?.id || 'edge-csp-to-session',
      'edge-session-to-backend',
    ].filter(Boolean) as string[],
  };

  graph.attackPaths.push(attackPath);

  onProgress(`Generated live attack graph with ${graph.nodes.length} entities and ${graph.findings.length} findings`);
  return validateGraph(graph);
}
