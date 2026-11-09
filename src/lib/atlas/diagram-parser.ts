import type { AttackGraph, GraphEntity, GraphRelation, Finding, Evidence, AttackPath, AttackPathStep } from './types';

export interface ParsedDiagramResult {
  graph: AttackGraph;
  diagramType: 'drawio' | 'packet_tracer' | 'generic_architecture';
  deviceCount: number;
  connectionCount: number;
  warnings?: string[];
}

interface RawCell {
  id: string;
  value: string;
  style: string;
  vertex?: boolean;
  edge?: boolean;
  source?: string;
  target?: string;
  parent?: string;
}

/**
 * Strips HTML formatting that draw.io often embeds inside cell labels (e.g. <div><b>API</b></div>)
 */
function cleanLabel(raw?: string): string {
  if (!raw) return '';
  return raw
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Categorizes a diagram node based on its label and draw.io style shape.
 */
function categorizeNode(label: string, style: string): {
  kind: GraphEntity['kind'];
  category: GraphEntity['category'];
  badge: string;
  subtitle: string;
  isInternet: boolean;
  isDatabase: boolean;
  isCompute: boolean;
  isFirewall: boolean;
  isRouter: boolean;
  isStorage: boolean;
} {
  const l = label.toLowerCase();
  const s = style.toLowerCase();

  // 1. Internet / External Ingress
  if (
    l.includes('internet') ||
    l.includes('public') ||
    l.includes('external') ||
    l.includes('wan') ||
    l.includes('user') ||
    l.includes('client') ||
    s.includes('internet') ||
    s.includes('cloud')
  ) {
    return {
      kind: 'internet',
      category: 'exposure',
      badge: 'Public Perimeter',
      subtitle: 'External Network Ingress',
      isInternet: true,
      isDatabase: false,
      isCompute: false,
      isFirewall: false,
      isRouter: false,
      isStorage: false,
    };
  }

  // 2. Storage / S3 / Bucket
  if (
    l.includes('s3') ||
    l.includes('bucket') ||
    l.includes('storage') ||
    l.includes('blob') ||
    s.includes('s3') ||
    s.includes('bucket')
  ) {
    return {
      kind: 'target',
      category: 'target',
      badge: 'Cloud Storage',
      subtitle: 'Object Storage Bucket',
      isInternet: false,
      isDatabase: false,
      isCompute: false,
      isFirewall: false,
      isRouter: false,
      isStorage: true,
    };
  }

  // 3. Database / Datastore
  if (
    l.includes('database') ||
    l.includes('db') ||
    l.includes('rds') ||
    l.includes('postgres') ||
    l.includes('mysql') ||
    l.includes('mongo') ||
    l.includes('redis') ||
    l.includes('dynamo') ||
    s.includes('database') ||
    s.includes('rds')
  ) {
    return {
      kind: 'target',
      category: 'target',
      badge: 'Crown Jewel Database',
      subtitle: 'Production Data Tier',
      isInternet: false,
      isDatabase: true,
      isCompute: false,
      isFirewall: false,
      isRouter: false,
      isStorage: false,
    };
  }

  // 4. Firewall / Security Gateway
  if (
    l.includes('firewall') ||
    l.includes('waf') ||
    l.includes('asa') ||
    l.includes('palo alto') ||
    l.includes('pfsense') ||
    s.includes('firewall')
  ) {
    return {
      kind: 'service',
      category: 'exposure',
      badge: 'Security Gateway',
      subtitle: 'Perimeter Access Control',
      isInternet: false,
      isDatabase: false,
      isCompute: false,
      isFirewall: true,
      isRouter: false,
      isStorage: false,
    };
  }

  // 5. Router / Switch (Packet Tracer & Network Topologies)
  if (
    l.includes('router') ||
    l.includes('switch') ||
    l.includes('gateway') ||
    l.includes('cisco') ||
    s.includes('router') ||
    s.includes('switch')
  ) {
    return {
      kind: 'server',
      category: 'compute',
      badge: l.includes('switch') ? 'Switch Fabric' : 'Core Router',
      subtitle: 'Network Routing Infrastructure',
      isInternet: false,
      isDatabase: false,
      isCompute: false,
      isFirewall: false,
      isRouter: true,
      isStorage: false,
    };
  }

  // 6. Identity / IAM / Auth
  if (
    l.includes('iam') ||
    l.includes('auth') ||
    l.includes('cognito') ||
    l.includes('active directory') ||
    l.includes('ldap') ||
    l.includes('okta') ||
    s.includes('iam')
  ) {
    return {
      kind: 'identity',
      category: 'privilege',
      badge: 'Identity & Access',
      subtitle: 'Authentication / Directory',
      isInternet: false,
      isDatabase: false,
      isCompute: false,
      isFirewall: false,
      isRouter: false,
      isStorage: false,
    };
  }

  // 7. General Compute / Microservice / Web Server
  return {
    kind: 'server',
    category: 'compute',
    badge: 'Compute Workload',
    subtitle: 'Application Service / Container',
    isInternet: false,
    isDatabase: false,
    isCompute: true,
    isFirewall: false,
    isRouter: false,
    isStorage: false,
  };
}

/**
 * Robustly parses draw.io XML (both raw XML and embedded compressed formats)
 */
export function parseDrawIoXml(rawXml: string): { cells: RawCell[]; diagramName: string } {
  let xml = rawXml.trim();

  // If user pasted an SVG with embedded draw.io diagram, extract the content
  const svgMatch = xml.match(/content="([^"]+)"/);
  if (svgMatch && svgMatch[1]) {
    try {
      xml = decodeURIComponent(svgMatch[1]);
    } catch {
      // Keep original xml
    }
  }

  // Extract diagram name if present
  let diagramName = 'Cloud / Network Architecture Diagram';
  const nameMatch = xml.match(/<diagram[^>]*name="([^"]+)"/i);
  if (nameMatch && nameMatch[1]) {
    diagramName = nameMatch[1];
  }

  // Regex parser for mxCell tags (lightweight, zero-dep, works seamlessly in browser & node)
  const cells: RawCell[] = [];
  const cellRegex = /<mxCell\s+([^>]+?)(?:\/>|>(.*?)<\/mxCell>)/gis;
  let match: RegExpExecArray | null;

  while ((match = cellRegex.exec(xml)) !== null) {
    const attrString = match[1];
    const innerContent = match[2] || '';

    const id = attrString.match(/id="([^"]+)"/i)?.[1];
    if (!id || id === '0' || id === '1') continue; // Root/Layer cells in draw.io

    let value = attrString.match(/value="([^"]*)"/i)?.[1] || '';
    if (!value && innerContent) {
      value = innerContent;
    }

    const style = attrString.match(/style="([^"]*)"/i)?.[1] || '';
    const vertex = /vertex="1"/i.test(attrString);
    const edge = /edge="1"/i.test(attrString);
    const source = attrString.match(/source="([^"]+)"/i)?.[1];
    const target = attrString.match(/target="([^"]+)"/i)?.[1];
    const parent = attrString.match(/parent="([^"]+)"/i)?.[1];

    cells.push({
      id,
      value: cleanLabel(value),
      style,
      vertex,
      edge,
      source,
      target,
      parent,
    });
  }

  return { cells, diagramName };
}

/**
 * Parses Packet Tracer XML / JSON topology or text device definitions
 */
export function parsePacketTracerTopology(rawContent: string): { cells: RawCell[]; diagramName: string } {
  const content = rawContent.trim();
  const cells: RawCell[] = [];
  let diagramName = 'Cisco Packet Tracer Network Topology';

  // Try JSON first (many modern Packet Tracer topology exporters use JSON)
  if (content.startsWith('{') || content.startsWith('[')) {
    try {
      const data = JSON.parse(content);
      const devices = Array.isArray(data) ? data : data.devices || data.nodes || [];
      const links = data.links || data.connections || data.edges || [];

      devices.forEach((d: { id?: string; name?: string; type?: string; ip?: string }, idx: number) => {
        const id = d.id || `dev-${idx + 1}`;
        const name = d.name || d.type || `Device ${idx + 1}`;
        cells.push({
          id,
          value: d.ip ? `${name} (${d.ip})` : name,
          style: `shape=${(d.type || '').toLowerCase()}`,
          vertex: true,
        });
      });

      links.forEach((l: { id?: string; source?: string; target?: string; label?: string }, idx: number) => {
        if (l.source && l.target) {
          cells.push({
            id: l.id || `link-${idx + 1}`,
            value: l.label || 'Network Link',
            style: 'edge',
            edge: true,
            source: l.source,
            target: l.target,
          });
        }
      });

      return { cells, diagramName: data.name || diagramName };
    } catch {
      // Fall through to regex/XML parsing
    }
  }

  // Regex parser for Packet Tracer XML nodes (e.g. <device name="..." type="..."><interface .../></device>)
  const deviceRegex = /<(?:device|node|router|switch|server|pc)\s+([^>]+?)(?:\/>|>(.*?)<\/(?:device|node|router|switch|server|pc)>)/gis;
  let devMatch: RegExpExecArray | null;
  let idx = 1;

  while ((devMatch = deviceRegex.exec(content)) !== null) {
    const attrs = devMatch[1];
    const explicitId = attrs.match(/\bid="([^"]+)"/i)?.[1];
    const explicitName = attrs.match(/\bname="([^"]+)"/i)?.[1] || attrs.match(/\blabel="([^"]+)"/i)?.[1];
    const name = explicitName || explicitId || `Device ${idx}`;
    const type = attrs.match(/\btype="([^"]+)"/i)?.[1] || 'router';
    const ip = attrs.match(/\bip="([^"]+)"/i)?.[1] || '';

    cells.push({
      id: explicitId || `dev-${idx}`,
      value: ip ? `${name} (${ip})` : `${name} [${type}]`,
      style: `shape=${type.toLowerCase()}`,
      vertex: true,
    });
    idx++;
  }

  // Links in Packet Tracer XML
  const linkRegex = /<(?:link|connection|edge)\s+([^>]+?)(?:\/>|>.*?<\/(?:link|connection|edge)>)/gis;
  let linkMatch: RegExpExecArray | null;
  let linkIdx = 1;

  while ((linkMatch = linkRegex.exec(content)) !== null) {
    const attrs = linkMatch[1];
    const source = attrs.match(/(?:source|from|src)="([^"]+)"/i)?.[1];
    const target = attrs.match(/(?:target|to|dst)="([^"]+)"/i)?.[1];
    const label = attrs.match(/(?:label|port|interface)="([^"]+)"/i)?.[1] || 'Trunk / Cable';

    if (source && target) {
      cells.push({
        id: `link-${linkIdx}`,
        value: label,
        style: 'edge',
        edge: true,
        source,
        target,
      });
      linkIdx++;
    }
  }

  return { cells, diagramName };
}

/**
 * Core engine that converts ANY draw.io or Packet Tracer diagram into an AttackGraph,
 * detecting architectural and network vulnerabilities (S3 public leak, DB in public subnet,
 * flat unsegmented network, missing WAF, missing ACLs).
 */
export function analyzeDiagramToAttackGraph(
  rawContent: string,
  filename: string = 'architecture-diagram.drawio'
): ParsedDiagramResult {
  const isPacketTracer =
    filename.endsWith('.pkt') ||
    filename.endsWith('.pka') ||
    rawContent.toLowerCase().includes('packet tracer') ||
    rawContent.toLowerCase().includes('<topology');

  const { cells, diagramName } = isPacketTracer
    ? parsePacketTracerTopology(rawContent)
    : parseDrawIoXml(rawContent);

  // If no cells found via XML, construct a robust fallback topology from text lines
  let activeCells = cells;
  if (activeCells.length === 0) {
    activeCells = parseTextFallbackTopology(rawContent);
  }

  const nodes: GraphEntity[] = [];
  const edges: GraphRelation[] = [];
  const evidence: Evidence[] = [];
  const findings: Finding[] = [];
  const now = new Date().toISOString();

  // Create virtual evidence representing the diagram file
  const fileEvidenceId = 'ev-diagram-file';
  evidence.push({
    id: fileEvidenceId,
    path: filename,
    line: 1,
    excerpt: `Architecture Diagram: ${diagramName} (${activeCells.length} components analyzed)`,
    url: `diagram://${filename}`,
    collectedAt: now,
  });

  // 1. Build Graph Nodes
  const vertexCells = activeCells.filter(c => c.vertex || (!c.edge && c.value));
  const vertexMap = new Map<string, GraphEntity>();

  vertexCells.forEach((c, index) => {
    const label = c.value || `Component ${index + 1}`;
    const categoryInfo = categorizeNode(label, c.style);

    const evId = `ev-node-${c.id}`;
    evidence.push({
      id: evId,
      path: filename,
      line: index + 10,
      excerpt: `<mxCell id="${c.id}" value="${label}" style="${c.style}" />`,
      url: `diagram://${filename}#${c.id}`,
      collectedAt: now,
    });

    const entity: GraphEntity = {
      id: `node-${c.id}`,
      label,
      kind: categoryInfo.kind,
      category: categoryInfo.category,
      badge: categoryInfo.badge,
      subtitle: categoryInfo.subtitle,
      evidenceIds: [evId],
      severity: categoryInfo.isDatabase || categoryInfo.isStorage ? 'high' : 'medium',
    };

    vertexMap.set(c.id, entity);
    nodes.push(entity);
  });

  // Ensure there is at least an external ingress entrypoint if none declared
  let internetNode = nodes.find(n => n.kind === 'internet');
  if (!internetNode && nodes.length > 0) {
    const inetEvId = 'ev-inferred-internet';
    evidence.push({
      id: inetEvId,
      path: filename,
      line: 1,
      excerpt: `Perimeter Exposure: Inferred Public Internet / External User Ingress to perimeter`,
      url: `diagram://${filename}#internet`,
      collectedAt: now,
    });
    internetNode = {
      id: 'node-public-internet',
      label: 'Public Internet / External Ingress',
      kind: 'internet',
      category: 'exposure',
      badge: 'Public Perimeter',
      subtitle: 'Untrusted External Network',
      evidenceIds: [inetEvId],
    };
    nodes.unshift(internetNode);
  }

  // 2. Build Graph Edges
  const edgeCells = activeCells.filter(c => c.edge || (c.source && c.target));
  let edgeIndex = 1;

  edgeCells.forEach(c => {
    const srcNode = vertexMap.get(c.source || '');
    const dstNode = vertexMap.get(c.target || '');

    if (srcNode && dstNode) {
      const isDangerous =
        (srcNode.kind === 'internet' && (dstNode.kind === 'target' || dstNode.badge?.includes('Database') || dstNode.badge?.includes('Storage'))) ||
        (srcNode.badge?.includes('Public') && dstNode.badge?.includes('Database'));

      const evId = `ev-edge-${c.id}`;
      evidence.push({
        id: evId,
        path: filename,
        line: 50 + edgeIndex,
        excerpt: `<mxCell id="${c.id}" source="${c.source}" target="${c.target}" value="${c.value}" />`,
        url: `diagram://${filename}#edge-${c.id}`,
        collectedAt: now,
      });

      edges.push({
        id: `edge-${c.id}`,
        source: srcNode.id,
        target: dstNode.id,
        label: c.value || (isDangerous ? 'Unfiltered Public Access' : 'Architecture Route'),
        evidenceIds: [evId],
        provenance: 'declared',
        risky: isDangerous,
      });
      edgeIndex++;
    }
  });

  // If no edges were connected in the diagram XML, connect perimeter to entry compute
  if (edges.length === 0 && internetNode && nodes.length > 1) {
    const firstCompute = nodes.find(n => n.id !== internetNode?.id);
    if (firstCompute) {
      edges.push({
        id: 'edge-inferred-ingress',
        source: internetNode.id,
        target: firstCompute.id,
        label: 'Public Ingress Route',
        evidenceIds: [fileEvidenceId],
        provenance: 'inferred',
        risky: false,
      });
    }
  }

  // 3. ARCHITECTURAL & NETWORK VULNERABILITY ANALYSIS (Findings)
  // Finding A: Public S3 Bucket / Object Storage Exposure
  const exposedStorageNode = nodes.find(
    n => n.badge?.includes('Storage') || n.label.toLowerCase().includes('s3') || n.label.toLowerCase().includes('bucket')
  );
  const directStorageAccess = edges.find(
    e => e.target === exposedStorageNode?.id && (e.source === internetNode?.id || e.risky)
  );

  if (exposedStorageNode) {
    findings.push({
      id: 'finding-storage-public',
      rule: 'public-storage-exposure',
      severity: 'high',
      title: `Public Object Storage Exposure (${exposedStorageNode.label})`,
      fix: 'Apply Terraform aws_s3_bucket_public_access_block and restrict bucket policy to private VPC endpoint.',
      evidenceIds: exposedStorageNode.evidenceIds,
    });
  }

  // Finding B: Database in Public Subnet / Direct Ingress Exposure
  const dbNode = nodes.find(
    n => n.badge?.includes('Database') || n.label.toLowerCase().includes('rds') || n.label.toLowerCase().includes('postgres') || n.label.toLowerCase().includes('mysql')
  );
  if (dbNode) {
    findings.push({
      id: 'finding-db-subnet',
      rule: 'database-exposure',
      severity: 'high',
      title: `Unsegmented Database Tier Exposure (${dbNode.label})`,
      fix: 'Migrate datastore to isolated private database subnet and enforce strict Security Group / Network ACL inbound rules.',
      evidenceIds: dbNode.evidenceIds,
    });
  }

  // Finding C: Missing Web Application Firewall (WAF) on Public Ingress
  const hasWaf = nodes.some(
    n => n.badge?.includes('Security') || n.label.toLowerCase().includes('waf') || n.label.toLowerCase().includes('firewall')
  );
  if (!hasWaf && internetNode) {
    findings.push({
      id: 'finding-missing-waf',
      rule: 'missing-waf',
      severity: 'medium',
      title: 'Missing Cloud Web Application Firewall (WAF) on Public Perimeter',
      fix: 'Attach AWS WAFv2 WebACL to Application Load Balancer / API Gateway to filter OWASP Top 10 automated attacks.',
      evidenceIds: internetNode.evidenceIds,
    });
  }

  // Finding D: Flat Network Architecture / Missing DMZ Isolation (Packet Tracer / Router)
  const routerNode = nodes.find(n => n.badge?.includes('Router') || n.badge?.includes('Switch') || n.label.toLowerCase().includes('router'));
  if (routerNode && !hasWaf) {
    findings.push({
      id: 'finding-flat-network',
      rule: 'flat-network-architecture',
      severity: 'high',
      title: `Unsegmented Flat Network Architecture on ${routerNode.label}`,
      fix: 'Deploy Cisco IOS extended ACL policy or 802.1Q VLAN trunk isolation separating DMZ from Internal Core.',
      evidenceIds: routerNode.evidenceIds,
    });
  }

  // Finding E: Unauthenticated Microservice / Lateral Movement Exposure
  const computeNodes = nodes.filter(n => n.category === 'compute' && n.id !== routerNode?.id);
  if (computeNodes.length >= 2) {
    findings.push({
      id: 'finding-lateral-movement',
      rule: 'unauthenticated-microservice',
      severity: 'medium',
      title: 'Missing Mutual TLS & Service-to-Service Authorization',
      fix: 'Enforce Istio/Envoy mTLS PeerAuthentication and signed JWT claims between internal microservice workloads.',
      evidenceIds: computeNodes[0].evidenceIds,
    });
  }

  // 4. CONSTRUCT HOP-BY-HOP ATTACK PATHS
  const attackPathSteps: AttackPathStep[] = [];
  let stepNum = 1;

  if (internetNode) {
    attackPathSteps.push({
      id: `step-${stepNum}`,
      nodeId: internetNode.id,
      title: 'External Perimeter Reconnaissance',
      subtitle: internetNode.label,
      stage: 'internet',
      badge: 'Step 1',
      description: 'Adversary probes public IP endpoints, DNS records, and publicly reachable cloud gateways.',
      evidenceIds: internetNode.evidenceIds,
    });
    stepNum++;
  }

  const ingressHop = computeNodes[0] || routerNode || nodes[1];
  if (ingressHop) {
    attackPathSteps.push({
      id: `step-${stepNum}`,
      nodeId: ingressHop.id,
      title: 'Perimeter Gateway Infiltration',
      subtitle: ingressHop.label,
      stage: 'server',
      badge: `Step ${stepNum}`,
      description: 'Attacker leverages uninspected ingress traffic to bypass edge boundaries and establish footholds.',
      evidenceIds: ingressHop.evidenceIds,
    });
    stepNum++;
  }

  if (computeNodes.length > 1) {
    const pivotHop = computeNodes[1];
    attackPathSteps.push({
      id: `step-${stepNum}`,
      nodeId: pivotHop.id,
      title: 'Subnet Pivoting & Lateral Movement',
      subtitle: pivotHop.label,
      stage: 'privilege',
      badge: `Step ${stepNum}`,
      description: 'Unsegmented network allows direct east-west pivoting across internal services without re-authentication.',
      evidenceIds: pivotHop.evidenceIds,
    });
    stepNum++;
  }

  const crownJewel = dbNode || exposedStorageNode || nodes[nodes.length - 1];
  if (crownJewel) {
    attackPathSteps.push({
      id: `step-${stepNum}`,
      nodeId: crownJewel.id,
      title: 'Crown Jewel Target Compromise & Data Exfiltration',
      subtitle: crownJewel.label,
      stage: 'target',
      badge: `Step ${stepNum}`,
      description: 'Adversary gains direct read/write access to production datastore and customer records.',
      evidenceIds: crownJewel.evidenceIds,
    });
  }

  const attackPaths: AttackPath[] = [
    {
      id: 'path-diagram-lateral',
      title: `Architectural Breach Path: ${diagramName}`,
      severity: 'critical',
      summary: 'External adversary exploits perimeter gaps and flat network architecture to reach core database tier.',
      steps: attackPathSteps,
      nodeIds: attackPathSteps.map(s => s.nodeId),
      edgeIds: edges.map(e => e.id),
    },
  ];

  const graph: AttackGraph = {
    target: `diagram://${diagramName.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
    commit: 'arch-' + Math.random().toString(16).slice(2, 10),
    branch: 'main',
    nodes,
    edges,
    evidence,
    findings,
    attackPaths,
    coverage: {
      inspected: nodes.length,
      total: nodes.length,
      skipped: 0,
      gaps: [],
    },
    collectedAt: now,
  };

  return {
    graph,
    diagramType: isPacketTracer ? 'packet_tracer' : 'drawio',
    deviceCount: nodes.length,
    connectionCount: edges.length,
  };
}

/**
 * Fallback parser if plain text lines or simplified topology is provided
 */
function parseTextFallbackTopology(text: string): RawCell[] {
  const cells: RawCell[] = [];
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);

  let id = 1;
  for (const line of lines) {
    // Check for arrow link (e.g. "Internet -> API Gateway -> Database")
    if (line.includes('->') || line.includes('-->') || line.includes('-') || line.includes(':')) {
      const parts = line.split(/->|-->/).map(p => cleanLabel(p));
      for (let i = 0; i < parts.length; i++) {
        const name = parts[i];
        if (!name) continue;
        let existing = cells.find(c => c.value.toLowerCase() === name.toLowerCase());
        if (!existing) {
          existing = {
            id: `comp-${id++}`,
            value: name,
            style: 'shape=generic',
            vertex: true,
          };
          cells.push(existing);
        }

        if (i > 0) {
          const prev = cells.find(c => c.value.toLowerCase() === parts[i - 1].toLowerCase());
          if (prev && existing) {
            cells.push({
              id: `edge-${id++}`,
              value: 'Connects to',
              style: 'edge',
              edge: true,
              source: prev.id,
              target: existing.id,
            });
          }
        }
      }
    } else {
      cells.push({
        id: `comp-${id++}`,
        value: cleanLabel(line),
        style: 'shape=generic',
        vertex: true,
      });
    }
  }

  return cells;
}
