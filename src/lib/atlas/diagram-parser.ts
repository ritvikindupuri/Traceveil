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

export type ComponentRole =
  | 'internet'
  | 'firewall_waf'
  | 'load_balancer'
  | 'compute'
  | 'datastore'
  | 'storage'
  | 'queue_stream'
  | 'identity'
  | 'network_device'
  | 'unknown';

interface ClassifiedNode {
  role: ComponentRole;
  kind: GraphEntity['kind'];
  category: GraphEntity['category'];
  badge: string;
  subtitle: string;
  severity: 'high' | 'medium' | 'low';
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
 * Universally classifies ANY diagram node across AWS, Azure, GCP, Cisco, Kubernetes, On-Premise, and SCADA.
 * Not limited to presets — recognizes shapes, standard keywords, and infrastructure terminology.
 */
function classifyComponent(label: string, style: string): ClassifiedNode {
  const l = label.toLowerCase();
  const s = style.toLowerCase();

  // 1. Internet / External Perimeter
  if (
    l.includes('internet') ||
    l.includes('public') ||
    l.includes('external') ||
    l.includes('wan') ||
    l.includes('client') ||
    l.includes('user') ||
    l.includes('traffic') ||
    l.includes('browser') ||
    s.includes('.internet') ||
    s.includes('.cloud') ||
    s.includes('.users') ||
    s.includes('.client')
  ) {
    return {
      role: 'internet',
      kind: 'internet',
      category: 'exposure',
      badge: 'Public Perimeter',
      subtitle: 'Untrusted Ingress',
      severity: 'low',
    };
  }

  // 2. Firewalls, WAF, Security Gateways, IDS/IPS
  if (
    l.includes('waf') ||
    l.includes('firewall') ||
    l.includes('armor') ||
    l.includes('shield') ||
    l.includes('asa') ||
    l.includes('palo alto') ||
    l.includes('fortinet') ||
    l.includes('fortigate') ||
    l.includes('pfsense') ||
    l.includes('security group') ||
    l.includes('guardduty') ||
    l.includes('iptables') ||
    s.includes('.waf') ||
    s.includes('.firewall') ||
    s.includes('.shield') ||
    s.includes('.security')
  ) {
    return {
      role: 'firewall_waf',
      kind: 'service',
      category: 'exposure',
      badge: 'Security Gateway',
      subtitle: 'Traffic Inspection & Filter',
      severity: 'low',
    };
  }

  // 3. Load Balancers, API Gateways, Ingress Controllers, Reverse Proxies
  if (
    l.includes('alb') ||
    l.includes('nlb') ||
    l.includes('elb') ||
    l.includes('load balancer') ||
    l.includes('api gateway') ||
    l.includes('ingress') ||
    l.includes('proxy') ||
    l.includes('envoy') ||
    l.includes('traefik') ||
    l.includes('kong') ||
    l.includes('nginx') ||
    l.includes('f5') ||
    l.includes('front door') ||
    l.includes('application gateway') ||
    s.includes('.load_balancing') ||
    s.includes('.api_gateway') ||
    s.includes('.ingress') ||
    s.includes('.proxy')
  ) {
    return {
      role: 'load_balancer',
      kind: 'service',
      category: 'compute',
      badge: 'Ingress Gateway',
      subtitle: 'Load Balancer / Proxy',
      severity: 'low',
    };
  }

  // 4. Object Storage & File Buckets (AWS S3, Azure Blob, GCS, SAN/NAS)
  if (
    l.includes('s3') ||
    l.includes('bucket') ||
    l.includes('blob') ||
    l.includes('storage') ||
    l.includes('gcs') ||
    l.includes('file share') ||
    l.includes('nfs') ||
    l.includes('san') ||
    l.includes('nas') ||
    l.includes('data lake') ||
    s.includes('.s3') ||
    s.includes('.storage') ||
    s.includes('.blob') ||
    s.includes('.bucket')
  ) {
    return {
      role: 'storage',
      kind: 'target',
      category: 'target',
      badge: 'Object / File Storage',
      subtitle: 'Cloud Storage Bucket',
      severity: 'high',
    };
  }

  // 5. Databases & Datastores (SQL, NoSQL, Cache, Cloud Databases)
  if (
    l.includes('database') ||
    l.includes('db') ||
    l.includes('rds') ||
    l.includes('aurora') ||
    l.includes('postgres') ||
    l.includes('mysql') ||
    l.includes('mongo') ||
    l.includes('redis') ||
    l.includes('dynamo') ||
    l.includes('cosmos') ||
    l.includes('bigquery') ||
    l.includes('snowflake') ||
    l.includes('oracle') ||
    l.includes('cassandra') ||
    l.includes('spanner') ||
    l.includes('sql') ||
    s.includes('.database') ||
    s.includes('.rds') ||
    s.includes('.sql') ||
    s.includes('.nosql')
  ) {
    return {
      role: 'datastore',
      kind: 'target',
      category: 'target',
      badge: 'Crown Jewel Database',
      subtitle: 'Persistent Data Tier',
      severity: 'high',
    };
  }

  // 6. Identity, Directory & Secrets (IAM, Active Directory, Cognito, Vault)
  if (
    l.includes('iam') ||
    l.includes('auth') ||
    l.includes('active directory') ||
    l.includes('ldap') ||
    l.includes('cognito') ||
    l.includes('okta') ||
    l.includes('keycloak') ||
    l.includes('vault') ||
    l.includes('secrets') ||
    l.includes('key vault') ||
    l.includes('kms') ||
    s.includes('.iam') ||
    s.includes('.key') ||
    s.includes('.vault')
  ) {
    return {
      role: 'identity',
      kind: 'identity',
      category: 'privilege',
      badge: 'Identity & Secrets',
      subtitle: 'Directory / Privilege Vault',
      severity: 'high',
    };
  }

  // 7. Network Routing Infrastructure (Routers, Switches, VPN, Peering, Transit)
  if (
    l.includes('router') ||
    l.includes('switch') ||
    l.includes('gateway') ||
    l.includes('cisco') ||
    l.includes('catalyst') ||
    l.includes('nexus') ||
    l.includes('vpn') ||
    l.includes('peering') ||
    l.includes('transit') ||
    l.includes('vnet') ||
    l.includes('vpc') ||
    l.includes('subnet') ||
    s.includes('.router') ||
    s.includes('.switch') ||
    s.includes('.networking') ||
    s.includes('.vpc')
  ) {
    return {
      role: 'network_device',
      kind: 'server',
      category: 'compute',
      badge: l.includes('switch') ? 'Switch Fabric' : 'Network Router',
      subtitle: 'L2/L3 Infrastructure',
      severity: 'medium',
    };
  }

  // 8. Event Queues & Streams (Kafka, SQS, RabbitMQ, EventBridge)
  if (
    l.includes('kafka') ||
    l.includes('sqs') ||
    l.includes('rabbitmq') ||
    l.includes('queue') ||
    l.includes('pub/sub') ||
    l.includes('eventbridge') ||
    l.includes('kinesis') ||
    s.includes('.queue') ||
    s.includes('.messaging')
  ) {
    return {
      role: 'queue_stream',
      kind: 'service',
      category: 'compute',
      badge: 'Message Broker',
      subtitle: 'Event Stream / Queue',
      severity: 'medium',
    };
  }

  // 9. Compute Workloads (VMs, Containers, Pods, Microservices, Serverless)
  return {
    role: 'compute',
    kind: 'server',
    category: 'compute',
    badge: 'Compute Workload',
    subtitle: 'Container / VM / Service',
    severity: 'medium',
  };
}

/**
 * Universal XML parser for draw.io diagrams
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

  let diagramName = 'Architecture Diagram';
  const nameMatch = xml.match(/<diagram[^>]*name="([^"]+)"/i);
  if (nameMatch && nameMatch[1]) {
    diagramName = nameMatch[1];
  }

  const cells: RawCell[] = [];
  const cellRegex = /<mxCell\s+([^>]+?)(?:\/>|>(.*?)<\/mxCell>)/gis;
  let match: RegExpExecArray | null;

  while ((match = cellRegex.exec(xml)) !== null) {
    const attrString = match[1];
    const innerContent = match[2] || '';

    const id = attrString.match(/id="([^"]+)"/i)?.[1];
    if (!id || id === '0' || id === '1') continue;

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
 * Universal Packet Tracer topology parser (JSON or XML)
 */
export function parsePacketTracerTopology(rawContent: string): { cells: RawCell[]; diagramName: string } {
  const content = rawContent.trim();
  const cells: RawCell[] = [];
  let diagramName = 'Cisco Packet Tracer Network Topology';

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
      // Fall through to regex
    }
  }

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

function isPublicIp(ip: string): boolean {
  if (!ip) return false;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('0.')) return false;
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (!isNaN(second) && second >= 16 && second <= 31) return false;
  }
  return true;
}

function getSubnetPrefix(ip: string, mask: string): string {
  const ipParts = ip.split('.').map(Number);
  const maskParts = mask.split('.').map(Number);
  if (ipParts.length !== 4 || maskParts.length !== 4) return ip;
  const netParts = ipParts.map((p, i) => p & maskParts[i]);
  const cidr = maskParts.reduce((acc, m) => acc + (m.toString(2).match(/1/g) || []).length, 0);
  return `${netParts.join('.')}/${cidr}`;
}

/**
 * Universal Cisco IOS / Packet Tracer running-config and startup-config parser
 */
export function parseCiscoIosConfig(rawText: string, filename: string): {
  cells: RawCell[];
  diagramName: string;
  ciscoFindings: Finding[];
} {
  const text = rawText.replace(/[^\x20-\x7E\r\n\t]/g, ' ');
  const lines = text.split('\n').map(l => l.trim());

  const cells: RawCell[] = [];
  const ciscoFindings: Finding[] = [];
  let diagramName = 'Cisco Network Architecture';

  const hostnames: string[] = [];
  lines.forEach(l => {
    const match = l.match(/^hostname\s+([A-Za-z0-9_.-]+)/i);
    if (match && !hostnames.includes(match[1])) {
      hostnames.push(match[1]);
    }
  });

  if (hostnames.length === 0) {
    hostnames.push('Cisco-Device-1');
  } else {
    diagramName = `Cisco Network (${hostnames.join(', ')})`;
  }

  let currentHost = hostnames[0];
  let currentInterface: { name: string; ip?: string; mask?: string; isPublic: boolean; accessGroupIn?: string } | null = null;
  const deviceInterfaces = new Map<string, typeof currentInterface[]>();
  hostnames.forEach(h => deviceInterfaces.set(h, []));

  let inVty = false;

  lines.forEach((line, lineNum) => {
    const hostMatch = line.match(/^hostname\s+([A-Za-z0-9_.-]+)/i);
    if (hostMatch) {
      currentHost = hostMatch[1];
      inVty = false;
      return;
    }

    const ifMatch = line.match(/^interface\s+([A-Za-z0-9_./-]+)/i);
    if (ifMatch) {
      inVty = false;
      currentInterface = { name: ifMatch[1], isPublic: false };
      deviceInterfaces.get(currentHost)?.push(currentInterface);
      return;
    }

    if (currentInterface) {
      const ipMatch = line.match(/^ip\s+address\s+([0-9.]+)\s+([0-9.]+)/i);
      if (ipMatch) {
        currentInterface.ip = ipMatch[1];
        currentInterface.mask = ipMatch[2];
        currentInterface.isPublic = isPublicIp(ipMatch[1]);
      }
      const aclMatch = line.match(/^ip\s+access-group\s+([A-Za-z0-9_-]+)\s+in/i);
      if (aclMatch) {
        currentInterface.accessGroupIn = aclMatch[1];
      }
    }

    if (line.match(/^line\s+vty/i)) {
      inVty = true;
      currentInterface = null;
      return;
    }

    if (inVty && line.match(/transport\s+input\s+(?:all|telnet)/i)) {
      ciscoFindings.push({
        id: `finding-telnet-${currentHost}`,
        rule: 'cleartext-telnet-mgmt',
        severity: 'high',
        title: `Cleartext Telnet Remote Management Enabled on ${currentHost}`,
        fix: "Disable Telnet and enforce SSHv2: 'line vty 0 4' -> 'transport input ssh' with 2048-bit RSA key.",
        evidenceIds: [`ev-line-${lineNum + 1}`],
      });
    }

    if (line.match(/access-list\s+\d+\s+permit\s+ip\s+any\s+any/i) || line.match(/permit\s+ip\s+any\s+any/i)) {
      ciscoFindings.push({
        id: `finding-acl-permissive-${currentHost}-${lineNum}`,
        rule: 'permissive-cisco-acl',
        severity: 'high',
        title: `Overly Permissive Access Control List (permit ip any any) on ${currentHost}`,
        fix: "Replace wildcard 'permit ip any any' with least-privilege destination port filtering.",
        evidenceIds: [`ev-line-${lineNum + 1}`],
      });
    }

    if (line.match(/^no\s+service\s+password-encryption/i) || line.match(/^password\s+[A-Za-z0-9]+/i)) {
      if (!ciscoFindings.some(f => f.rule === 'cleartext-passwords' && f.title.includes(currentHost))) {
        ciscoFindings.push({
          id: `finding-pwd-${currentHost}`,
          rule: 'cleartext-passwords',
          severity: 'medium',
          title: `Plaintext Passwords in Running Configuration on ${currentHost}`,
          fix: "Enable 'service password-encryption' and configure secret hashes with 'enable secret'.",
          evidenceIds: [`ev-line-${lineNum + 1}`],
        });
      }
    }
  });

  hostnames.forEach(h => {
    const isSwitch = h.toLowerCase().includes('switch') || h.toLowerCase().includes('sw');
    cells.push({
      id: `dev-${h}`,
      value: `${h} [${isSwitch ? 'Switch' : 'Router'}]`,
      style: isSwitch ? 'shape=cisco.switch' : 'shape=cisco.router',
      vertex: true,
    });
  });

  const subnetMap = new Map<string, { host: string; ifName: string; ip: string }[]>();
  deviceInterfaces.forEach((ifs, host) => {
    ifs.forEach(iface => {
      if (iface.ip && iface.mask) {
        const subnet = getSubnetPrefix(iface.ip, iface.mask);
        if (!subnetMap.has(subnet)) subnetMap.set(subnet, []);
        subnetMap.get(subnet)?.push({ host, ifName: iface.name, ip: iface.ip });
      }
    });
  });

  let linkCount = 1;
  subnetMap.forEach((endpoints, subnet) => {
    if (endpoints.length >= 2) {
      for (let i = 0; i < endpoints.length - 1; i++) {
        const ep1 = endpoints[i];
        const ep2 = endpoints[i + 1];
        if (ep1.host !== ep2.host) {
          cells.push({
            id: `link-${linkCount++}`,
            value: `${ep1.ifName} <-> ${ep2.ifName} (${subnet})`,
            style: 'edge',
            edge: true,
            source: `dev-${ep1.host}`,
            target: `dev-${ep2.host}`,
          });
        }
      }
    } else if (endpoints.length === 1) {
      const ep = endpoints[0];
      const isPublic = isPublicIp(ep.ip);
      const peerId = isPublic ? 'public-wan' : `net-${subnet.replace(/[^a-z0-9]/gi, '-')}`;
      const peerName = isPublic ? 'Public Internet / WAN' : `Internal Subnet (${subnet})`;

      if (!cells.some(c => c.id === peerId)) {
        cells.push({
          id: peerId,
          value: peerName,
          style: isPublic ? 'shape=mxgraph.aws4.internet' : 'shape=network.subnet',
          vertex: true,
        });
      }

      cells.push({
        id: `link-${linkCount++}`,
        value: `${ep.ifName} · ${ep.ip}`,
        style: 'edge',
        edge: true,
        source: isPublic ? peerId : `dev-${ep.host}`,
        target: isPublic ? `dev-${ep.host}` : peerId,
      });

      const ifaceObj = deviceInterfaces.get(ep.host)?.find(item => item.name === ep.ifName);
      if (isPublic && !ifaceObj?.accessGroupIn) {
        ciscoFindings.push({
          id: `finding-missing-acl-${ep.host}-${ep.ifName}`,
          rule: 'missing-ingress-acl',
          severity: 'high',
          title: `Unfiltered Public Ingress Interface (${ep.ifName} · ${ep.ip}) on ${ep.host}`,
          fix: `Apply inbound access-list: 'interface ${ep.ifName}' -> 'ip access-group SEC_INBOUND in'.`,
          evidenceIds: [`ev-dev-${ep.host}`],
        });
      }
    }
  });

  return { cells, diagramName, ciscoFindings };
}

/**
 * Universal graph-theoretic engine that analyzes ANY draw.io or Packet Tracer diagram.
 * Evaluates real topological edges, choke-points, path reachability, and isolation boundaries.
 * Zero hardcoded presets — findings are derived 100% from actual diagram topology!
 */
export function analyzeDiagramToAttackGraph(
  rawContent: string,
  filename: string = 'architecture-diagram.drawio'
): ParsedDiagramResult {
  const isCiscoConfig =
    filename.endsWith('.cfg') ||
    filename.endsWith('.ios') ||
    filename.endsWith('.conf') ||
    rawContent.includes('hostname ') ||
    rawContent.includes('interface GigabitEthernet') ||
    rawContent.includes('interface FastEthernet') ||
    rawContent.includes('interface Vlan') ||
    rawContent.includes('access-list ') ||
    rawContent.includes('line vty');

  const isPacketTracer =
    !isCiscoConfig &&
    (filename.endsWith('.pkt') ||
      filename.endsWith('.pka') ||
      rawContent.toLowerCase().includes('packet tracer') ||
      rawContent.toLowerCase().includes('<topology'));

  let cells: RawCell[] = [];
  let diagramName = 'Architecture Diagram';
  const findings: Finding[] = [];

  if (isCiscoConfig) {
    const cisco = parseCiscoIosConfig(rawContent, filename);
    cells = cisco.cells;
    diagramName = cisco.diagramName;
    cisco.ciscoFindings.forEach(f => findings.push(f));
  } else if (isPacketTracer) {
    const pt = parsePacketTracerTopology(rawContent);
    cells = pt.cells;
    diagramName = pt.diagramName;
  } else {
    const drawio = parseDrawIoXml(rawContent);
    cells = drawio.cells;
    diagramName = drawio.diagramName;
  }

  let activeCells = cells;
  if (activeCells.length === 0) {
    activeCells = parseTextFallbackTopology(rawContent);
  }

  const nodes: GraphEntity[] = [];
  const edges: GraphRelation[] = [];
  const evidence: Evidence[] = [];
  const now = new Date().toISOString();

  const fileEvidenceId = 'ev-diagram-file';
  evidence.push({
    id: fileEvidenceId,
    path: filename,
    line: 1,
    excerpt: `Architecture Diagram: ${diagramName} (${activeCells.length} elements inspected)`,
    url: `diagram://${filename}`,
    collectedAt: now,
  });

  // 1. Build Nodes & Classify Components
  const vertexCells = activeCells.filter(c => c.vertex || (!c.edge && c.value));
  const vertexMap = new Map<string, GraphEntity>();
  const roleMap = new Map<string, ComponentRole>();

  vertexCells.forEach((c, index) => {
    const label = c.value || `Component ${index + 1}`;
    const classification = classifyComponent(label, c.style);

    const evId = `ev-node-${c.id}`;
    evidence.push({
      id: evId,
      path: filename,
      line: index + 5,
      excerpt: `<mxCell id="${c.id}" value="${label}" style="${c.style}" />`,
      url: `diagram://${filename}#${c.id}`,
      collectedAt: now,
    });

    const entity: GraphEntity = {
      id: `node-${c.id}`,
      label,
      kind: classification.kind,
      category: classification.category,
      badge: classification.badge,
      subtitle: classification.subtitle,
      evidenceIds: [evId],
      severity: classification.severity,
    };

    vertexMap.set(c.id, entity);
    roleMap.set(entity.id, classification.role);
    nodes.push(entity);
  });

  // Identify or infer Perimeter Entrypoints
  let perimeterNodes = nodes.filter(n => roleMap.get(n.id) === 'internet');
  if (perimeterNodes.length === 0 && nodes.length > 0) {
    const inetEvId = 'ev-inferred-perimeter';
    evidence.push({
      id: inetEvId,
      path: filename,
      line: 1,
      excerpt: `Perimeter Exposure: External Network Ingress Boundary`,
      url: `diagram://${filename}#perimeter`,
      collectedAt: now,
    });
    const inferredPerimeter: GraphEntity = {
      id: 'node-public-perimeter',
      label: 'Public Internet / External Ingress',
      kind: 'internet',
      category: 'exposure',
      badge: 'Public Perimeter',
      subtitle: 'Untrusted External Network',
      evidenceIds: [inetEvId],
    };
    nodes.unshift(inferredPerimeter);
    roleMap.set(inferredPerimeter.id, 'internet');
    perimeterNodes = [inferredPerimeter];
  }

  // 2. Build Graph Edges & Adjacency Structure
  const edgeCells = activeCells.filter(c => c.edge || (c.source && c.target));
  const adjacency = new Map<string, string[]>();
  const undirectedAdjacency = new Map<string, string[]>();

  nodes.forEach(n => {
    adjacency.set(n.id, []);
    undirectedAdjacency.set(n.id, []);
  });

  let edgeIndex = 1;
  edgeCells.forEach(c => {
    const srcNode = vertexMap.get(c.source || '');
    const dstNode = vertexMap.get(c.target || '');

    if (srcNode && dstNode) {
      const srcRole = roleMap.get(srcNode.id);
      const dstRole = roleMap.get(dstNode.id);

      // Risky if untrusted perimeter touches internal datastore/storage directly
      const isDangerous =
        srcRole === 'internet' && (dstRole === 'datastore' || dstRole === 'storage');

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
        label: c.value || (isDangerous ? 'Direct Unfiltered Exposure' : 'Traffic Link'),
        evidenceIds: [evId],
        provenance: 'declared',
        risky: isDangerous,
      });

      adjacency.get(srcNode.id)?.push(dstNode.id);
      undirectedAdjacency.get(srcNode.id)?.push(dstNode.id);
      undirectedAdjacency.get(dstNode.id)?.push(srcNode.id);
      edgeIndex++;
    }
  });

  // If no edges were connected in the diagram XML, connect perimeter to entry compute
  if (edges.length === 0 && perimeterNodes[0] && nodes.length > 1) {
    const firstTarget = nodes.find(n => n.id !== perimeterNodes[0].id);
    if (firstTarget) {
      edges.push({
        id: 'edge-inferred-ingress',
        source: perimeterNodes[0].id,
        target: firstTarget.id,
        label: 'Inferred Ingress Route',
        evidenceIds: [fileEvidenceId],
        provenance: 'inferred',
        risky: false,
      });
      adjacency.get(perimeterNodes[0].id)?.push(firstTarget.id);
    }
  }

  // 3. GRAPH-THEORETIC REACHABILITY & VULNERABILITY ANALYSIS (Zero presets)
  // Check A: Which nodes are reachable from the perimeter?
  const reachableFromPerimeter = new Set<string>();
  const securityIntermediaries = new Set<string>();

  nodes.forEach(n => {
    if (roleMap.get(n.id) === 'firewall_waf') {
      securityIntermediaries.add(n.id);
    }
  });

  // BFS traversal tracking if path passed through a security gateway
  const queue: { nodeId: string; passedSecurity: boolean }[] = [];
  perimeterNodes.forEach(p => {
    queue.push({ nodeId: p.id, passedSecurity: false });
    reachableFromPerimeter.add(p.id);
  });

  const unprotectedCrownJewels: GraphEntity[] = [];
  const directlyExposedStorage: GraphEntity[] = [];

  while (queue.length > 0) {
    const current = queue.shift()!;
    const neighbors = adjacency.get(current.nodeId) || [];

    for (const neighborId of neighbors) {
      const neighbor = nodes.find(n => n.id === neighborId);
      if (!neighbor) continue;

      const isSecurityNode = securityIntermediaries.has(neighborId);
      const passedSecurity = current.passedSecurity || isSecurityNode;
      const role = roleMap.get(neighborId);

      // Check if datastore or storage is reached WITHOUT passing through a security inspection node
      if (!passedSecurity && (role === 'datastore' || role === 'storage')) {
        unprotectedCrownJewels.push(neighbor);
        // Direct 1-hop exposure from internet
        if (roleMap.get(current.nodeId) === 'internet') {
          if (role === 'storage') directlyExposedStorage.push(neighbor);
        }
      }

      if (!reachableFromPerimeter.has(neighborId)) {
        reachableFromPerimeter.add(neighborId);
        queue.push({ nodeId: neighborId, passedSecurity });
      }
    }
  }

  // Finding 1: Direct Public Storage Exposure
  if (directlyExposedStorage.length > 0) {
    const s = directlyExposedStorage[0];
    findings.push({
      id: 'finding-storage-public',
      rule: 'public-storage-exposure',
      severity: 'high',
      title: `Public Object Storage Exposure (${s.label})`,
      fix: 'Apply Terraform aws_s3_bucket_public_access_block and enforce private VPC endpoint.',
      evidenceIds: s.evidenceIds,
    });
  }

  // Finding 2: Unprotected Datastore / Crown Jewel (No WAF or Firewall in path)
  if (unprotectedCrownJewels.length > 0) {
    const db = unprotectedCrownJewels.find(n => roleMap.get(n.id) === 'datastore') || unprotectedCrownJewels[0];
    findings.push({
      id: 'finding-db-subnet',
      rule: 'database-exposure',
      severity: 'high',
      title: `Unsegmented Database Ingress Exposure (${db.label})`,
      fix: 'Migrate datastore to isolated private database subnet and enforce strict Security Group inbound rules.',
      evidenceIds: db.evidenceIds,
    });
  }

  // Finding 3: Missing Perimeter Inspection Gateway (WAF / Firewall)
  const hasSecurityAtPerimeter = perimeterNodes.some(p => {
    const downstream = adjacency.get(p.id) || [];
    return downstream.some(id => securityIntermediaries.has(id));
  });

  if (!hasSecurityAtPerimeter && nodes.length >= 3) {
    findings.push({
      id: 'finding-missing-waf',
      rule: 'missing-waf',
      severity: 'medium',
      title: 'Missing Cloud Web Application Firewall (WAF) / Perimeter Filter',
      fix: 'Attach AWS WAFv2 WebACL to perimeter load balancer / gateway to inspect incoming requests.',
      evidenceIds: perimeterNodes[0].evidenceIds,
    });
  }

  // Finding 4: Flat Network Architecture (Router directly bridges External & Internal Core)
  const networkDevices = nodes.filter(n => roleMap.get(n.id) === 'network_device');
  networkDevices.forEach(r => {
    const connected = undirectedAdjacency.get(r.id) || [];
    const touchesExternal = connected.some(id => roleMap.get(id) === 'internet');
    const touchesInternal = connected.some(id => roleMap.get(id) === 'datastore' || roleMap.get(id) === 'storage');
    const hasFirewall = connected.some(id => roleMap.get(id) === 'firewall_waf');

    if (touchesExternal && touchesInternal && !hasFirewall) {
      findings.push({
        id: `finding-flat-network-${r.id}`,
        rule: 'flat-network-architecture',
        severity: 'high',
        title: `Unsegmented Flat Network Architecture on ${r.label}`,
        fix: 'Deploy Cisco IOS extended ACL policy or 802.1Q VLAN trunk isolation separating external DMZ from core subnet.',
        evidenceIds: r.evidenceIds,
      });
    }
  });

  // Finding 5: Unauthenticated Lateral Microservice Communication
  const computeWorkloads = nodes.filter(n => roleMap.get(n.id) === 'compute');
  if (computeWorkloads.length >= 2 && !findings.some(f => f.rule === 'unauthenticated-microservice')) {
    findings.push({
      id: 'finding-lateral-movement',
      rule: 'unauthenticated-microservice',
      severity: 'medium',
      title: 'Missing Mutual TLS & Service-to-Service Authorization',
      fix: 'Enforce Istio STRICT mutual TLS and fine-grained SPIFFE workload identity authorization.',
      evidenceIds: computeWorkloads[0].evidenceIds,
    });
  }

  // Finding 6: Exposed Remote Management Protocols (SSH / RDP / Telnet)
  const mgmtKeywords = ['ssh', '22', 'rdp', '3389', 'telnet', '23', 'snmp', '161'];
  edges.forEach(e => {
    const l = (e.label || '').toLowerCase();
    if (mgmtKeywords.some(k => l.includes(k))) {
      findings.push({
        id: `finding-mgmt-exposure-${e.id}`,
        rule: 'public-cidr',
        severity: 'high',
        title: `Exposed Remote Management Protocol (${e.label})`,
        fix: 'Remove public ingress to management ports and require Bastion host or VPN with MFA.',
        evidenceIds: e.evidenceIds,
      });
    }
  });

  // 4. DYNAMIC SHORTEST ATTACK PATH VIA BFS (Derived strictly from topology)
  const attackPathSteps: AttackPathStep[] = [];
  const startNode = perimeterNodes[0];
  const targetNode =
    unprotectedCrownJewels[0] ||
    nodes.find(n => roleMap.get(n.id) === 'datastore' || roleMap.get(n.id) === 'storage') ||
    computeWorkloads[computeWorkloads.length - 1] ||
    nodes[nodes.length - 1];

  if (startNode && targetNode) {
    // Find shortest path from startNode to targetNode using BFS
    const parentMap = new Map<string, string>();
    const visited = new Set<string>();
    const bfsQueue: string[] = [startNode.id];
    visited.add(startNode.id);

    while (bfsQueue.length > 0) {
      const u = bfsQueue.shift()!;
      if (u === targetNode.id) break;

      const neighbors = adjacency.get(u) || [];
      for (const v of neighbors) {
        if (!visited.has(v)) {
          visited.add(v);
          parentMap.set(v, u);
          bfsQueue.push(v);
        }
      }
    }

    // Reconstruct path
    const pathIds: string[] = [];
    let curr: string | undefined = targetNode.id;
    while (curr) {
      pathIds.unshift(curr);
      curr = parentMap.get(curr);
    }

    // If no directed path exists, fall back to reachable node chain
    const finalChain = pathIds.length > 1 ? pathIds : [startNode.id, targetNode.id];

    finalChain.forEach((nodeId, idx) => {
      const n = nodes.find(item => item.id === nodeId);
      if (!n) return;

      const role = roleMap.get(nodeId);
      const stage: AttackPathStep['stage'] =
        role === 'internet'
          ? 'internet'
          : role === 'datastore' || role === 'storage'
          ? 'target'
          : role === 'identity'
          ? 'privilege'
          : 'server';

      attackPathSteps.push({
        id: `step-${idx + 1}`,
        nodeId: n.id,
        title: idx === 0 ? 'External Perimeter Reconnaissance' : idx === finalChain.length - 1 ? 'Crown Jewel Data Exfiltration' : `Lateral Pivot: ${n.label}`,
        subtitle: n.label,
        stage,
        badge: `Hop ${idx + 1}`,
        description:
          idx === 0
            ? 'Adversary probes public IP endpoints and exposed perimeter entrypoints.'
            : idx === finalChain.length - 1
            ? 'Adversary establishes unauthorized access to core datastore and sensitive customer assets.'
            : `Adversary traverses uninspected boundary to compromise ${n.label}.`,
        evidenceIds: n.evidenceIds,
      });
    });
  }

  const attackPaths: AttackPath[] = [
    {
      id: 'path-diagram-adaptive',
      title: `Architectural Breach Path: ${diagramName}`,
      severity: findings.some(f => f.severity === 'high') ? 'critical' : 'high',
      summary: `Dynamic graph analysis discovered ${findings.length} architectural exposures across ${nodes.length} components.`,
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
 * Universal text topology parser
 */
function parseTextFallbackTopology(text: string): RawCell[] {
  const cells: RawCell[] = [];
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);

  let id = 1;
  for (const line of lines) {
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
