import type { AttackGraph, GraphEntity, GraphRelation } from './types';

/**
 * Generates a valid, complete draw.io XML file containing the remediated & hardened architecture.
 * It applies architectural best practices:
 * - Moves unsegmented datastores into an isolated Private Subnet container
 * - Inserts a Web Application Firewall (WAF) / Perimeter Shield before ingress load balancers
 * - Restricts direct public internet connections to internal components
 * - Enforces S3 / Object Storage Public Access Block and encryption boundaries
 * - Annotates remediated nodes with [✓ SECURED] badges and clean color styling
 */
export function generateCorrectedDrawIoXml(graph: AttackGraph): string {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const findings = graph.findings || [];

  // Determine what remediations are needed from findings
  const hasDbExposure = findings.some(f => f.rule === 'public-database-exposure' || f.rule === 'database-exposure');
  const hasStorageExposure = findings.some(f => f.rule === 'public-storage-exposure');
  const hasMissingWaf = findings.some(f => f.rule === 'missing-waf');
  const hasFlatNetwork = findings.some(f => f.rule === 'flat-network-architecture');

  interface DiagramCell {
    id: string;
    value: string;
    style: string;
    vertex?: boolean;
    edge?: boolean;
    source?: string;
    target?: string;
    parent?: string;
    x?: number;
    y?: number;
    width?: number;
    height?: number;
  }

  const cells: DiagramCell[] = [];
  let nextId = 100;

  // Root default cells required by draw.io
  cells.push({ id: '0', value: '', style: '' });
  cells.push({ id: '1', value: '', style: '', parent: '0' });

  // 1. Title & Legend Header Banner
  cells.push({
    id: 'header-banner',
    value: `&lt;b&gt;TRACEVEIL HARDENED ARCHITECTURE&lt;/b&gt;&lt;br&gt;&lt;font style="font-size: 11px; font-weight: normal; color: #555555;"&gt;Target: ${graph.target.replace('diagram://', '')} · Auto-Remediated Zero-Trust Topology&lt;/font&gt;`,
    style: 'shape=rectangle;fillColor=#F3F4F6;strokeColor=#D1D5DB;rounded=1;fontColor=#111827;align=left;spacingLeft=15;fontSize=14;fontFamily=Helvetica;',
    vertex: true,
    parent: '1',
    x: 40,
    y: 30,
    width: 920,
    height: 50,
  });

  // 2. Legend / Remediation Summary Box
  cells.push({
    id: 'legend-box',
    value: `&lt;b&gt;Remediation Legend:&lt;/b&gt;&lt;br&gt;• &lt;font color="#15803D"&gt;&lt;b&gt;[✓ SECURED]&lt;/b&gt;&lt;/font&gt; Isolated Subnet &amp; WAF Protection&lt;br&gt;• Perimeter Inspection Active (No Direct Public DB Routing)&lt;br&gt;• Least-Privilege Network Ingress Enforced`,
    style: 'shape=rectangle;fillColor=#ECFDF5;strokeColor=#86EFAC;rounded=1;fontColor=#065F46;align=left;spacingLeft=10;fontSize=10;fontFamily=Helvetica;',
    vertex: true,
    parent: '1',
    x: 680,
    y: 35,
    width: 270,
    height: 40,
  });

  // Layout coordinates
  // Tier 0: Internet (X: 50)
  // Tier 1: WAF & Perimeter (X: 220)
  // Tier 2: Ingress / ALB (X: 390)
  // Tier 3: Compute / App Tier (X: 560)
  // Tier 4: Private Subnet (Container) -> Datastore & Storage (X: 740)

  // 3. Private Subnet Container (If DB or Storage exists)
  const privateSubnetId = 'container-private-subnet';
  cells.push({
    id: privateSubnetId,
    value: `&lt;b&gt;[✓ SECURED] Isolated Private Subnet (10.0.2.0/24)&lt;/b&gt;&lt;br&gt;&lt;font style="font-size: 10px; color: #166534;"&gt;No Public Route / No Internet Gateway Attachment&lt;/font&gt;`,
    style: 'swimlane;fillColor=#F0FDF4;strokeColor=#16A34A;strokeWidth=2;dashed=1;rounded=1;fontColor=#166534;align=left;spacingLeft=10;startSize=30;fontSize=11;fontFamily=Helvetica;',
    vertex: true,
    parent: '1',
    x: 720,
    y: 110,
    width: 250,
    height: 480,
  });

  // Check if we need to insert a WAF node
  const wafNodeId = 'node-waf-perimeter';
  cells.push({
    id: wafNodeId,
    value: `&lt;b&gt;[✓ SECURED]&lt;/b&gt;&lt;br&gt;Cloud WAF &amp; Shield&lt;br&gt;&lt;font style="font-size: 9px; color: #ffffff;"&gt;Layer 7 Inspection&lt;/font&gt;`,
    style: 'shape=mxgraph.aws4.waf;fillColor=#DC2626;strokeColor=#991B1B;fontColor=#ffffff;rounded=1;align=center;fontSize=11;fontFamily=Helvetica;',
    vertex: true,
    parent: '1',
    x: 210,
    y: 220,
    width: 120,
    height: 70,
  });

  // Track created nodes and their positions
  const nodeCellMap = new Map<string, string>();
  let computeY = 160;
  let datastoreY = 170;
  let internetY = 220;

  nodes.forEach((node) => {
    const l = (node.label || '').toLowerCase();
    const isInternet = node.kind === 'internet' || l.includes('internet') || l.includes('client') || l.includes('user') || l.includes('wan');
    const isDatastore = node.kind === 'target' || node.category === 'target' || l.includes('db') || l.includes('database') || l.includes('sql') || l.includes('rds') || l.includes('mongo');
    const isStorage = l.includes('s3') || l.includes('bucket') || l.includes('storage') || l.includes('blob');
    const isLB = l.includes('alb') || l.includes('load balancer') || l.includes('ingress') || l.includes('proxy');

    if (isInternet) {
      const cellId = `node-${node.id}`;
      nodeCellMap.set(node.id, cellId);
      cells.push({
        id: cellId,
        value: `&lt;b&gt;${node.label}&lt;/b&gt;&lt;br&gt;&lt;font style="font-size: 9px; color: #cccccc;"&gt;External Traffic&lt;/font&gt;`,
        style: 'shape=mxgraph.aws4.client;fillColor=#1F2937;strokeColor=#111827;fontColor=#ffffff;rounded=1;align=center;fontSize=11;fontFamily=Helvetica;',
        vertex: true,
        parent: '1',
        x: 50,
        y: internetY,
        width: 110,
        height: 70,
      });
      internetY += 100;
    } else if (isDatastore || isStorage) {
      // Place inside the Private Subnet container
      const cellId = `node-${node.id}`;
      nodeCellMap.set(node.id, cellId);
      const isSecured = hasDbExposure || hasStorageExposure;
      const badge = isSecured ? '&lt;b&gt;[✓ SECURED]&lt;/b&gt;&lt;br&gt;' : '';
      const subtitle = isDatastore ? 'Private RDS / DB' : 'Encrypted S3 (Block Public)';

      cells.push({
        id: cellId,
        value: `${badge}&lt;b&gt;${node.label}&lt;/b&gt;&lt;br&gt;&lt;font style="font-size: 9px; color: #ffffff;"&gt;${subtitle}&lt;/font&gt;`,
        style: isDatastore
          ? 'shape=mxgraph.aws4.database;fillColor=#2563EB;strokeColor=#1D4ED8;fontColor=#ffffff;rounded=1;align=center;fontSize=11;fontFamily=Helvetica;'
          : 'shape=mxgraph.aws4.bucket_with_objects;fillColor=#059669;strokeColor=#047857;fontColor=#ffffff;rounded=1;align=center;fontSize=11;fontFamily=Helvetica;',
        vertex: true,
        parent: '1',
        x: 750,
        y: datastoreY,
        width: 190,
        height: 65,
      });
      datastoreY += 95;
    } else if (isLB) {
      const cellId = `node-${node.id}`;
      nodeCellMap.set(node.id, cellId);
      cells.push({
        id: cellId,
        value: `&lt;b&gt;${node.label}&lt;/b&gt;&lt;br&gt;&lt;font style="font-size: 9px; color: #ffffff;"&gt;TLS Ingress ALB&lt;/font&gt;`,
        style: 'shape=mxgraph.aws4.application_load_balancer;fillColor=#7C3AED;strokeColor=#6D28D9;fontColor=#ffffff;rounded=1;align=center;fontSize=11;fontFamily=Helvetica;',
        vertex: true,
        parent: '1',
        x: 380,
        y: 220,
        width: 130,
        height: 70,
      });
    } else {
      // Compute / App tier
      const cellId = `node-${node.id}`;
      nodeCellMap.set(node.id, cellId);
      cells.push({
        id: cellId,
        value: `&lt;b&gt;${node.label}&lt;/b&gt;&lt;br&gt;&lt;font style="font-size: 9px; color: #ffffff;"&gt;App Workload (Private)&lt;/font&gt;`,
        style: 'shape=mxgraph.aws4.compute;fillColor=#D97706;strokeColor=#B45309;fontColor=#ffffff;rounded=1;align=center;fontSize=11;fontFamily=Helvetica;',
        vertex: true,
        parent: '1',
        x: 550,
        y: computeY,
        width: 130,
        height: 70,
      });
      computeY += 95;
    }
  });

  // Now create secure edges
  // 1. Connect Internet -> WAF
  const internetNode = nodes.find(n => n.kind === 'internet' || (n.label || '').toLowerCase().includes('internet') || (n.label || '').toLowerCase().includes('client'));
  const internetCellId = internetNode ? nodeCellMap.get(internetNode.id) : null;
  if (internetCellId) {
    cells.push({
      id: `edge-${nextId++}`,
      value: 'HTTPS / 443 (Inspected)',
      style: 'edgeStyle=orthogonalEdgeStyle;rounded=1;strokeColor=#DC2626;strokeWidth=2;fontSize=9;fontColor=#B91C1C;',
      edge: true,
      source: internetCellId,
      target: wafNodeId,
      parent: '1',
    });
  }

  // 2. Connect WAF -> ALB or First Compute Node
  const albNode = nodes.find(n => (n.label || '').toLowerCase().includes('alb') || (n.label || '').toLowerCase().includes('load') || (n.label || '').toLowerCase().includes('ingress'));
  const albCellId = albNode ? nodeCellMap.get(albNode.id) : null;
  const firstComputeNode = nodes.find(n => n.kind === 'server' || n.kind === 'service' || (!nodeCellMap.get(n.id)?.includes('client') && !nodeCellMap.get(n.id)?.includes('db')));
  const targetAfterWaf = albCellId || (firstComputeNode ? nodeCellMap.get(firstComputeNode.id) : null);

  if (targetAfterWaf && targetAfterWaf !== wafNodeId) {
    cells.push({
      id: `edge-${nextId++}`,
      value: 'Filtered Ingress',
      style: 'edgeStyle=orthogonalEdgeStyle;rounded=1;strokeColor=#16A34A;strokeWidth=2;fontSize=9;fontColor=#15803D;',
      edge: true,
      source: wafNodeId,
      target: targetAfterWaf,
      parent: '1',
    });
  }

  // 3. Connect existing app-to-app and app-to-db edges
  edges.forEach((edge) => {
    const sId = nodeCellMap.get(edge.source);
    const tId = nodeCellMap.get(edge.target);

    // If original edge connected Internet directly to Database or Storage, REMOVE IT!
    const sourceNode = nodes.find(n => n.id === edge.source);
    const targetNode = nodes.find(n => n.id === edge.target);

    const isDirectInternetToDb =
      (sourceNode?.kind === 'internet' || (sourceNode?.label || '').toLowerCase().includes('internet')) &&
      ((targetNode?.label || '').toLowerCase().includes('db') || (targetNode?.label || '').toLowerCase().includes('rds') || (targetNode?.label || '').toLowerCase().includes('sql'));

    if (isDirectInternetToDb) {
      // Intentionally suppressed! Remediated by routing through WAF & App tier.
      return;
    }

    if (sId && tId && sId !== tId) {
      cells.push({
        id: `edge-${nextId++}`,
        value: edge.label || 'VPC Route (mTLS)',
        style: 'edgeStyle=orthogonalEdgeStyle;rounded=1;strokeColor=#4B5563;strokeWidth=1.5;fontSize=9;fontColor=#4B5563;',
        edge: true,
        source: sId,
        target: tId,
        parent: '1',
      });
    }
  });

  // 4. Ensure Compute connects to Database
  const dbNode = nodes.find(n => (n.label || '').toLowerCase().includes('db') || (n.label || '').toLowerCase().includes('rds') || (n.label || '').toLowerCase().includes('sql') || (n.label || '').toLowerCase().includes('mongo'));
  if (dbNode && firstComputeNode) {
    const sId = nodeCellMap.get(firstComputeNode.id);
    const tId = nodeCellMap.get(dbNode.id);
    const alreadyConnected = cells.some(c => c.edge && c.source === sId && c.target === tId);

    if (sId && tId && !alreadyConnected) {
      cells.push({
        id: `edge-${nextId++}`,
        value: 'Internal SQL / 5432 (Isolated)',
        style: 'edgeStyle=orthogonalEdgeStyle;rounded=1;strokeColor=#2563EB;strokeWidth=2;fontSize=9;fontColor=#1D4ED8;',
        edge: true,
        source: sId,
        target: tId,
        parent: '1',
      });
    }
  }

  // XML serialization
  const cellXmlList = cells.map(c => {
    if (c.edge) {
      return `        &lt;mxCell id="${c.id}" value="${c.value}" style="${c.style}" edge="1" parent="${c.parent || '1'}" source="${c.source}" target="${c.target}"&gt;
          &lt;mxGeometry relative="1" as="geometry"/&gt;
        &lt;/mxCell&gt;`
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>');
    }

    if (c.id === '0' || c.id === '1') {
      return `        <mxCell id="${c.id}"${c.parent ? ` parent="${c.parent}"` : ''}/>`;
    }

    return `        &lt;mxCell id="${c.id}" value="${c.value}" style="${c.style}" vertex="1" parent="${c.parent || '1'}"&gt;
          &lt;mxGeometry x="${c.x || 0}" y="${c.y || 0}" width="${c.width || 120}" height="${c.height || 60}" as="geometry"/&gt;
        &lt;/mxCell&gt;`
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>');
  }).join('\n');

  return `&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;mxfile host="Traceveil-Security-Studio" modified="${new Date().toISOString()}" agent="Traceveil Security Copilot" version="21.0.0" type="device"&gt;
  &lt;diagram id="traceveil-hardened" name="Hardened Architecture"&gt;
    &lt;mxGraphModel dx="1420" dy="880" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1200" pageHeight="800" background="#FFFFFF"&gt;
      &lt;root&gt;
${cellXmlList}
      &lt;/root&gt;
    &lt;/mxGraphModel&gt;
  &lt;/diagram&gt;
&lt;/mxfile&gt;`
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

/**
 * Architectural visual comparison details for each security finding
 */
export interface ArchitecturalRemediationGuide {
  findingTitle: string;
  flawSummary: string;
  beforeTopology: {
    title: string;
    description: string;
    nodes: string[];
    riskCallout: string;
  };
  afterTopology: {
    title: string;
    description: string;
    nodes: string[];
    benefitCallout: string;
  };
  drawIoSteps: string[];
}

export function getArchitecturalRemediationGuide(rule: string, componentLabel: string): ArchitecturalRemediationGuide {
  switch (rule) {
    case 'public-database-exposure':
    case 'database-exposure':
      return {
        findingTitle: `Public Database Exposure (${componentLabel})`,
        flawSummary: `The database '${componentLabel}' is directly accessible from the public Internet perimeter (0.0.0.0/0) without private subnet isolation.`,
        beforeTopology: {
          title: 'Flawed Architecture in Current Diagram',
          description: 'Direct internet ingress line into database instance',
          nodes: ['Public Internet / WAN', 'Direct Public Route (0.0.0.0/0)', `${componentLabel} (Exposed Public IP)`],
          riskCallout: 'Attacker can port-scan, credential-stuff, or exploit database zero-days directly from the public web.',
        },
        afterTopology: {
          title: 'Corrected Zero-Trust Architecture',
          description: 'Database moved inside isolated Private Subnet with no Internet Gateway route',
          nodes: ['Public Internet', 'Cloud WAF / ALB', 'Backend App Service', `[Private Subnet (10.0.2.0/24)] ${componentLabel}`],
          benefitCallout: 'Database has no public IP. Ingress is strictly locked to backend application Security Group on internal port.',
        },
        drawIoSteps: [
          `In draw.io, delete the direct connection line between the Internet/WAN node and '${componentLabel}'.`,
          'Draw a container/swimlane box labeled "Private Database Subnet (10.0.2.0/24)" with green border (#16A34A).',
          `Move the '${componentLabel}' database shape inside the new Private Subnet container.`,
          `Draw a directed arrow from the Backend Application Service to '${componentLabel}' labeled "TCP 5432 / mTLS".`,
          'Ensure no routing table arrow connects the Internet Gateway to this private subnet container.',
        ],
      };

    case 'public-storage-exposure':
      return {
        findingTitle: `Public Object Storage Exposure (${componentLabel})`,
        flawSummary: `Object storage bucket '${componentLabel}' permits unauthenticated anonymous read/write operations from public IP ranges.`,
        beforeTopology: {
          title: 'Flawed Architecture in Current Diagram',
          description: 'Direct unauthenticated public edge connected to bucket',
          nodes: ['Anonymous Internet User', 'Unrestricted Bucket ACL', `${componentLabel} (Public Reads Allowed)`],
          riskCallout: 'Data leakage of confidential documents, invoices, or customer backups.',
        },
        afterTopology: {
          title: 'Corrected Zero-Trust Architecture',
          description: 'S3 Public Access Block enabled with KMS encryption at rest',
          nodes: ['Internal Compute Service', 'VPC Gateway Endpoint', `[Private Encrypted Bucket] ${componentLabel}`],
          benefitCallout: 'Bucket blocks all public ACLs and requires IAM role authentication via internal VPC endpoint.',
        },
        drawIoSteps: [
          `Select '${componentLabel}' in draw.io and change its label to "[✓ SECURED] ${componentLabel} (Block Public Access)".`,
          'Change the shape fill color to green (#059669) to indicate private enforcement.',
          'Delete any connection line coming directly from the Internet/WAN node.',
          `Connect only authorized backend services to '${componentLabel}' via an internal VPC Gateway Endpoint.`,
        ],
      };

    case 'missing-waf':
      return {
        findingTitle: 'Missing Web Application Firewall (WAF) / Perimeter Shield',
        flawSummary: 'External internet ingress reaches load balancers and services without Layer 7 inspection.',
        beforeTopology: {
          title: 'Flawed Architecture in Current Diagram',
          description: 'Unfiltered public requests flow straight into application load balancers',
          nodes: ['Public Internet Users', 'Uninspected Edge Traffic', 'Application Load Balancer'],
          riskCallout: 'Vulnerable to SQLi, XSS, rate-limiting bypass, and automated DDoS attacks.',
        },
        afterTopology: {
          title: 'Corrected Zero-Trust Architecture',
          description: 'AWS WAF / Cloud Armor positioned between Internet and Load Balancer',
          nodes: ['Public Internet', 'AWS WAF / Shield (L7 Rules)', 'Application Load Balancer', 'Backend Workloads'],
          benefitCallout: 'Inspects HTTP payloads, blocks OWASP Top 10 exploits, and filters bot traffic before hitting compute.',
        },
        drawIoSteps: [
          'Add a new shape from the AWS / Security library: "AWS WAF / Perimeter Shield".',
          'Position the WAF shape between the Internet node and the Application Load Balancer.',
          'Reroute the Internet connection line to enter the WAF first.',
          'Draw an arrow from the WAF to the Application Load Balancer labeled "Inspected & Filtered Ingress".',
        ],
      };

    case 'flat-network-architecture':
    case 'permissive-cisco-acl':
      return {
        findingTitle: `Unsegmented Flat Network (${componentLabel})`,
        flawSummary: `Network device '${componentLabel}' bridges external untrusted traffic and internal core subnets without VLAN or ACL isolation.`,
        beforeTopology: {
          title: 'Flawed Architecture in Current Diagram',
          description: 'Flat single subnet routing external and internal traffic through same switch/router',
          nodes: ['External WAN', `${componentLabel} (Permissive Ingress)`, 'Core Internal Database / Storage'],
          riskCallout: 'Any breach of edge device allows immediate lateral traversal to core internal crown jewels.',
        },
        afterTopology: {
          title: 'Corrected Zero-Trust Architecture',
          description: 'VLAN segmentation with DMZ, Ingress ACL, and stateful firewall inspection',
          nodes: ['External WAN', 'VLAN 10 (DMZ)', 'Next-Gen Firewall / Ingress ACL', 'VLAN 20 (Core DB Subnet)'],
          benefitCallout: 'Enforces strict Layer 3/4 boundary controls between untrusted ingress and protected assets.',
        },
        drawIoSteps: [
          `On '${componentLabel}', add a dedicated DMZ VLAN (VLAN 10) for edge-facing services.`,
          'Create a separate internal VLAN (VLAN 20) for databases and sensitive backend compute.',
          'Place a firewall or router ACL between VLAN 10 and VLAN 20.',
          'Block all inbound connection requests originating from external networks to VLAN 20.',
        ],
      };

    default:
      return {
        findingTitle: `Architectural Hardening Recommendation (${componentLabel})`,
        flawSummary: `Component '${componentLabel}' requires perimeter segmentation and zero-trust policy enforcement.`,
        beforeTopology: {
          title: 'Flawed Architecture in Current Diagram',
          description: 'Unscoped access path or missing isolation boundary',
          nodes: ['Untrusted Caller', 'Unbounded Route', componentLabel],
          riskCallout: 'Unauthorized access or privilege escalation across shared network path.',
        },
        afterTopology: {
          title: 'Corrected Zero-Trust Architecture',
          description: 'Isolated private tier with authentication and policy scoping',
          nodes: ['Authenticated Service', 'Least-Privilege Security Group', `[Secured] ${componentLabel}`],
          benefitCallout: 'Conforms to defense-in-depth and least-privilege architectural baselines.',
        },
        drawIoSteps: [
          `In draw.io, verify that '${componentLabel}' is situated inside a private subnet boundary container.`,
          'Restrict inbound edge links to only explicit authorized upstream caller components.',
          'Add an encryption/TLS annotation to indicate encrypted in-transit traffic.',
        ],
      };
  }
}
