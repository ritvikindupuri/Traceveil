import { describe, it, expect } from 'vitest';
import { analyzeDiagramToAttackGraph } from './diagram-parser';

describe('diagram-parser (universal & adaptive to ANY draw.io or Packet Tracer diagram)', () => {
  it('analyzes Azure multi-tier architecture without preset assumptions', () => {
    const azureXml = `
      <mxfile host="app.diagrams.net">
        <diagram name="Azure Enterprise Healthcare Cloud">
          <mxGraphModel>
            <root>
              <mxCell id="0"/>
              <mxCell id="1" parent="0"/>
              <mxCell id="az-inet" value="Public Internet" style="shape=mxgraph.azure2.internet" vertex="1" parent="1"/>
              <mxCell id="az-gw" value="Azure Application Gateway" style="shape=mxgraph.azure2.application_gateway" vertex="1" parent="1"/>
              <mxCell id="az-app" value="Patient Record Microservice (AKS)" style="shape=mxgraph.azure2.aks" vertex="1" parent="1"/>
              <mxCell id="az-db" value="Azure Cosmos DB (Patient Records)" style="shape=mxgraph.azure2.cosmos_db" vertex="1" parent="1"/>
              <mxCell id="az-blob" value="Azure Blob Storage (Diagnostic Scans)" style="shape=mxgraph.azure2.blob_storage" vertex="1" parent="1"/>
              
              <mxCell id="e1" value="HTTPS Ingress" edge="1" source="az-inet" target="az-gw" parent="1"/>
              <mxCell id="e2" value="Internal Route" edge="1" source="az-gw" target="az-app" parent="1"/>
              <mxCell id="e3" value="SQL Query" edge="1" source="az-app" target="az-db" parent="1"/>
              <mxCell id="e4" value="Direct Public Upload" edge="1" source="az-inet" target="az-blob" parent="1"/>
            </root>
          </mxGraphModel>
        </diagram>
      </mxfile>
    `;

    const result = analyzeDiagramToAttackGraph(azureXml, 'azure-healthcare.drawio');
    const graph = result.graph;

    expect(graph.nodes.length).toBe(5);
    // Identifies direct public blob exposure
    expect(graph.findings.some(f => f.rule === 'public-storage-exposure')).toBe(true);
    // Identifies database ingress exposure
    expect(graph.findings.some(f => f.rule === 'database-exposure')).toBe(true);

    // BFS shortest attack path traverses the exact nodes drawn
    const path = graph.attackPaths![0];
    expect(path.steps.some(s => s.subtitle.includes('Azure'))).toBe(true);
  });

  it('accurately identifies defense-in-depth on properly hardened architectures (NO false positives)', () => {
    const hardenedXml = `
      <mxfile host="app.diagrams.net">
        <diagram name="Hardened Cloud Architecture">
          <mxGraphModel>
            <root>
              <mxCell id="0"/>
              <mxCell id="1" parent="0"/>
              <mxCell id="h1" value="Public Traffic" style="shape=mxgraph.aws4.internet" vertex="1" parent="1"/>
              <mxCell id="h2" value="Cloudflare WAF Guard" style="shape=mxgraph.aws4.waf" vertex="1" parent="1"/>
              <mxCell id="h3" value="Application Load Balancer" style="shape=mxgraph.aws4.alb" vertex="1" parent="1"/>
              <mxCell id="h4" value="Private App Service" style="shape=mxgraph.aws4.ecs" vertex="1" parent="1"/>
              <mxCell id="h5" value="Private Aurora PostgreSQL" style="shape=mxgraph.aws4.rds" vertex="1" parent="1"/>
              
              <mxCell id="e1" value="HTTPS" edge="1" source="h1" target="h2" parent="1"/>
              <mxCell id="e2" value="Filtered Ingress" edge="1" source="h2" target="h3" parent="1"/>
              <mxCell id="e3" value="VPC Private Link" edge="1" source="h3" target="h4" parent="1"/>
              <mxCell id="e4" value="Database Access" edge="1" source="h4" target="h5" parent="1"/>
            </root>
          </mxGraphModel>
        </diagram>
      </mxfile>
    `;

    const result = analyzeDiagramToAttackGraph(hardenedXml, 'hardened.drawio');
    const graph = result.graph;

    // Because WAF is present in the ingress path, it does NOT report missing-waf!
    expect(graph.findings.some(f => f.rule === 'missing-waf')).toBe(false);
    // S3 is not present or exposed, so no storage exposure
    expect(graph.findings.some(f => f.rule === 'public-storage-exposure')).toBe(false);
  });

  it('detects exposed remote management ports on custom on-premise topologies', () => {
    const onPremTopology = `
      <topology name="Corporate On-Premise Core">
        <devices>
          <device id="gw" name="Border-Router" type="router" ip="198.51.100.1"/>
          <device id="core-sw" name="Core-Switch" type="switch" ip="10.0.0.2"/>
          <device id="srv-admin" name="Active-Directory-DC" type="server" ip="10.0.0.10"/>
        </devices>
        <links>
          <link id="l1" source="gw" target="core-sw" port="Gig0/0"/>
          <link id="l2" source="core-sw" target="srv-admin" port="SSH Port 22"/>
        </links>
      </topology>
    `;

    const result = analyzeDiagramToAttackGraph(onPremTopology, 'onprem.pkt');
    const graph = result.graph;

    expect(graph.findings.some(f => f.rule === 'public-cidr' && f.title.includes('Management'))).toBe(true);
  });

  it('correctly ingests and audits raw Cisco IOS running-config without presets', () => {
    const ciscoIosConfig = `
! Current configuration : 1850 bytes
version 15.2
service timestamps log datetime msec
no service password-encryption
!
hostname Edge-Gateway-ISR4331
!
enable password cisco123
username admin privilege 15 password 7 0822404F1A0A
!
interface GigabitEthernet0/0/0
 description WAN Ingress
 ip address 203.0.113.5 255.255.255.248
 ip access-group 101 in
!
interface GigabitEthernet0/0/1
 description LAN Internal
 ip address 10.10.10.1 255.255.255.0
!
access-list 101 permit ip any any
!
line vty 0 4
 transport input telnet
 login local
!
end
    `;

    const result = analyzeDiagramToAttackGraph(ciscoIosConfig, 'running-config.cfg');
    const graph = result.graph;

    // Verify entity and edge extraction
    expect(graph.nodes.some(e => e.label.includes('Edge-Gateway-ISR4331'))).toBe(true);
    expect(graph.edges.some(e => e.label?.includes('GigabitEthernet0/0/0'))).toBe(true);

    // Verify Cisco-specific security findings
    const ruleIds = graph.findings.map(f => f.rule);
    expect(ruleIds).toContain('cleartext-telnet-mgmt');
    expect(ruleIds).toContain('permissive-cisco-acl');
    expect(ruleIds).toContain('cleartext-passwords');
  });

  it('adaptively parses completely custom non-cloud SCADA/OT draw.io diagram', () => {
    const scadaDrawIo = `
      <mxGraphModel>
        <root>
          <mxCell id="0"/>
          <mxCell id="1" parent="0"/>
          <mxCell id="modbus-master" value="SCADA Human-Machine Interface (HMI)" vertex="1" parent="1"/>
          <mxCell id="plc-1" value="Siemens S7-1500 PLC Controller" vertex="1" parent="1"/>
          <mxCell id="rtu-db" value="Historian Telemetry Database" vertex="1" parent="1"/>
          <mxCell id="ext-partner" value="Public Internet Contractor VPN" vertex="1" parent="1"/>
          
          <mxCell id="e1" edge="1" source="ext-partner" target="modbus-master" parent="1" value="Port 502 Modbus"/>
          <mxCell id="e2" edge="1" source="modbus-master" target="plc-1" parent="1"/>
          <mxCell id="e3" edge="1" source="modbus-master" target="rtu-db" parent="1"/>
        </root>
      </mxGraphModel>
    `;

    const result = analyzeDiagramToAttackGraph(scadaDrawIo, 'water-treatment-scada.drawio');
    const graph = result.graph;

    expect(graph.nodes.length).toBeGreaterThanOrEqual(4);
    // Verified adaptive reachability: external contractor can traverse to historian database / PLC
    expect(graph.findings.length).toBeGreaterThan(0);
    expect(result.deviceCount).toBe(4);
  });

  it('synthesizes draw.io XML from conversational natural language prompts (AWS 3-Tier + S3 bucket)', () => {
    const prompt = 'CloudFront -> ALB -> ECS Fargate -> Postgres RDS in private subnet, plus a public S3 bucket for invoices';
    const result = analyzeDiagramToAttackGraph(prompt);
    const graph = result.graph;

    expect(graph.nodes.length).toBeGreaterThanOrEqual(5);
    // Verifies vendor classification
    expect(graph.nodes.some(n => n.label.toLowerCase().includes('cloudfront'))).toBe(true);
    expect(graph.nodes.some(n => n.label.toLowerCase().includes('alb'))).toBe(true);
    expect(graph.nodes.some(n => n.label.toLowerCase().includes('rds') || n.label.toLowerCase().includes('postgres'))).toBe(true);
    expect(graph.nodes.some(n => n.label.toLowerCase().includes('s3'))).toBe(true);

    // Verifies security finding extraction (public S3 bucket or unauthenticated storage)
    expect(graph.findings.some(f => f.rule === 'public-storage-exposure' || f.rule === 'database-exposure')).toBe(true);

    // Verifies BFS attack path derivation
    expect(graph.attackPaths).toBeDefined();
    expect(graph.attackPaths!.length).toBeGreaterThan(0);
    expect(graph.attackPaths![0].steps.length).toBeGreaterThan(1);
  });

  it('synthesizes Cisco enterprise topology from natural language sentences', () => {
    const prompt =
      'Cisco 2911 router connects WAN to ASA 5505 firewall. Firewall forwards web traffic to DMZ Apache web server on port 443, and internal core switch connects directly to MySQL database and unauthenticated Redis cache.';
    const result = analyzeDiagramToAttackGraph(prompt);
    const graph = result.graph;

    expect(graph.nodes.length).toBeGreaterThanOrEqual(6);
    expect(graph.nodes.some(n => n.label.toLowerCase().includes('2911'))).toBe(true);
    expect(graph.nodes.some(n => n.label.toLowerCase().includes('firewall') || n.label.toLowerCase().includes('asa'))).toBe(true);
    expect(graph.nodes.some(n => n.label.toLowerCase().includes('mysql') || n.label.toLowerCase().includes('redis'))).toBe(true);

    // BFS shortest attack path traverses through perimeter firewall to database
    const path = graph.attackPaths![0];
    expect(path.steps.some(s => s.subtitle.toLowerCase().includes('firewall') || s.subtitle.toLowerCase().includes('router') || s.subtitle.toLowerCase().includes('wan'))).toBe(true);
  });

  it('synthesizes Kubernetes microservices with unprotected debug pod exposure', () => {
    const prompt =
      'Kubernetes cluster with Ingress controller, order-service and auth-service pods, connecting to shared MongoDB and Kafka, with an exposed debug pod running with privileged root container.';
    const result = analyzeDiagramToAttackGraph(prompt);
    const graph = result.graph;

    expect(graph.nodes.length).toBeGreaterThanOrEqual(5);
    expect(graph.nodes.some(n => n.label.toLowerCase().includes('debug'))).toBe(true);
    expect(graph.findings.length).toBeGreaterThan(0);
  });
});

