import { describe, it, expect } from 'vitest';
import { analyzeDiagramToAttackGraph, parseDrawIoXml, parsePacketTracerTopology } from './diagram-parser';

describe('diagram-parser (draw.io & Packet Tracer architecture parsing)', () => {
  it('parses real draw.io XML architecture diagram with AWS Cloud and Database', () => {
    const drawIoXml = `
      <mxfile host="app.diagrams.net">
        <diagram name="AWS Production Cloud Architecture" id="d1">
          <mxGraphModel>
            <root>
              <mxCell id="0"/>
              <mxCell id="1" parent="0"/>
              <mxCell id="2" value="Public Internet" style="shape=mxgraph.aws4.internet" vertex="1" parent="1"/>
              <mxCell id="3" value="Cloud API Gateway" style="shape=mxgraph.aws4.api_gateway" vertex="1" parent="1"/>
              <mxCell id="4" value="Orders Microservice (ECS)" style="shape=mxgraph.aws4.ecs" vertex="1" parent="1"/>
              <mxCell id="5" value="PostgreSQL Production Database" style="shape=mxgraph.aws4.rds" vertex="1" parent="1"/>
              <mxCell id="6" value="S3 Customer Documents Bucket" style="shape=mxgraph.aws4.s3" vertex="1" parent="1"/>
              
              <mxCell id="e1" value="HTTPS Inbound" edge="1" source="2" target="3" parent="1"/>
              <mxCell id="e2" value="gRPC Route" edge="1" source="3" target="4" parent="1"/>
              <mxCell id="e3" value="SQL Query" edge="1" source="4" target="5" parent="1"/>
              <mxCell id="e4" value="Direct Public Fetch" edge="1" source="2" target="6" parent="1"/>
            </root>
          </mxGraphModel>
        </diagram>
      </mxfile>
    `;

    const result = analyzeDiagramToAttackGraph(drawIoXml, 'aws-production.drawio');
    expect(result.diagramType).toBe('drawio');
    expect(result.deviceCount).toBe(5);
    expect(result.connectionCount).toBe(4);

    const graph = result.graph;
    expect(graph.target).toContain('aws-production');
    expect(graph.nodes.some(n => n.label.includes('Internet'))).toBe(true);
    expect(graph.nodes.some(n => n.label.includes('PostgreSQL'))).toBe(true);
    expect(graph.nodes.some(n => n.label.includes('S3'))).toBe(true);

    // Architectural Findings verified
    expect(graph.findings.some(f => f.rule === 'public-storage-exposure')).toBe(true);
    expect(graph.findings.some(f => f.rule === 'database-exposure')).toBe(true);
    expect(graph.findings.some(f => f.rule === 'missing-waf')).toBe(true);

    // Attack path generated
    expect(graph.attackPaths && graph.attackPaths.length > 0).toBe(true);
    const path = graph.attackPaths![0];
    expect(path.steps.length).toBeGreaterThanOrEqual(3);
  });

  it('parses Cisco Packet Tracer network topology with Router, Switch, and DMZ', () => {
    const ptTopology = `
      <topology name="Enterprise Cisco DMZ Network">
        <devices>
          <device id="r1" name="Edge-Router-2911" type="router" ip="203.0.113.1"/>
          <device id="sw1" name="Core-Switch-2960" type="switch" ip="192.168.1.2"/>
          <device id="dmz-srv" name="DMZ-Web-Server" type="server" ip="192.168.2.10"/>
          <device id="db-srv" name="Internal-Finance-DB" type="database" ip="10.0.1.50"/>
        </devices>
        <links>
          <link id="l1" source="r1" target="sw1" interface="Gig0/0"/>
          <link id="l2" source="sw1" target="dmz-srv" interface="Fa0/1"/>
          <link id="l3" source="sw1" target="db-srv" interface="Fa0/2"/>
        </links>
      </topology>
    `;

    const result = analyzeDiagramToAttackGraph(ptTopology, 'enterprise-network.pkt');
    expect(result.diagramType).toBe('packet_tracer');
    expect(result.deviceCount).toBeGreaterThanOrEqual(4);

    const graph = result.graph;
    expect(graph.nodes.some(n => n.label.includes('Router'))).toBe(true);
    expect(graph.findings.some(f => f.rule === 'flat-network-architecture')).toBe(true);
    expect(graph.findings.some(f => f.rule === 'database-exposure')).toBe(true);
  });

  it('parses simplified text topology fallback gracefully', () => {
    const fallbackText = `
      Public Internet -> Ingress Gateway
      Ingress Gateway -> Auth Service
      Auth Service -> User Database (PostgreSQL)
    `;

    const result = analyzeDiagramToAttackGraph(fallbackText, 'quick-diagram.txt');
    expect(result.deviceCount).toBe(4);
    expect(result.connectionCount).toBe(3);
    expect(result.graph.findings.some(f => f.rule === 'database-exposure')).toBe(true);
  });
});
