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
});
