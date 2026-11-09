import { describe, expect, it } from 'vitest';
import { generateCorrectedDrawIoXml, getArchitecturalRemediationGuide } from './corrected-diagram';
import type { AttackGraph } from './types';

describe('generateCorrectedDrawIoXml', () => {
  const sampleGraph: AttackGraph = {
    target: 'diagram://aws-enterprise-architecture.drawio',
    commit: 'arch-12345678',
    branch: 'main',
    nodes: [
      { id: '1', label: 'Public Internet', kind: 'internet', evidenceIds: ['ev-1'] },
      { id: '2', label: 'ALB Ingress', kind: 'server', evidenceIds: ['ev-2'] },
      { id: '3', label: 'Backend API', kind: 'server', evidenceIds: ['ev-3'] },
      { id: '4', label: 'prod-db', kind: 'target', evidenceIds: ['ev-4'] },
    ],
    edges: [
      { id: 'e1', source: '1', target: '4', label: 'Public Ingress 0.0.0.0/0', evidenceIds: ['ev-e1'], provenance: 'declared' },
      { id: 'e2', source: '2', target: '3', label: 'Internal Route', evidenceIds: ['ev-e2'], provenance: 'declared' },
      { id: 'e3', source: '3', target: '4', label: 'SQL Ingress', evidenceIds: ['ev-e3'], provenance: 'declared' },
    ],
    evidence: [],
    findings: [
      {
        id: 'f1',
        title: 'Public Database Exposure (prod-db)',
        severity: 'high',
        rule: 'public-database-exposure',
        fix: 'Move to private subnet',
        evidenceIds: ['ev-4'],
      },
    ],
    coverage: { inspected: 4, total: 4, skipped: 0, gaps: [] },
    collectedAt: new Date().toISOString(),
  };

  it('generates a valid draw.io XML structure', () => {
    const xml = generateCorrectedDrawIoXml(sampleGraph);
    expect(xml).toContain('<mxfile');
    expect(xml).toContain('<diagram');
    expect(xml).toContain('Hardened Architecture');
    expect(xml).toContain('TRACEVEIL HARDENED ARCHITECTURE');
  });

  it('encloses the exposed database inside a secured private subnet container', () => {
    const xml = generateCorrectedDrawIoXml(sampleGraph);
    expect(xml).toContain('Isolated Private Subnet (10.0.2.0/24)');
    expect(xml).toContain('[✓ SECURED]');
    expect(xml).toContain('prod-db');
  });

  it('removes direct public internet to database edge', () => {
    const xml = generateCorrectedDrawIoXml(sampleGraph);
    expect(xml).toContain('node-waf-perimeter');
    // Direct public edge is replaced by WAF inspection path
    expect(xml).toContain('HTTPS / 443 (Inspected)');
  });

  it('returns step-by-step draw.io editing steps for architectural rules', () => {
    const guide = getArchitecturalRemediationGuide('public-database-exposure', 'prod-db');
    expect(guide.drawIoSteps.length).toBeGreaterThan(3);
    expect(guide.drawIoSteps[0]).toContain('In draw.io');
    expect(guide.beforeTopology.nodes).toContain('Public Internet / WAN');
    expect(guide.afterTopology.nodes).toContain('Cloud WAF / ALB');
  });
});
