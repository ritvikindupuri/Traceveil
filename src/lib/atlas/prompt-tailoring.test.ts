import { describe, it, expect } from 'vitest';
import { generateTailoredIsolationPrompts, generateContextualFollowUpPrompts, getCleanTargetName } from './prompt-tailoring';
import type { AttackGraph } from './types';

describe('prompt-tailoring for actually scanned & validated findings', () => {
  it('generates prompts directly from REAL live scan findings (Cloudflare, CSP, HSTS)', () => {
    const target = 'https://cloudpilot-ai.codeworker.workers.dev';
    const mockGraph: Partial<AttackGraph> = {
      target,
      findings: [
        {
          id: 'finding-live-banner',
          rule: 'server-banner-leak',
          severity: 'medium',
          title: 'Server Banner & Routing Header Leakage (cloudflare)',
          fix: 'Suppress server header',
          evidenceIds: ['e1'],
        },
        {
          id: 'finding-live-csp',
          rule: 'missing-csp',
          severity: 'high',
          title: 'Missing Content-Security-Policy (CSP) Protection',
          fix: 'Add CSP',
          evidenceIds: ['e2'],
        },
        {
          id: 'finding-live-hsts',
          rule: 'missing-hsts',
          severity: 'high',
          title: 'Missing Strict-Transport-Security (HSTS) Header',
          fix: 'Add HSTS',
          evidenceIds: ['e3'],
        },
      ],
      nodes: [
        {
          id: 'live-app',
          label: 'Live Web Service',
          kind: 'compute',
          subtitle: 'TLS Web Server · cloudflare · Status 200',
          evidenceIds: ['e1'],
        },
      ],
    };

    const prompts = generateTailoredIsolationPrompts(target, mockGraph as AttackGraph);
    expect(prompts.length).toBe(4);
    // Directly addresses the real Cloudflare banner leak finding
    expect(prompts.some(p => p.toLowerCase().includes('cloudflare') || p.toLowerCase().includes('banner'))).toBe(true);
    // Directly addresses the real missing CSP finding
    expect(prompts.some(p => p.toLowerCase().includes('csp'))).toBe(true);
    // Directly addresses the real missing HSTS finding
    expect(prompts.some(p => p.toLowerCase().includes('hsts'))).toBe(true);
    // Always provides a verification probe
    expect(prompts.some(p => p.toLowerCase().includes('probes'))).toBe(true);
  });

  it('generates prompts from real GitHub repository scan findings', () => {
    const target = 'https://github.com/ritvikindupuri/Cloudpilot';
    const mockGraph: Partial<AttackGraph> = {
      target,
      findings: [
        {
          id: 'f1',
          rule: 'public-cidr',
          title: 'Unrestricted Ingress (0.0.0.0/0)',
          severity: 'high',
          fix: 'Restrict CIDR',
          evidenceIds: ['e1'],
        },
        {
          id: 'f2',
          rule: 'secret-in-code',
          title: 'Hardcoded Secret',
          severity: 'high',
          fix: 'Remove secret',
          evidenceIds: ['e2'],
        },
      ],
      nodes: [],
    };

    const prompts = generateTailoredIsolationPrompts(target, mockGraph as AttackGraph);
    expect(prompts.some(p => p.toLowerCase().includes('cidr') || p.toLowerCase().includes('ingress'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('secret') || p.toLowerCase().includes('credentials'))).toBe(true);
  });

  it('generates pre-scan prompts directing user to actually scan and validate', () => {
    const target = 'https://api.acme-corp.io/v1';
    const prompts = generateTailoredIsolationPrompts(target, null);
    expect(prompts.some(p => p.toLowerCase().includes('scan'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('probes'))).toBe(true);
  });

  it('generates contextual follow-up prompts for any live web app', () => {
    const followUps = generateContextualFollowUpPrompts('https://api.acme-corp.io', 'Can we verify RLS?');
    expect(followUps.length).toBeGreaterThan(0);
    expect(followUps.some(f => f.toLowerCase().includes('database') || f.toLowerCase().includes('migration'))).toBe(true);
  });
});
