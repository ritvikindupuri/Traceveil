import { describe, it, expect } from 'vitest';
import { generateTailoredIsolationPrompts, generateContextualFollowUpPrompts, getCleanTargetName } from './prompt-tailoring';
import type { AttackGraph } from './types';

describe('Universal evidence-driven prompt tailoring for ANY web app or repo', () => {
  it('generates prompts directly from live scan findings on any custom web app (e.g. Stripe, Nginx, Clickjacking)', () => {
    const target = 'https://api.stripe.com';
    const mockGraph: Partial<AttackGraph> = {
      target,
      findings: [
        {
          id: 'f-banner',
          rule: 'server-banner-leak',
          severity: 'medium',
          title: 'Server Banner & Routing Header Leakage (nginx)',
          fix: 'Suppress server header',
          evidenceIds: ['e1'],
        },
        {
          id: 'f-frame',
          rule: 'missing-frame-options',
          severity: 'medium',
          title: 'Missing Anti-Clickjacking Protection',
          fix: 'Add X-Frame-Options',
          evidenceIds: ['e2'],
        },
      ],
      nodes: [
        {
          id: 'live-app',
          label: 'Live Web Service',
          kind: 'compute',
          subtitle: 'TLS Web Server · nginx · Status 200',
          evidenceIds: ['e1'],
        },
      ],
    };

    const prompts = generateTailoredIsolationPrompts(target, mockGraph as AttackGraph);
    expect(prompts.length).toBe(3);
    expect(prompts.some(p => p.toLowerCase().includes('nginx') || p.toLowerCase().includes('banner'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('clickjacking') || p.toLowerCase().includes('frame'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('probes'))).toBe(true);
  });

  it('generates prompts from exposed secret findings on any healthcare or internal live domain', () => {
    const target = 'https://portal.my-hospital.org';
    const mockGraph: Partial<AttackGraph> = {
      target,
      findings: [
        {
          id: 'f-env',
          rule: 'exposed-env',
          severity: 'high',
          title: 'Publicly Exposed Environment Variables (.env)',
          fix: 'Block .env',
          evidenceIds: ['e1'],
        },
      ],
      nodes: [],
    };

    const prompts = generateTailoredIsolationPrompts(target, mockGraph as AttackGraph);
    expect(prompts.some(p => p.toLowerCase().includes('.env') || p.toLowerCase().includes('secrets'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('probes'))).toBe(true);
  });

  it('generates prompts for ANY GitHub repository based on its inspected findings', () => {
    const target = 'https://github.com/facebook/react';
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
          rule: 'missing-auth',
          title: 'Unauthenticated API Route',
          severity: 'high',
          fix: 'Add auth',
          evidenceIds: ['e2'],
        },
      ],
      nodes: [],
    };

    const prompts = generateTailoredIsolationPrompts(target, mockGraph as AttackGraph);
    expect(prompts.some(p => p.toLowerCase().includes('cidr') || p.toLowerCase().includes('ingress'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('tenant_id authentication') || p.toLowerCase().includes('unprotected'))).toBe(true);
  });

  it('generates zero-trust prompts when ANY web app or repo is clean with zero vulnerabilities', () => {
    const target = 'https://clean-hardened-app.com';
    const mockGraph: Partial<AttackGraph> = {
      target,
      findings: [],
      nodes: [
        {
          id: 'live-app',
          label: 'Live Web Service',
          kind: 'compute',
          evidenceIds: ['e1'],
        },
      ],
    };

    const prompts = generateTailoredIsolationPrompts(target, mockGraph as AttackGraph);
    expect(prompts.length).toBe(4);
    expect(prompts.some(p => p.toLowerCase().includes('probes'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('rls'))).toBe(true);
  });

  it('generates pre-scan prompts directing user to run real probes on any entered URL before scanning', () => {
    const target = 'https://arbitrary-startup.io';
    const prompts = generateTailoredIsolationPrompts(target, null);
    expect(prompts.some(p => p.toLowerCase().includes('scan'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('probes'))).toBe(true);
  });

  it('generates contextual follow-up prompts for any live web app or repo', () => {
    const followUps = generateContextualFollowUpPrompts('https://arbitrary-startup.io', 'Can we verify RLS?');
    expect(followUps.length).toBeGreaterThan(0);
    expect(followUps.some(f => f.toLowerCase().includes('database') || f.toLowerCase().includes('migration'))).toBe(true);
  });
});
