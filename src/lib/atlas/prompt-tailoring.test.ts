import { describe, it, expect } from 'vitest';
import { generateTailoredIsolationPrompts, generateContextualFollowUpPrompts, getCleanTargetName } from './prompt-tailoring';
import type { AttackGraph } from './types';

describe('prompt-tailoring for all live web apps and codebases', () => {
  it('tailors prompts for any custom enterprise live domain', () => {
    const target = 'https://api.acme-corp.io/v1';
    const info = getCleanTargetName(target);
    expect(info.isLive).toBe(true);
    expect(info.name).toBe('Api');

    const prompts = generateTailoredIsolationPrompts(target);
    expect(prompts.length).toBe(4);
    expect(prompts.some(p => p.includes('Api'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('tenant isolation') || p.toLowerCase().includes('bola'))).toBe(true);
  });

  it('tailors prompts for live fintech & banking web applications', () => {
    const target = 'https://vault-banking.fintech-ledger.net';
    const prompts = generateTailoredIsolationPrompts(target);
    expect(prompts.some(p => p.toLowerCase().includes('transaction') || p.toLowerCase().includes('financial'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('transfer') || p.toLowerCase().includes('idor'))).toBe(true);
  });

  it('tailors prompts for live healthcare & patient web applications', () => {
    const target = 'https://patient-records.healthclinic.org';
    const prompts = generateTailoredIsolationPrompts(target);
    expect(prompts.some(p => p.toLowerCase().includes('hipaa') || p.toLowerCase().includes('patient'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('phi'))).toBe(true);
  });

  it('tailors prompts for live e-commerce & retail web applications', () => {
    const target = 'https://checkout-cart.my-store.shop';
    const prompts = generateTailoredIsolationPrompts(target);
    expect(prompts.some(p => p.toLowerCase().includes('billing') || p.toLowerCase().includes('order'))).toBe(true);
  });

  it('tailors prompts for Vercel, Fly.io, AWS, and Cloudflare live web apps', () => {
    const vercelTarget = 'https://my-saas-dashboard.vercel.app';
    const vercelPrompts = generateTailoredIsolationPrompts(vercelTarget);
    expect(vercelPrompts.some(p => p.includes('Vercel'))).toBe(true);

    const flyTarget = 'https://auth-service.fly.dev';
    const flyPrompts = generateTailoredIsolationPrompts(flyTarget);
    expect(flyPrompts.some(p => p.includes('Fly.io') || p.toLowerCase().includes('jwt'))).toBe(true);

    const cfTarget = 'https://cloudpilot-ai.codeworker.workers.dev';
    const cfPrompts = generateTailoredIsolationPrompts(cfTarget);
    expect(cfPrompts.some(p => p.toLowerCase().includes('cloudflare workers'))).toBe(true);
  });

  it('incorporates real live scanner findings into tailored prompts', () => {
    const target = 'https://my-live-app.example.com';
    const mockGraph: Partial<AttackGraph> = {
      target,
      findings: [
        {
          id: 'f1',
          title: 'Missing Content-Security-Policy',
          severity: 'high',
          evidenceIds: ['e1'],
          rule: 'csp',
          fix: 'Add CSP',
        },
      ],
      nodes: [
        {
          id: 'live-app',
          label: 'Live Web Service',
          kind: 'compute',
          subtitle: 'TLS Web Server · Nginx Ingress · Status 200',
          evidenceIds: ['e1'],
        },
      ],
    };

    const prompts = generateTailoredIsolationPrompts(target, mockGraph as AttackGraph);
    expect(prompts.some(p => p.toLowerCase().includes('content-security-policy') || p.toLowerCase().includes('csp'))).toBe(true);
  });

  it('identifies and formats GitHub repositories', () => {
    const target = 'https://github.com/ritvikindupuri/Traceveil';
    const info = getCleanTargetName(target);
    expect(info.isGithub).toBe(true);
    expect(info.name).toBe('Traceveil');

    const prompts = generateTailoredIsolationPrompts(target);
    expect(prompts.some(p => p.includes('Traceveil'))).toBe(true);
  });

  it('generates contextual follow-up prompts for any live web app', () => {
    const followUps = generateContextualFollowUpPrompts('https://api.acme-corp.io', 'Can we verify RLS?');
    expect(followUps.length).toBeGreaterThan(0);
    expect(followUps.some(f => f.toLowerCase().includes('database') || f.toLowerCase().includes('migration'))).toBe(true);
  });
});
