import { describe, it, expect } from 'vitest';
import { generateTailoredIsolationPrompts, generateContextualFollowUpPrompts, getCleanTargetName } from './prompt-tailoring';

describe('prompt-tailoring', () => {
  it('identifies and formats Cloudflare Workers live applications', () => {
    const target = 'https://cloudpilot-ai.codeworker.workers.dev';
    const info = getCleanTargetName(target);
    expect(info.isWorker).toBe(true);
    expect(info.isLive).toBe(true);

    const prompts = generateTailoredIsolationPrompts(target);
    expect(prompts.some(p => p.toLowerCase().includes('cloudflare workers'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('cloudpilot ai'))).toBe(true);
    expect(prompts.some(p => p.toLowerCase().includes('d1') || p.toLowerCase().includes('kv'))).toBe(true);
  });

  it('identifies and formats AI / LLM applications', () => {
    const target = 'https://my-copilot-assistant.ai';
    const prompts = generateTailoredIsolationPrompts(target);
    expect(prompts.some(p => p.toLowerCase().includes('prompt history') || p.toLowerCase().includes('vector'))).toBe(true);
  });

  it('identifies and formats e-commerce / payment repositories', () => {
    const target = 'https://github.com/company/payment-billing-service';
    const prompts = generateTailoredIsolationPrompts(target);
    expect(prompts.some(p => p.toLowerCase().includes('billing') || p.toLowerCase().includes('invoices') || p.toLowerCase().includes('payment'))).toBe(true);
  });

  it('identifies and formats GitHub repositories', () => {
    const target = 'https://github.com/ritvikindupuri/Traceveil';
    const info = getCleanTargetName(target);
    expect(info.isGithub).toBe(true);
    expect(info.name).toBe('Traceveil');

    const prompts = generateTailoredIsolationPrompts(target);
    expect(prompts.some(p => p.includes('Traceveil'))).toBe(true);
  });

  it('generates contextual follow-up prompts based on user questions', () => {
    const followUps = generateContextualFollowUpPrompts('https://cloudpilot-ai.codeworker.workers.dev', 'Can we verify RLS?');
    expect(followUps.length).toBeGreaterThan(0);
    expect(followUps.some(f => f.toLowerCase().includes('cloudpilot ai'))).toBe(true);
  });
});
