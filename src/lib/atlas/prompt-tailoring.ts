import type { AttackGraph } from './types';

export function getCleanTargetName(target?: string): { name: string; isLive: boolean; isWorker: boolean; isGithub: boolean; cleanUrl: string } {
  if (!target || target === 'production-cluster (live)') {
    return { name: 'your application', isLive: true, isWorker: false, isGithub: false, cleanUrl: 'your application' };
  }

  const cleanUrl = target.trim();
  const isGithub = cleanUrl.includes('github.com');
  const isWorker = cleanUrl.includes('.workers.dev') || cleanUrl.includes('.pages.dev') || cleanUrl.includes('.deno.dev');

  if (isGithub) {
    const parts = cleanUrl.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '').replace(/\/$/, '').split('/');
    const repo = parts[1] || parts[0] || 'repository';
    return { name: repo, isLive: false, isWorker: false, isGithub: true, cleanUrl };
  }

  try {
    const parsed = new URL(cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`);
    const host = parsed.hostname;
    // e.g. cloudpilot-ai.codeworker.workers.dev -> cloudpilot-ai
    const sub = host.split('.')[0];
    const formatted = sub
      .replace(/[-_]/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());
    return { name: formatted || host, isLive: true, isWorker, isGithub: false, cleanUrl };
  } catch {
    return { name: cleanUrl, isLive: true, isWorker, isGithub: false, cleanUrl };
  }
}

/**
 * Generates tailored quick action prompts for any application or repository.
 */
export function generateTailoredIsolationPrompts(target?: string, graph?: AttackGraph | null): string[] {
  const { name, isWorker, isGithub, cleanUrl } = getCleanTargetName(target);
  const lower = cleanUrl.toLowerCase();

  // 1. Cloudflare Workers / Edge Runtime
  if (isWorker || lower.includes('worker') || lower.includes('edge')) {
    return [
      `Verify tenant boundaries on ${name} Cloudflare Workers edge routes`,
      `Isolate multi-tenant context in ${name} KV and D1 edge storage`,
      `Prevent BOLA & IDOR on ${name} worker endpoints`,
      `Run live cross-tenant boundary verification probes against ${name}`,
    ];
  }

  // 2. AI / Copilot / LLM Application
  if (lower.includes('ai') || lower.includes('pilot') || lower.includes('agent') || lower.includes('copilot') || lower.includes('llm') || lower.includes('gpt')) {
    return [
      `Isolate ${name} prompt history and conversation memory across tenants`,
      `Prevent cross-tenant data leakage in ${name} vector stores & embeddings`,
      `Enforce tenant_id boundaries on ${name} autonomous agent tools & APIs`,
      `Run live cross-tenant boundary verification probes against ${name}`,
    ];
  }

  // 3. E-Commerce / Payments / Billing
  if (lower.includes('shop') || lower.includes('store') || lower.includes('pay') || lower.includes('bill') || lower.includes('stripe') || lower.includes('order')) {
    return [
      `Isolate customer billing, invoices, and payment methods in ${name}`,
      `Prevent IDOR and BOLA on ${name} order checkout and cart endpoints`,
      `Synthesize zero-trust PostgreSQL RLS policies for ${name} customer records`,
      `Run live cross-tenant boundary verification probes on ${name} billing APIs`,
    ];
  }

  // 4. Identity, Auth & Access Management
  if (lower.includes('auth') || lower.includes('login') || lower.includes('sso') || lower.includes('id') || lower.includes('user') || lower.includes('rbac')) {
    return [
      `Prevent cross-tenant JWT claim tampering and user impersonation in ${name}`,
      `Isolate multi-organization workspaces and roles in ${name}`,
      `Enforce strict tenant boundary middleware on ${name} session validation`,
      `Run live cross-tenant token substitution probes against ${name}`,
    ];
  }

  // 5. Healthcare & MedTech (HIPAA)
  if (lower.includes('health') || lower.includes('med') || lower.includes('patient') || lower.includes('care') || lower.includes('clinic')) {
    return [
      `Enforce HIPAA-compliant tenant isolation for patient health records in ${name}`,
      `Prevent unauthorized cross-tenant PHI data access (BOLA) in ${name}`,
      `Generate PostgreSQL RLS policies with cryptographic tenant partitioning for ${name}`,
      `Run live cross-tenant boundary verification probes against ${name}`,
    ];
  }

  // 6. GitHub Repository Codebase with graph context
  if (isGithub && graph) {
    const prompts: string[] = [];
    const hasDb = graph.nodes?.some(n => n.kind === 'target' || n.category === 'target' || n.label.toLowerCase().includes('sql') || n.label.toLowerCase().includes('db'));
    const hasHeaderFindings = graph.findings?.some(f => f.title.toLowerCase().includes('header') || f.title.toLowerCase().includes('banner'));
    const hasAuthFindings = graph.findings?.some(f => f.title.toLowerCase().includes('auth') || f.title.toLowerCase().includes('token') || f.title.toLowerCase().includes('key'));

    if (hasDb) {
      prompts.push(`Enforce multi-tenant Row-Level Security (RLS) on ${name} database models`);
    }
    if (hasAuthFindings) {
      prompts.push(`Prevent cross-tenant credential exposure & token leakage in ${name}`);
    }
    if (hasHeaderFindings) {
      prompts.push(`Prevent cross-tenant routing header leakage in ${name}`);
    }

    prompts.push(`Audit ${name} route controllers for missing tenant_id authorization checks (BOLA)`);
    prompts.push(`Generate zero-trust authorization middleware for ${name} API routes`);
    prompts.push(`Run automated CI/CD tenant boundary regression suite for ${name}`);

    return prompts.slice(0, 4);
  }

  if (isGithub) {
    return [
      `Audit ${name} controllers for missing tenant_id authorization checks (BOLA)`,
      `Generate PostgreSQL RLS policies for ${name} database schema`,
      `Enforce zero-trust authorization middleware on ${name} API endpoints`,
      `Run live cross-tenant boundary verification probes against ${name}`,
    ];
  }

  // 7. General Web Application
  return [
    `How do I enforce strict tenant isolation in ${name}?`,
    `Prevent BOLA and IDOR on ${name} customer data endpoints`,
    `Synthesize zero-trust PostgreSQL RLS policies for ${name}`,
    `Run live cross-tenant boundary verification probes against ${name}`,
  ];
}

/**
 * Generates tailored follow-up prompts after an agent response.
 */
export function generateContextualFollowUpPrompts(target?: string, userPrompt?: string): string[] {
  const { name, isWorker, isGithub } = getCleanTargetName(target);
  const p = (userPrompt || '').toLowerCase();

  if (p.includes('probe') || p.includes('test') || p.includes('verify')) {
    return [
      `How do I run these isolation probes in our CI/CD pipeline for ${name}?`,
      `Can you simulate a cross-tenant token replay attack on ${name}?`,
      `How do I set up automated Slack/webhook alerts on boundary violations?`,
    ];
  }

  if (p.includes('rls') || p.includes('sql') || p.includes('database')) {
    return [
      `Can you generate a database migration script for ${name}?`,
      `How do I bypass RLS safely for background administrative cron jobs?`,
      `Can you create multi-tenant database indexes to optimize query speed?`,
    ];
  }

  if (p.includes('middleware') || p.includes('idor') || p.includes('bola')) {
    return [
      `Can you generate a TypeScript type-safe tenant context middleware for ${name}?`,
      `How do I handle users who belong to multiple organizations in ${name}?`,
      `How do I return sanitized 403 Forbidden responses without leaking tenant existence?`,
    ];
  }

  if (isWorker) {
    return [
      `How do I bind Cloudflare KV namespaces per tenant in ${name}?`,
      `Can you generate a Cloudflare Workers JWT validation and tenant extraction module?`,
      `How do I test edge isolation locally using Miniflare / Wrangler?`,
    ];
  }

  if (isGithub) {
    return [
      `Can you generate a GitHub Actions workflow to run these isolation tests on pull requests?`,
      `How do I integrate this tenant boundary check into ${name}'s test suite?`,
      `How do I handle multi-tenant data migrations safely without downtime?`,
    ];
  }

  return [
    `How do I handle users who belong to multiple organizations in ${name}?`,
    `Can you generate an automated regression test script for ${name}?`,
    `How do I safely audit cross-tenant data access logs in production?`,
  ];
}
