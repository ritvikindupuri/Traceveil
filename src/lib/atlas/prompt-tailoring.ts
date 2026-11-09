import type { AttackGraph } from './types';

export interface TargetMetadata {
  name: string;
  isLive: boolean;
  isGithub: boolean;
  cleanUrl: string;
  host: string;
  platform: string;
  serverBanner?: string;
  findings: string[];
}

export function getCleanTargetName(target?: string, graph?: AttackGraph | null): TargetMetadata {
  if (!target || target === 'production-cluster (live)') {
    return {
      name: 'your application',
      isLive: true,
      isGithub: false,
      cleanUrl: 'your application',
      host: 'localhost',
      platform: 'Live Web Service',
      findings: [],
    };
  }

  const cleanUrl = target.trim();
  const isGithub = cleanUrl.includes('github.com');
  const findings = (graph?.findings || []).map(f => f.title);

  // Extract server banner if recorded in graph nodes
  const liveNode = graph?.nodes?.find(n => n.id === 'live-app' || n.kind === 'compute');
  let serverBanner: string | undefined;
  if (liveNode?.subtitle) {
    const match = liveNode.subtitle.match(/·\s*([^·]+?)\s*·/);
    if (match) serverBanner = match[1].trim();
  }

  if (isGithub) {
    const parts = cleanUrl.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '').replace(/\/$/, '').split('/');
    const repo = parts[1] || parts[0] || 'repository';
    return {
      name: repo,
      isLive: false,
      isGithub: true,
      cleanUrl,
      host: 'github.com',
      platform: 'GitHub Repository',
      serverBanner,
      findings,
    };
  }

  try {
    const parsed = new URL(cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`);
    const host = parsed.hostname;

    // Detect Hosting Platform / Ingress for any live web app
    let platform = 'Web Service';
    if (host.endsWith('.workers.dev') || host.endsWith('.pages.dev')) platform = 'Cloudflare Workers';
    else if (host.endsWith('.vercel.app')) platform = 'Vercel';
    else if (host.endsWith('.fly.dev')) platform = 'Fly.io';
    else if (host.endsWith('.railway.app')) platform = 'Railway';
    else if (host.endsWith('.onrender.com')) platform = 'Render';
    else if (host.endsWith('.herokuapp.com')) platform = 'Heroku';
    else if (host.includes('.amazonaws.com') || host.includes('.elasticbeanstalk.com')) platform = 'AWS';
    else if (host.includes('.azurewebsites.net')) platform = 'Azure';
    else if (host.includes('.appspot.com')) platform = 'Google Cloud';
    else if (host.includes('.supabase.co')) platform = 'Supabase';
    else if (parsed.port) platform = `Live Service (Port ${parsed.port})`;

    // Format human-friendly name from subdomain or host
    const sub = host.split('.')[0];
    const formatted = sub
      .replace(/[-_]/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase());

    return {
      name: formatted || host,
      isLive: true,
      isGithub: false,
      cleanUrl,
      host,
      platform,
      serverBanner,
      findings,
    };
  } catch {
    return {
      name: cleanUrl,
      isLive: true,
      isGithub: false,
      cleanUrl,
      host: cleanUrl,
      platform: 'Live Web App',
      serverBanner,
      findings,
    };
  }
}

/**
 * Generates tailored quick action prompts for ANY live web application or source repository.
 */
export function generateTailoredIsolationPrompts(target?: string, graph?: AttackGraph | null): string[] {
  const meta = getCleanTargetName(target, graph);
  const { name, cleanUrl, platform, serverBanner, findings } = meta;
  const lower = cleanUrl.toLowerCase();
  const prompts: string[] = [];

  // 1. Live scan findings take top priority for tailored actionability
  if (findings.length > 0) {
    if (findings.some(f => f.toLowerCase().includes('header') || f.toLowerCase().includes('banner'))) {
      prompts.push(`Prevent routing header leakage and tenant fingerprinting on ${name}`);
    }
    if (findings.some(f => f.toLowerCase().includes('content-security-policy') || f.toLowerCase().includes('csp'))) {
      prompts.push(`Prevent cross-tenant session hijacking with zero-trust CSP for ${name}`);
    }
    if (findings.some(f => f.toLowerCase().includes('cors') || f.toLowerCase().includes('origin'))) {
      prompts.push(`Prevent cross-tenant credential theft and BOLA via CORS rules on ${name}`);
    }
    if (findings.some(f => f.toLowerCase().includes('env') || f.toLowerCase().includes('secret'))) {
      prompts.push(`Isolate environment secrets and database credentials on ${name}`);
    }
  }

  // 2. Industry / Domain Archetype Tailoring (Works for any custom domain, e.g. api.acme.com, shop.corp.net, app.fintech.io)
  if (lower.includes('fintech') || lower.includes('bank') || lower.includes('ledger') || lower.includes('pay') || lower.includes('wallet') || lower.includes('crypto')) {
    prompts.push(`Isolate customer transaction ledgers and financial records on ${name}`);
    prompts.push(`Prevent cross-account transfer tampering and IDOR on ${name} APIs`);
    prompts.push(`Enforce cryptographic tenant boundary verification on ${name}`);
    prompts.push(`Run live cross-tenant boundary verification probes against ${name}`);
    return prompts.slice(0, 4);
  }

  if (lower.includes('health') || lower.includes('med') || lower.includes('patient') || lower.includes('care') || lower.includes('clinic') || lower.includes('ehr')) {
    prompts.push(`Enforce HIPAA-compliant tenant isolation for patient records on ${name}`);
    prompts.push(`Prevent unauthorized cross-tenant PHI data exposure (BOLA) on ${name}`);
    prompts.push(`Generate zero-trust PostgreSQL RLS policies for ${name}`);
    prompts.push(`Run live cross-tenant boundary verification probes against ${name}`);
    return prompts.slice(0, 4);
  }

  if (lower.includes('shop') || lower.includes('store') || lower.includes('cart') || lower.includes('bill') || lower.includes('checkout') || lower.includes('stripe')) {
    prompts.push(`Isolate customer billing, cart states, and orders in ${name}`);
    prompts.push(`Prevent BOLA and IDOR on ${name} checkout and payment webhooks`);
    prompts.push(`Synthesize zero-trust RLS policies for ${name} order records`);
    prompts.push(`Run live cross-tenant boundary verification probes on ${name} billing APIs`);
    return prompts.slice(0, 4);
  }

  if (lower.includes('ai') || lower.includes('pilot') || lower.includes('agent') || lower.includes('copilot') || lower.includes('llm') || lower.includes('gpt')) {
    prompts.push(`Isolate ${name} prompt history and conversation memory across tenants`);
    prompts.push(`Prevent cross-tenant data leakage in ${name} vector stores & embeddings`);
    if (platform === 'Cloudflare Workers') {
      prompts.push(`Verify tenant boundaries on ${name} Cloudflare Workers edge routes`);
    } else {
      prompts.push(`Enforce tenant_id boundaries on ${name} autonomous agent tools & APIs`);
    }
    prompts.push(`Run live cross-tenant boundary verification probes against ${name}`);
    return prompts.slice(0, 4);
  }

  if (lower.includes('auth') || lower.includes('login') || lower.includes('sso') || lower.includes('identity') || lower.includes('user') || lower.includes('rbac')) {
    prompts.push(`Prevent cross-tenant JWT claim tampering and user impersonation on ${name}`);
    prompts.push(`Isolate multi-organization workspaces and roles in ${name}`);
    prompts.push(`Enforce strict tenant boundary middleware on ${name} session validation`);
    prompts.push(`Run live cross-tenant token substitution probes against ${name}`);
    return prompts.slice(0, 4);
  }

  // 3. Platform & Infrastructure Tailoring (Cloudflare, Vercel, Fly.io, AWS, Heroku, etc.)
  if (platform !== 'Web Service' && platform !== 'GitHub Repository' && platform !== 'Live Web App') {
    prompts.push(`Verify tenant boundaries on ${name} ${platform} routes`);
    prompts.push(`Prevent BOLA & IDOR on ${name} ${platform} endpoints`);
    prompts.push(`Isolate multi-tenant context and environment bindings on ${platform}`);
    prompts.push(`Run live cross-tenant boundary verification probes against ${name}`);
    return prompts.slice(0, 4);
  }

  // 4. Server Framework Tailoring if detected on any live web app
  if (serverBanner) {
    prompts.push(`Configure zero-trust tenant middleware for ${serverBanner} on ${name}`);
    prompts.push(`Prevent BOLA & IDOR on ${name} ${serverBanner} API routes`);
    prompts.push(`Synthesize multi-tenant Row-Level Security policies for ${name}`);
    prompts.push(`Run live cross-tenant boundary verification probes against ${name}`);
    return prompts.slice(0, 4);
  }

  // 5. GitHub Repository Codebase
  if (meta.isGithub) {
    prompts.push(`Audit ${name} route controllers for missing tenant_id authorization checks (BOLA)`);
    prompts.push(`Generate PostgreSQL RLS policies for ${name} database schema`);
    prompts.push(`Enforce zero-trust authorization middleware on ${name} API endpoints`);
    prompts.push(`Run live cross-tenant boundary verification probes against ${name}`);
    return prompts.slice(0, 4);
  }

  // 6. Any other Live Web App
  if (prompts.length < 4) {
    prompts.push(`How do I enforce strict tenant isolation on ${name}?`);
    prompts.push(`Prevent BOLA and IDOR on ${name} customer data endpoints`);
    prompts.push(`Synthesize zero-trust PostgreSQL RLS policies for ${name}`);
    prompts.push(`Run live cross-tenant boundary verification probes against ${name}`);
  }

  return prompts.slice(0, 4);
}

/**
 * Generates tailored follow-up prompts after an agent response for ANY application.
 */
export function generateContextualFollowUpPrompts(target?: string, userPrompt?: string): string[] {
  const { name, platform, isGithub } = getCleanTargetName(target);
  const p = (userPrompt || '').toLowerCase();

  if (p.includes('rls') || p.includes('sql') || p.includes('database')) {
    return [
      `Can you generate a database migration script for ${name}?`,
      `How do I bypass RLS safely for background administrative cron jobs?`,
      `Can you create multi-tenant database indexes to optimize query speed on ${name}?`,
    ];
  }

  if (p.includes('probe') || p.includes('test') || p.includes('verify')) {
    return [
      `How do I run these isolation probes in our CI/CD pipeline for ${name}?`,
      `Can you simulate a cross-tenant token replay attack on ${name}?`,
      `How do I set up automated Slack/webhook alerts on boundary violations?`,
    ];
  }

  if (p.includes('middleware') || p.includes('idor') || p.includes('bola')) {
    return [
      `Can you generate a TypeScript type-safe tenant context middleware for ${name}?`,
      `How do I handle users who belong to multiple organizations in ${name}?`,
      `How do I return sanitized 403 Forbidden responses without leaking tenant existence?`,
    ];
  }

  if (platform !== 'Web Service' && platform !== 'GitHub Repository') {
    return [
      `How do I deploy this tenant isolation policy on ${platform}?`,
      `Can you generate environment variable bindings for ${platform}?`,
      `How do I test edge isolation locally before deploying to ${platform}?`,
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
