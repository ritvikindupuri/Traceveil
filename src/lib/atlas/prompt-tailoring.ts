import type { AttackGraph, Finding } from './types';

export interface TargetMetadata {
  name: string;
  isLive: boolean;
  isGithub: boolean;
  cleanUrl: string;
  host: string;
  platform: string;
  serverBanner?: string;
  findings: Finding[];
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
      findings: graph?.findings || [],
    };
  }

  const cleanUrl = target.trim();
  const isGithub = cleanUrl.includes('github.com');
  const findings = graph?.findings || [];

  // Extract real inspected server banner if recorded in graph nodes
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

    // Detect Ingress / Cloud Hosting from inspected TLS endpoint
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

    // Format clean application name
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

function promptFromFinding(f: Finding, name: string, serverBanner?: string): string {
  switch (f.rule) {
    case 'server-banner-leak':
      return serverBanner
        ? `Remediate detected ${serverBanner} routing header & banner leak on ${name}`
        : `Remediate detected server banner & routing header leak on ${name}`;
    case 'missing-csp':
      return `Mitigate script injection & session hijack exposure via strict CSP on ${name}`;
    case 'missing-hsts':
      return `Enforce HSTS encryption to protect live customer sessions on ${name}`;
    case 'missing-frame-options':
      return `Add anti-clickjacking frame protection (X-Frame-Options) to ${name}`;
    case 'exposed-env':
      return `Quarantine publicly exposed .env credentials & rotate secrets for ${name}`;
    case 'public-cidr':
      return `Restrict public CIDR ingress (0.0.0.0/0) on ${name} infrastructure`;
    case 'secret-in-code':
      return `Remove hardcoded credentials and isolate tenant API keys in ${name}`;
    case 'missing-auth':
      return `Enforce tenant_id authentication on unprotected routes in ${name}`;
    case 'database-exposure':
      return `Synthesize multi-tenant PostgreSQL RLS policies for ${name}`;
    default:
      return `Remediate validated finding: ${f.title} on ${name}`;
  }
}

/**
 * Generates tailored quick action prompts based on ACTUALLY SCANNED & VALIDATED findings and evidence.
 * Never simulated, never assumed.
 */
export function generateTailoredIsolationPrompts(target?: string, graph?: AttackGraph | null): string[] {
  const meta = getCleanTargetName(target, graph);
  const { name, cleanUrl, platform, serverBanner, findings } = meta;
  const prompts: string[] = [];

  // LEVEL 1 (PRIMARY): ACTUALLY SCANNED & VALIDATED FINDINGS
  // If the target was scanned, every prompt directly addresses real evidence found in the scan!
  if (findings.length > 0) {
    for (const f of findings) {
      const p = promptFromFinding(f, name, serverBanner);
      if (p && !prompts.includes(p)) {
        prompts.push(p);
      }
    }

    // Always include a live cross-tenant boundary verification probe
    prompts.push(`Run live cross-tenant boundary verification probes against ${name}`);
    return prompts.slice(0, 4);
  }

  // LEVEL 2: IF GRAPH WAS SCANNED WITH ZERO VULNERABILITIES (CLEAN SCAN)
  if (graph && graph.nodes && graph.nodes.length > 0) {
    return [
      `Run live cross-tenant boundary verification probes against ${name}`,
      `Verify zero-trust PostgreSQL RLS enforcement on ${name} datastore`,
      `Audit client-side session tokens on ${name} for BOLA and IDOR resilience`,
      `Generate CI/CD regression suite for ${name} tenant boundaries`,
    ];
  }

  // LEVEL 3: PRE-SCAN (User typed URL or selected repository, but hasn't scanned yet)
  // Direct them to actually scan and validate rather than guessing!
  const lower = cleanUrl.toLowerCase();

  if (meta.isGithub) {
    return [
      `Scan ${name} repository to validate tenant boundaries and authorization checks`,
      `Generate PostgreSQL RLS policies for ${name} database models`,
      `Audit ${name} route controllers for missing tenant_id checks (BOLA)`,
      `Run live cross-tenant boundary verification probes against ${name}`,
    ];
  }

  if (platform !== 'Web Service' && platform !== 'Live Web App') {
    return [
      `Run live TLS & security posture scan against ${name} on ${platform}`,
      `Verify tenant boundaries on ${name} ${platform} routes`,
      `Prevent BOLA & IDOR on ${name} ${platform} endpoints`,
      `Run live cross-tenant boundary verification probes against ${name}`,
    ];
  }

  return [
    `Run live TLS & security posture scan against ${name}`,
    `Validate tenant authorization boundaries on ${name} before deployment`,
    `Prevent BOLA and IDOR on ${name} customer endpoints`,
    `Run live cross-tenant boundary verification probes against ${name}`,
  ];
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
