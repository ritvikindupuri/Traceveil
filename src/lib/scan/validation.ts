import { z } from 'zod';
import type { Verdict } from './types';

export const scanRequestSchema = z.object({
  mode: z.enum(['definitions', 'transcript', 'endpoint']),
  input: z.string().trim().min(1).max(400_000),
  token: z.string().max(4096).optional(),
}).strict();

const score = z.number().int().min(0).max(100);
export const verdictSchema = z.object({
  verdict: z.enum(['block', 'review', 'allow']), risk: score,
  summary: z.string().min(1).max(2000),
  tools: z.array(z.object({tool: z.string().min(1).max(256), risk: score, class: z.string().max(256)}).strict()).max(30),
  findings: z.array(z.object({severity: z.enum(['critical','high','medium','low']), title: z.string().min(1).max(500), detail: z.string().min(1).max(2000), evidence: z.string().max(2000)}).strict()).max(8),
  guardrails: z.array(z.string().min(1).max(2000)).max(6),
}).strict();

export function validateVerdict(value: unknown, names: string[]): Verdict {
  const result = verdictSchema.parse(value);
  const seen = new Set<string>();
  for (const tool of result.tools) {
    if (!names.includes(tool.tool) || seen.has(tool.tool)) throw new Error('Verdict contains unknown or duplicate tools');
    seen.add(tool.tool);
  }
  return result;
}

export function publicEndpoint(raw: string): URL {
  const url = new URL(raw);
  const host = url.hostname.toLowerCase();
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443') || url.hash) throw new Error('Use a credential-free HTTPS endpoint on port 443');
  if (host.endsWith('.') || !host.includes('.') || host.includes(':') || /^\d+(\.\d+)*$/.test(host) || /(^|\.)(localhost|local|internal|test|invalid|example|onion)$/.test(host)) throw new Error('Private, literal IP and internal endpoints are not allowed');
  return url;
}

export function isPublicIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a,b,c] = parts;
  if (a === undefined || b === undefined || c === undefined) return false;
  return !(a === 0 || a === 10 || a === 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && (b === 168 || b === 0 || b === 2) || a === 100 && b >= 64 && b <= 127 || a === 198 && (b === 18 || b === 19 || b === 51 && c === 100) || a === 203 && b === 0 && c === 113 || a >= 224);
}