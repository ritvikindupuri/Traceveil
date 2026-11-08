import { z } from 'zod';
import type { AttackGraph } from './types';
export const applicationRequest = z.object({ url: z.string().max(500), ref: z.string().max(100).default(''), aiConsent: z.literal(true) });
export function repositoryTarget(raw: string) {
 const url = new URL(raw);
 if(url.protocol !== 'https:' || url.hostname !== 'github.com' || url.port || url.username || url.password || url.search || url.hash) throw new Error('Enter a public GitHub repository URL');
 const parts = url.pathname.replace(/\/$/,'').split('/').filter(Boolean);
 if(parts.length !== 2 || !parts.every(p => /^[a-zA-Z0-9_.-]+$/.test(p) && p!=='.' && p!=='..')) throw new Error('Use https://github.com/owner/repository');
 const [owner, name] = parts; if(!owner || !name) throw new Error('Repository required');
 const repo = name.replace(/\.git$/,''); if(!repo) throw new Error('Repository required');
 return {owner,repo,url:`https://github.com/${owner}/${repo}`};
}
export function redact(text:string) {
 return text.replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g,'[REDACTED PRIVATE KEY]')
 .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,}|sk-[A-Za-z0-9_-]{16,})\b/g,'[REDACTED TOKEN]')
 .replace(/((?:password|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*)["']?[^\s,"';}\n]+["']?/gi,'$1[REDACTED]');
}
export function validateGraph(graph:AttackGraph) {
 const ids=new Set(graph.nodes.map(n=>n.id)), evidence=new Set(graph.evidence.map(e=>e.id));
 if(ids.size!==graph.nodes.length) throw new Error('Duplicate graph entities');
 for(const item of [...graph.nodes,...graph.edges,...graph.findings]) if(!item.evidenceIds.length || item.evidenceIds.some(id=>!evidence.has(id))) throw new Error('Unsupported graph evidence');
 for(const edge of graph.edges) if(!ids.has(edge.source)||!ids.has(edge.target)) throw new Error('Unknown graph entity');
 return graph;
}
