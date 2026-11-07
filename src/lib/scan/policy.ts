import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import type { McpTool, Verdict } from './types';
import { scanTools, scanTranscript } from './signals';

export function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.entries(value).sort(([a],[b]) => a.localeCompare(b)).map(([k,v]) => JSON.stringify(k)+':'+canonical(v)).join(',') + '}';
  return JSON.stringify(value) ?? 'null';
}
export async function fingerprint(tools: McpTool[]): Promise<string> {
  const bytes = new TextEncoder().encode(canonical([...tools].sort((a,b) => a.name.localeCompare(b.name))));
  const digest = await crypto.subtle.digest('SHA-256',bytes);
  return Array.from(new Uint8Array(digest),n => n.toString(16).padStart(2,'0')).join('');
}
export function eligibleTools(tools: McpTool[], verdict: Verdict): string[] {
  if (verdict.verdict !== 'allow') return [];
  return tools.filter(t => verdict.tools.some(v => v.tool === t.name && v.risk < 40) && !scanTools([t]).some(s => s.severity === 'critical' || s.severity === 'high') && !/\b(write|delete|execute|shell|credential|secret|send|upload|payment)\b/i.test(t.name.replace(/_/g,' ')+' '+t.description)).map(t => t.name);
}
export function checkCall(tools: McpTool[], approved: string[], name: string, args: Record<string,unknown>): string | null {
  const tool = tools.find(t => t.name === name);
  if (!tool || !approved.includes(name)) return 'Tool is not approved';
  if (JSON.stringify(args).length > 16_000) return 'Arguments exceed limit';
  const schema = tool.inputSchema;
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) return 'Invalid tool schema';
  const obj = schema as Record<string,unknown>;
  if (obj.type !== 'object' || !obj.properties || typeof obj.properties !== 'object') return 'An explicit object schema is required';
  if (Object.keys(args).some(k => !Object.hasOwn(obj.properties as object,k))) return 'Undeclared argument';
  if (/"\$ref"\s*:\s*"(?!#)/.test(JSON.stringify(schema))) return 'External schema references are not allowed';
  try {
    const ajv = new Ajv({allErrors:true,strict:false,validateFormats:true}); addFormats(ajv);
    if (!ajv.compile(schema)(args)) return 'Arguments violate the approved schema';
  } catch { return 'Schema could not be validated'; }
  const text = JSON.stringify(args);
  if (/https?:\/\/|\.\.\/|\.\.\\|(?:\/etc\/|\.ssh|\.aws|\.env)|\b(?:api[_-]?key|access[_-]?token|password|secret)\b/i.test(text)) return 'Sensitive path, credential or egress parameter blocked';
  if (scanTranscript(text).some(s => s.severity === 'critical' || s.severity === 'high')) return 'Injection signal in arguments';
  return null;
}