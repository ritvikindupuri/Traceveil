import {z} from 'zod';
import {MCP_DESTINATIONS} from './destinations';
import type {Verdict} from './types';

const host = z.string().trim().toLowerCase().max(253).regex(/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/, 'Use an exact hostname');
export const runtimePolicySchema = z.object({
  enabled:z.boolean(),
  hosts:z.array(host).max(100).transform(v=>[...new Set(v)]),
  tools:z.array(z.string().trim().min(1).max(256).regex(/^[a-zA-Z0-9_.-]+$/, 'Use exact tool names')).max(500).transform(v=>[...new Set(v)]),
  maxToolRisk:z.number().int().min(0).max(100),
  maxAuditRisk:z.number().int().min(0).max(100),
}).strict();
export type RuntimePolicy = z.infer<typeof runtimePolicySchema>;
export function defaultRuntimePolicy():RuntimePolicy {
  return {enabled:true,hosts:MCP_DESTINATIONS.map(d=>new URL(d.endpoint).hostname),tools:MCP_DESTINATIONS.flatMap(d=>[...d.tools]),maxToolRisk:39,maxAuditRisk:39};
}

// A user policy can only narrow independent platform checks, never grant network authority or approval.
export function evaluateRuntimePolicy(policy:RuntimePolicy,endpoint:string|null,name:string,verdict:Verdict):string|null {
  if(!policy.enabled)return 'Runtime forwarding disabled by policy';
  if(!endpoint)return 'Live endpoint required';
  let hostname:string;
  try{hostname=new URL(endpoint).hostname;}catch{return 'Invalid endpoint';}
  if(!policy.hosts.includes(hostname))return 'Host denied by policy';
  if(!policy.tools.includes(name))return 'Tool denied by policy';
  if(verdict.verdict!=='allow')return 'Audit requires review or is blocked';
  if(!Number.isFinite(verdict.risk)||verdict.risk>policy.maxAuditRisk)return 'Audit risk exceeds policy threshold';
  const score=verdict.tools.find(t=>t.tool===name)?.risk;
  if(score===undefined||!Number.isFinite(score))return 'Tool risk unavailable';
  if(score>policy.maxToolRisk)return 'Tool risk exceeds policy threshold';
  return null;
}