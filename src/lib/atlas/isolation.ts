import {z} from 'zod';
export const isolationScope=z.object({
 scanId:z.string().uuid(),
 endpoint:z.string().max(240).regex(/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\/\{id\}$/,'Use an object-read path ending in /{id}'),
 idPointer:z.string().max(120).regex(/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+$/,'Use a JSON pointer such as /id or /data/id'),
 rule:z.string().trim().min(10).max(500),
 approval:z.literal(true),
}).strict();
export const caseIds=['a-own','b-own','a-cross','b-cross'] as const;
export const isolationReport=z.object({
 version:z.literal(1),planId:z.string().uuid(),nonce:z.string().uuid(),commit:z.string().regex(/^[a-f0-9]{40}$/),suiteDigest:z.string().regex(/^[a-f0-9]{64}$/),
 cases:z.array(z.object({id:z.enum(caseIds),status:z.number().int().min(0).max(599),matched:z.boolean(),leaked:z.boolean(),error:z.boolean()}).strict()).length(4),
}).strict();
export type IsolationReport=z.infer<typeof isolationReport>;
export type IsolationOutcome='pass'|'fail'|'inconclusive';
export function evaluateIsolation(report:IsolationReport):IsolationOutcome {
 if(new Set(report.cases.map(c=>c.id)).size!==4)return 'inconclusive';
 const own=report.cases.filter(c=>c.id.endsWith('own'));
 if(own.some(c=>c.error||c.status!==200||!c.matched))return 'inconclusive';
 const cross=report.cases.filter(c=>c.id.endsWith('cross'));
 if(cross.some(c=>!c.error&&(c.leaked||c.matched)))return 'fail';
 if(cross.some(c=>c.error||![403,404].includes(c.status)))return 'inconclusive';
 return 'pass';
}
export function assertReportBinding(report:IsolationReport,plan:{id:string;nonce:string;commit_sha:string;suite_digest:string;expires_at:string},now=Date.now()) {
 if(report.planId!==plan.id||report.nonce!==plan.nonce||report.commit!==plan.commit_sha||report.suiteDigest!==plan.suite_digest)throw new Error('Result does not match this approved plan, commit or test suite');
 if(!Number.isFinite(Date.parse(plan.expires_at))||Date.parse(plan.expires_at)<now)throw new Error('Approval expired. Create a new plan before testing.');
}