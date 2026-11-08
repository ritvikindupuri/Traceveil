import {createServerFn} from '@tanstack/react-start';
import {requireSupabaseAuth} from '@/integrations/supabase/auth-middleware';
import {z} from 'zod';
import {assertIsolationOwner,assertReportBinding,evaluateIsolation,isolationReport,isolationScope} from './isolation';
import {ISOLATION_RUNNER,runnerSource} from './isolation-runner';
async function digest(value:string){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),b=>b.toString(16).padStart(2,'0')).join('');}
function signedIn(claims:Record<string,unknown>){if(claims['is_anonymous']===true)throw new Error('Sign in with a non-anonymous account');}
export const createIsolationPlan=createServerFn({method:'POST'}).middleware([requireSupabaseAuth]).inputValidator((input:unknown)=>isolationScope.parse(input)).handler(async({data,context})=>{
 signedIn(context.claims);
 const {data:scan,error}=await context.supabase.from('application_scans').select('id,target,commit_sha,user_id').eq('id',data.scanId).eq('user_id',context.userId).single();
 if(error||!scan)throw new Error('Saved scan not found in your workspace');
 assertIsolationOwner(scan.user_id,context.userId);
 const suiteDigest=await digest(JSON.stringify({version:1,endpoint:data.endpoint,idPointer:data.idPointer,rule:data.rule,runner:ISOLATION_RUNNER}));
 const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
 const {data:plan,error:saveError}=await supabaseAdmin.from('tenant_verification_plans').insert({user_id:context.userId,scan_id:scan.id,target:scan.target,commit_sha:scan.commit_sha,endpoint:data.endpoint,id_pointer:data.idPointer,rule:data.rule,suite_digest:suiteDigest}).select('*').single();
 if(saveError||!plan)throw new Error('Could not save the approved plan');
 return {plan,source:runnerSource({planId:plan.id,nonce:plan.nonce,commit:plan.commit_sha,suiteDigest:plan.suite_digest,endpoint:plan.endpoint,idPointer:plan.id_pointer,expiresAt:plan.expires_at})};
});
export const listIsolationPlans=createServerFn({method:'GET'}).middleware([requireSupabaseAuth]).handler(async({context})=>{
 signedIn(context.claims);
 const {data:plans,error}=await context.supabase.from('tenant_verification_plans').select('*').eq('user_id',context.userId).order('approved_at',{ascending:false}).limit(30);
 const {data:runs,error:runError}=await context.supabase.from('tenant_verification_runs').select('*').eq('user_id',context.userId).order('created_at',{ascending:false}).limit(50);
 if(error||runError)throw new Error('Could not load tenant checks');return {plans:plans??[],runs:runs??[]};
});
export const importIsolationResult=createServerFn({method:'POST'}).middleware([requireSupabaseAuth]).inputValidator((input:unknown)=>z.object({report:z.string().max(12000)}).strict().parse(input)).handler(async({data,context})=>{
 signedIn(context.claims);
 const report=isolationReport.parse(JSON.parse(data.report));
 const {data:plan,error}=await context.supabase.from('tenant_verification_plans').select('*').eq('id',report.planId).eq('user_id',context.userId).single();
 if(error||!plan)throw new Error('Approved plan not found in your workspace');
 assertIsolationOwner(plan.user_id,context.userId);
 assertReportBinding(report,plan);
 const expected=await digest(JSON.stringify({version:1,endpoint:plan.endpoint,idPointer:plan.id_pointer,rule:plan.rule,runner:ISOLATION_RUNNER}));
 if(expected!==plan.suite_digest)throw new Error('The test suite changed. Create a fresh plan.');
 const artifactDigest=await digest(JSON.stringify(report)),outcome=evaluateIsolation(report);
 const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
 const {error:saveError}=await supabaseAdmin.from('tenant_verification_runs').insert({user_id:context.userId,plan_id:plan.id,outcome,result:JSON.parse(JSON.stringify(report)),artifact_digest:artifactDigest,provenance:'customer-reported'});
 if(saveError)throw new Error(saveError.code==='23505'?'This plan already has a result. Create a new plan for another run.':'Could not save tenant-check result');
 return {outcome,provenance:'customer-reported'};
});