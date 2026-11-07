import {createServerFn} from '@tanstack/react-start';
import {requireSupabaseAuth} from '@/integrations/supabase/auth-middleware';
import {runtimePolicySchema} from './runtime-policy';

export const getRuntimePolicy=createServerFn({method:'GET'}).middleware([requireSupabaseAuth]).handler(async({context})=>{
 const {loadRuntimePolicy}=await import('./runtime-policy.server');
 return {...await loadRuntimePolicy(context.supabase,context.userId),egress:{status:'not-configured' as const,ip:null}};
});
export const saveRuntimePolicy=createServerFn({method:'POST'}).middleware([requireSupabaseAuth]).inputValidator((value:unknown)=>runtimePolicySchema.parse(value)).handler(async({data,context})=>{
 const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
 const {error}=await supabaseAdmin.from('guardrail_policies').upsert({user_id:context.userId,policy:data,revision:crypto.randomUUID(),updated_at:new Date().toISOString()});
 if(error)throw new Error('Policy could not be saved');
 const {loadRuntimePolicy}=await import('./runtime-policy.server');
 return loadRuntimePolicy(context.supabase,context.userId);
});