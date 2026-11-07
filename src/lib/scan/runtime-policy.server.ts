import type {SupabaseClient} from '@supabase/supabase-js';
import type {Database} from '@/integrations/supabase/types';
import {defaultRuntimePolicy,runtimePolicySchema} from './runtime-policy';

export async function loadRuntimePolicy(client:SupabaseClient<Database>,userId:string){
 const {data,error}=await client.from('guardrail_policies').select('policy,revision').eq('user_id',userId).maybeSingle();
 if(error)throw new Error('Runtime policy unavailable; forwarding blocked');
 return {policy:data?runtimePolicySchema.parse(data.policy):defaultRuntimePolicy(),revision:data?.revision ?? 'default'};
}