import {createServerFn} from '@tanstack/react-start';
import {requireSupabaseAuth} from '@/integrations/supabase/auth-middleware';
import {z} from 'zod';
import {publicEndpoint} from './validation';
import {trustedDestination} from './destinations';

export const listConnections=createServerFn({method:'GET'}).middleware([requireSupabaseAuth]).handler(async({context})=>{
  const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
  const {data,error}=await supabaseAdmin.from('mcp_connections').select('id,name,endpoint,enabled,token_ciphertext').eq('user_id',context.userId).order('created_at',{ascending:false});
  if(error)throw new Error('Could not load connections');
  return data.map(({token_ciphertext,...row})=>({...row,hasToken:Boolean(token_ciphertext)}));
});
export const saveConnection=createServerFn({method:'POST'}).middleware([requireSupabaseAuth]).inputValidator((v:unknown)=>z.object({name:z.string().trim().min(1).max(100),endpoint:z.string().max(2048),enabled:z.boolean(),token:z.string().max(4096).optional(),clearToken:z.boolean().optional()}).strict().parse(v)).handler(async({context,data})=>{
  const endpoint=publicEndpoint(data.endpoint).href;
  const destination=trustedDestination(endpoint);
  if(!destination)throw new Error('This host requires destination-pinned egress; it cannot be enabled yet');
  if(data.token&&!destination.auth)throw new Error('This public server does not accept stored credentials');
  const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
  const existing=await supabaseAdmin.from('mcp_connections').select('id').eq('user_id',context.userId).eq('endpoint',endpoint).maybeSingle();
  if(existing.error)throw new Error('Could not verify connection');
  const {encryptToken}=await import('./token-crypto.server');
  const row={user_id:context.userId,name:data.name,endpoint,enabled:data.enabled,...(data.clearToken?{token_ciphertext:null}:data.token?{token_ciphertext:await encryptToken(data.token,`${context.userId}:${endpoint}`)}:{})};
  const {error}=existing.data?await supabaseAdmin.from('mcp_connections').update(row).eq('id',existing.data.id).eq('user_id',context.userId):await supabaseAdmin.from('mcp_connections').insert(row);
  if(error)throw new Error('Could not save connection');
  return {ok:true};
});
export const deleteConnection=createServerFn({method:'POST'}).middleware([requireSupabaseAuth]).inputValidator((v:unknown)=>z.object({id:z.string().uuid()}).parse(v)).handler(async({context,data})=>{
  const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
  // Disable first so previously saved audits cannot use a deleted connection.
  const {error}=await supabaseAdmin.from('mcp_connections').update({enabled:false,token_ciphertext:null}).eq('id',data.id).eq('user_id',context.userId);
  if(error)throw new Error('Could not disable connection');
  return {ok:true};
});