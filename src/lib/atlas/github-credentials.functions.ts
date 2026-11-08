import {createServerFn} from '@tanstack/react-start';
import {setResponseHeader} from '@tanstack/react-start/server';
import {requireSupabaseAuth} from '@/integrations/supabase/auth-middleware';
export const githubCredentialStatus=createServerFn({method:'GET'}).middleware([requireSupabaseAuth]).handler(async({context})=>{
 setResponseHeader('Cache-Control','no-store');
 const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
 const {data,error}=await supabaseAdmin.from('github_credentials').select('updated_at').eq('user_id',context.userId).maybeSingle();
 return {connected:!error&&Boolean(data),error:error?'Could not load GitHub connection.':null};
});
export const saveGithubCredential=createServerFn({method:'POST'}).middleware([requireSupabaseAuth])
 // Never serialize input-bearing validation errors.
 .inputValidator((data:unknown)=>data).handler(async({data,context})=>{
  setResponseHeader('Cache-Control','no-store');
  const {saveGithubToken}=await import('./github-credentials.server');
  const token=typeof data==='object'&&data!==null&&'token' in data?data.token:null;
  if(typeof token!=='string')return {ok:false,error:'Enter a GitHub personal access token.'};
  return saveGithubToken(context.userId,token);
 });
export const removeGithubCredential=createServerFn({method:'POST'}).middleware([requireSupabaseAuth]).handler(async({context})=>{
 setResponseHeader('Cache-Control','no-store');
 const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
 const {error}=await supabaseAdmin.from('github_credentials').delete().eq('user_id',context.userId);
 return {ok:!error,error:error?'Could not remove the GitHub token.':null};
});