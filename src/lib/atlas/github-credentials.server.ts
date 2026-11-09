import {encryptToken,decryptToken} from '@/lib/scan/token-crypto.server';
export function validGithubToken(input:unknown):input is string {
 return typeof input==='string' && /^(?:github_pat_[A-Za-z0-9_]{20,240}|ghp_[A-Za-z0-9]{20,100})$/.test(input);
}
export const githubBinding=(userId:string)=>`traceveil:github-pat:v1:${userId}:https://api.github.com`;
export async function loadGithubToken(userId:string) {
 try {
  const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
  const {data,error}=await supabaseAdmin.from('github_credentials').select('token_ciphertext').eq('user_id',userId).maybeSingle();
  if(error||!data)return null;
  return await decryptToken(data.token_ciphertext,githubBinding(userId));
 } catch {
  return null;
 }
}
export async function saveGithubToken(userId:string,token:string) {
 if(!validGithubToken(token))return {ok:false,error:'Enter a GitHub personal access token.'};
 try {
  const response=await fetch('https://api.github.com/user',{headers:{Accept:'application/vnd.github+json',Authorization:`Bearer ${token}`,'User-Agent':'Traceveil'},redirect:'error',signal:AbortSignal.timeout(10000)});
  await response.body?.cancel();
  if(!response.ok)return {ok:false,error:response.status===401?'GitHub rejected this token. Check its expiry and permissions.':'GitHub could not validate this token. Try again later.'};
  const ciphertext=await encryptToken(token,githubBinding(userId));
  const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
  const {error}=await supabaseAdmin.from('github_credentials').upsert({user_id:userId,token_ciphertext:ciphertext,updated_at:new Date().toISOString()},{onConflict:'user_id'});
  return {ok:!error,error:error?'Could not save the GitHub token.':null};
 }catch{return {ok:false,error:'Secure GitHub connection unavailable. Try again later.'};}
}