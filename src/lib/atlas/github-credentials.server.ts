import {encryptToken,decryptToken} from '@/lib/scan/token-crypto.server';
export function validGithubToken(input:unknown):input is string {
  if (typeof input !== 'string') return false;
  const trimmed = input.trim();
  return /^(?:github_pat_[A-Za-z0-9_]{20,255}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,100}|[a-f0-9]{40})$/.test(trimmed);
}
export const githubBinding=(userId:string)=>`traceveil:github-pat:v1:${userId}:https://api.github.com`;
export async function loadGithubToken(userId:string) {
  try {
    const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
    const {data,error}=await supabaseAdmin.from('github_credentials').select('token_ciphertext').eq('user_id',userId).maybeSingle();
    if(error||!data || typeof data.token_ciphertext !== 'string')return null;
    return await decryptToken(data.token_ciphertext,githubBinding(userId));
  } catch {
    return null;
  }
}
export async function saveGithubToken(userId:string,token:string) {
  const cleanToken = typeof token === 'string' ? token.trim() : '';
  if(!validGithubToken(cleanToken))return {ok:false,error:'Enter a valid GitHub personal access token (e.g. ghp_... or github_pat_...).'};
  try {
    const response=await fetch('https://api.github.com/user',{
      headers:{
        Accept:'application/vnd.github+json',
        Authorization:`Bearer ${cleanToken}`,
        'User-Agent':'Traceveil'
      },
      redirect:'error',
      signal:AbortSignal.timeout(10000)
    });
    await response.body?.cancel();
    if(!response.ok) {
      return {
        ok:false,
        error: response.status === 401
          ? 'GitHub rejected this token (401 Unauthorized). Check that the token is active, not expired, and has repo permissions.'
          : response.status === 403
          ? 'GitHub rate limit or permission error (403 Forbidden). Ensure your token has repo read/write access.'
          : `GitHub could not validate this token (HTTP ${response.status}). Try again later.`
      };
    }
    const ciphertext=await encryptToken(cleanToken,githubBinding(userId));
    const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
    const {error}=await supabaseAdmin.from('github_credentials').upsert({
      user_id:userId,
      token_ciphertext:ciphertext,
      updated_at:new Date().toISOString()
    },{onConflict:'user_id'});
    return {ok:!error,error:error?'Could not save the GitHub token.':null};
  } catch (err: unknown) {
    console.error('[saveGithubToken] Error during validation or saving:', err);
    return {ok:false,error:'Secure GitHub connection unavailable. Check your internet connection and try again.'};
  }
}