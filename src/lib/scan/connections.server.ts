import {decryptToken} from './token-crypto.server';
import {trustedDestination} from './destinations';
export async function resolveConnection(userId:string,id:string,endpoint:string) {
  const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
  const {data,error}=await supabaseAdmin.from('mcp_connections').select('*').eq('id',id).eq('user_id',userId).single();
  if(error||!data||!data.enabled||data.endpoint!==endpoint)throw new Error('Connection unavailable or disabled');
  if(!trustedDestination(data.endpoint))throw new Error('Destination requires pinned egress');
  return data.token_ciphertext ? await decryptToken(data.token_ciphertext,`${userId}:${data.endpoint}`):undefined;
}