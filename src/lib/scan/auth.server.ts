import { createClient } from '@supabase/supabase-js';
import type { Database } from '@/integrations/supabase/types';

export async function authenticateRequest(request: Request) {
  const bearer = request.headers.get('authorization');
  if (!bearer?.startsWith('Bearer ')) throw new Error('Sign in to continue');
  const url = process.env['SUPABASE_URL'];
  const key = process.env['SUPABASE_PUBLISHABLE_KEY'];
  if (!url || !key) throw new Error('Account service unavailable');
  const client = createClient<Database>(url, key, {auth:{persistSession:false,autoRefreshToken:false}, global:{headers:{Authorization:bearer}, fetch:(input,init) => {
    const headers = new Headers(init?.headers); headers.set('apikey',key);
    if (headers.get('Authorization') === `Bearer ${key}`) headers.delete('Authorization');
    return fetch(input,{...init,headers});
  }}});
  const {data,error} = await client.auth.getUser(bearer.slice(7));
  if (error || !data.user || data.user.is_anonymous) throw new Error('Sign in to continue');
  return {client,userId:data.user.id};
}