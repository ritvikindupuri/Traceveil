import { getSessionByToken, createServerDbClient } from '@/lib/server/db.server';

export async function authenticateRequest(request: Request) {
  const bearer = request.headers.get('authorization');
  if (!bearer?.startsWith('Bearer ')) throw new Error('Sign in to continue');
  const token = bearer.slice(7).trim();
  if (!token) throw new Error('Sign in to continue');
  const active = getSessionByToken(token);
  if (!active) throw new Error('Sign in to continue');
  return {
    client: createServerDbClient(active.user.id),
    userId: active.user.id,
    user: active.user,
  };
}