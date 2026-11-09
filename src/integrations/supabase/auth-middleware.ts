import { createMiddleware } from '@tanstack/react-start';
import { getRequest } from '@tanstack/react-start/server';
import { getSessionByToken, createServerDbClient } from '@/lib/server/db.server';

export const requireSupabaseAuth = createMiddleware({ type: 'function' }).server(
  async ({ next }) => {
    const request = getRequest();

    if (!request?.headers) {
      throw new Error('Unauthorized: No request headers available');
    }

    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new Error('Unauthorized: No authorization header provided');
    }

    const token = authHeader.replace('Bearer ', '').trim();
    if (!token) {
      throw new Error('Unauthorized: No token provided');
    }

    const active = getSessionByToken(token);
    if (!active) {
      throw new Error('Unauthorized: Invalid or expired session');
    }

    return next({
      context: {
        userId: active.user.id,
        user: active.user,
        supabase: createServerDbClient(active.user.id),
      },
    });
  }
);
