import { createFileRoute } from '@tanstack/react-router';
import {
  createUser,
  findUserByEmail,
  verifyPassword,
  createSession,
  getSessionByToken,
  deleteSession,
  updateUserPassword,
} from '@/lib/server/db.server';

export const Route = createFileRoute('/api/auth')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        try {
          const body = await request.json().catch(() => ({}));
          const action = body.action || '';

          if (action === 'signup') {
            const { email, password } = body;
            const result = createUser(email || '', password || '');
            if (result.error) {
              return Response.json({ error: result.error }, { status: 400 });
            }
            const session = createSession(result.user.id);
            return Response.json({
              data: {
                user: result.user,
                session: {
                  access_token: session.token,
                  user: result.user,
                },
              },
              error: null,
            });
          }

          if (action === 'signin') {
            const { email, password } = body;
            if (!email || !password) {
              return Response.json({ error: 'Email and password are required.' }, { status: 400 });
            }
            const user = findUserByEmail(email);
            if (!user || !verifyPassword(password, user.password_hash)) {
              return Response.json({ error: 'Invalid email or password.' }, { status: 401 });
            }
            const session = createSession(user.id);
            const userClean = { id: user.id, email: user.email };
            return Response.json({
              data: {
                user: userClean,
                session: {
                  access_token: session.token,
                  user: userClean,
                },
              },
              error: null,
            });
          }

          if (action === 'session') {
            const authHeader = request.headers.get('authorization');
            const token = (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : body.token)?.trim();
            if (!token) {
              return Response.json({ data: { session: null, user: null }, error: null });
            }
            const active = getSessionByToken(token);
            if (!active) {
              return Response.json({ data: { session: null, user: null }, error: null });
            }
            return Response.json({
              data: {
                user: active.user,
                session: {
                  access_token: active.session.token,
                  user: active.user,
                },
              },
              error: null,
            });
          }

          if (action === 'signout') {
            const authHeader = request.headers.get('authorization');
            const token = (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : body.token)?.trim();
            if (token) deleteSession(token);
            return Response.json({ data: { ok: true }, error: null });
          }

          if (action === 'reset-password') {
            return Response.json({
              data: { message: 'Password reset request received. If an account exists, instructions have been prepared.' },
              error: null,
            });
          }

          if (action === 'update-password') {
            const authHeader = request.headers.get('authorization');
            const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
            const active = getSessionByToken(token);
            if (!active) {
              return Response.json({ error: 'Sign in to update your password.' }, { status: 401 });
            }
            const updated = updateUserPassword(active.user.id, body.password || '');
            if (!updated) {
              return Response.json({ error: 'Password must be at least 8 characters long.' }, { status: 400 });
            }
            return Response.json({ data: { user: active.user }, error: null });
          }

          return Response.json({ error: `Unknown auth action: ${action}` }, { status: 400 });
        } catch (err) {
          console.error('[api/auth] Error:', err);
          return Response.json({ error: 'Internal server error' }, { status: 500 });
        }
      },
    },
  },
});
