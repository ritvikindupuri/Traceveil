import { createFileRoute } from '@tanstack/react-router';

export const Route = createFileRoute('/api/github-credentials')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        let userId: string;
        try {
          const { authenticateRequest } = await import('@/lib/scan/auth.server');
          const auth = await authenticateRequest(request);
          userId = auth.userId;
        } catch {
          return Response.json({ connected: false, error: 'Sign in to check GitHub credentials.' }, { status: 401 });
        }

        try {
          const { supabaseAdmin } = await import('@/integrations/supabase/client.server');
          const { data, error } = await supabaseAdmin
            .from('github_credentials')
            .select('updated_at')
            .eq('user_id', userId)
            .maybeSingle();

          return Response.json({
            connected: !error && Boolean(data),
            error: error ? 'Could not load GitHub connection.' : null,
          });
        } catch {
          return Response.json({ connected: false, error: 'Could not load credentials.' }, { status: 500 });
        }
      },

      POST: async ({ request }) => {
        let userId: string;
        try {
          const auth = await authenticateRequest(request);
          userId = auth.userId;
        } catch {
          return Response.json({ ok: false, error: 'Sign in to save GitHub credentials.' }, { status: 401 });
        }

        try {
          const body = await request.json().catch(() => ({}));
          const token = typeof body?.token === 'string' ? body.token.trim() : '';
          if (!token) {
            return Response.json({ ok: false, error: 'Enter a GitHub personal access token.' }, { status: 400 });
          }

          const { saveGithubToken } = await import('@/lib/atlas/github-credentials.server');
          const result = await saveGithubToken(userId, token);
          return Response.json(result);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : 'Could not save token.';
          return Response.json({ ok: false, error: msg }, { status: 500 });
        }
      },

      DELETE: async ({ request }) => {
        let userId: string;
        try {
          const auth = await authenticateRequest(request);
          userId = auth.userId;
        } catch {
          return Response.json({ ok: false, error: 'Sign in to remove GitHub credentials.' }, { status: 401 });
        }

        try {
          const { supabaseAdmin } = await import('@/integrations/supabase/client.server');
          const { error } = await supabaseAdmin
            .from('github_credentials')
            .delete()
            .eq('user_id', userId);

          return Response.json({ ok: !error, error: error ? 'Could not remove GitHub token.' : null });
        } catch {
          return Response.json({ ok: false, error: 'Could not remove token.' }, { status: 500 });
        }
      },
    },
  },
});
