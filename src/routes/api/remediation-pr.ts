import { createFileRoute } from '@tanstack/react-router';
import { runRemediationAgent } from '@/lib/atlas/remediation.server';

export const Route = createFileRoute('/api/remediation-pr')({
  server: {
    handlers: {
      POST: async ({ request }) => {
        let userId: string | undefined;
        try {
          const { authenticateRequest } = await import('@/lib/scan/auth.server');
          const auth = await authenticateRequest(request);
          userId = auth.userId;
        } catch {
          // Unauthenticated or anonymous live session
        }

        try {
          const body = await request.json().catch(() => ({}));
          if (!body || !body.repoUrl || !body.patchId) {
            return Response.json(
              { error: 'Repository URL and patch ID are required.' },
              { status: 400 }
            );
          }

          const result = await runRemediationAgent({
            repoUrl: String(body.repoUrl),
            patchId: String(body.patchId),
            title: String(body.title || 'Security Remediation'),
            filePath: String(body.filePath || 'src/index.ts'),
            line: Number(body.line || 1),
            diff: String(body.diff || ''),
            remediatedCode: String(body.remediatedCode || ''),
            customToken: body.customToken ? String(body.customToken) : undefined,
            userId,
          });

          return Response.json(result, { status: 200 });
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : 'Internal remediation agent error';
          return Response.json({ error: message }, { status: 500 });
        }
      },
    },
  },
});
