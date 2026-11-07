import { createFileRoute } from "@tanstack/react-router";
import { runScan } from "@/lib/scan/agents.server";
import type { Mode } from "@/lib/scan/types";

const MODES: Mode[] = ["definitions", "transcript", "endpoint"];

export const Route = createFileRoute("/api/scan")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const body = (await request.json().catch(() => ({}))) as { mode?: Mode; input?: string; token?: string };
        if (!body.mode || !MODES.includes(body.mode) || typeof body.input !== "string" || !body.input.trim()) {
          return Response.json({ error: "Provide input" }, { status: 400 });
        }
        const enc = new TextEncoder();
        const stream = new ReadableStream({
          async start(controller) {
            const emit = (e: Record<string, unknown>) => controller.enqueue(enc.encode(JSON.stringify(e) + "\n"));
            try {
              await runScan(body.mode!, body.input!, emit, request.signal, body.token || undefined);
            } catch (err: any) {
              const status = err?.statusCode ?? err?.status;
              let message = err?.message ?? "Scan failed";
              if (status === 402) message = "AI credits exhausted. Add credits in Settings → Plans & credits.";
              if (status === 429) message = "Rate limited. Try again shortly.";
              if (!request.signal.aborted) emit({ type: "error", message });
            } finally {
              try { controller.close(); } catch {}
            }
          },
        });
        return new Response(stream, { headers: { "content-type": "application/x-ndjson", "cache-control": "no-cache" } });
      },
    },
  },
});
