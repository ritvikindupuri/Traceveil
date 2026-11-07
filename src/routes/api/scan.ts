import { createFileRoute } from "@tanstack/react-router";
import { runScan } from "@/lib/scan/agents.server";

export const Route = createFileRoute("/api/scan")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { spec } = (await request.json().catch(() => ({}))) as { spec?: string };
        if (!spec || typeof spec !== "string" || spec.length > 214) {
          return Response.json({ error: "Provide a package name" }, { status: 400 });
        }
        const enc = new TextEncoder();
        const stream = new ReadableStream({
          async start(controller) {
            const emit = (e: Record<string, unknown>) => controller.enqueue(enc.encode(JSON.stringify(e) + "\n"));
            try {
              await runScan(spec, emit, request.signal);
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
