import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/scan")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const {authenticateRequest} = await import('@/lib/scan/auth.server');
        let userId: string;
        try { ({userId} = await authenticateRequest(request)); }
        catch { return Response.json({error:'Sign in to audit'},{status:401}); }
        const {scanRequestSchema} = await import('@/lib/scan/validation');
        const {readBounded} = await import('@/lib/scan/http.server');
        const parsed = await readBounded(request.body,450_000).then(text => scanRequestSchema.safeParse(JSON.parse(text))).catch(() => null);
        if (!parsed?.success) return Response.json({error:'Invalid or oversized audit input'},{status:400});
        const body = parsed.data;
        let token=body.token;
        try {
          if(body.connectionId) {
            if(body.mode!=='endpoint')throw new Error('Endpoint required');
            const {resolveConnection}=await import('@/lib/scan/connections.server');
            token=await resolveConnection(userId,body.connectionId,body.input);
          }
          if (body.mode === 'endpoint' && token) {
            // Token supported for any authenticated MCP endpoint
          }
        } catch {return Response.json({error:'Connection unavailable or disabled'},{status:400});}
        const {supabaseAdmin} = await import('@/integrations/supabase/client.server');
        const quota = await supabaseAdmin.rpc('consume_audit_quota',{p_user:userId});
        if (quota.error) return Response.json({error:'Audit service unavailable'},{status:503});
        if (!quota.data) return Response.json({error:'Audit limit reached. Try again in a minute.'},{status:429});
        const enc = new TextEncoder();
        const stream = new ReadableStream({
          async start(controller) {
            const emit = (e: Record<string, unknown>) => controller.enqueue(enc.encode(JSON.stringify(e) + "\n"));
            try {
              const {runScan} = await import('@/lib/scan/agents.server');
              const {fingerprint} = await import('@/lib/scan/policy');
               const result = await runScan(body.mode, body.input, emit, AbortSignal.any([request.signal,AbortSignal.timeout(180_000)]), token || undefined);
              const hash = await fingerprint(result.data.tools);
              const {data:previous} = body.mode === 'endpoint' ? await supabaseAdmin.from('audit_records').select('fingerprint').eq('user_id',userId).eq('endpoint',body.input).order('created_at',{ascending:false}).limit(1).maybeSingle() : {data:null};
               const {data:record,error} = await supabaseAdmin.from('audit_records').insert({user_id:userId,connection_id:body.connectionId ?? null,mode:body.mode,source:result.data.source,endpoint:body.mode === 'endpoint' ? body.input : null,fingerprint:hash,tools:JSON.parse(JSON.stringify(result.data.tools)),inventory:JSON.parse(JSON.stringify(result.inventory)),signals:JSON.parse(JSON.stringify(result.signals)),verdict:JSON.parse(JSON.stringify(result.verdict)),reports:result.reports,model:result.model}).select('id').single();
              if (error || !record) throw new Error('Audit completed but could not be saved');
              emit({type:'record',id:record.id,fingerprint:hash,changed:previous ? previous.fingerprint !== hash : null});
              emit({type:'done'});
            } catch (err: any) {
              const status = err?.statusCode ?? err?.status;
              let message = err?.message || 'Audit failed or timed out. Check the input and try again.';
              if (status === 401 || err?.message?.includes('401') || err?.message?.toLowerCase().includes('authentication')) {
                message = `Endpoint requires authentication (HTTP 401 Unauthorized). The MCP server at ${body.mode === 'endpoint' ? body.input : 'endpoint'} requires a Bearer token. Please provide your API key or Bearer token in the 'Bearer token' field.`;
              } else if (status === 403 || err?.message?.includes('403')) {
                message = 'Access forbidden (HTTP 403). The provided Bearer token does not have permission to inspect this MCP server.';
              } else if (status === 404 || err?.message?.includes('404')) {
                message = 'MCP endpoint not found (HTTP 404). Please verify the server URL and path (e.g. /mcp or /sse).';
              } else if (status === 402) {
                message = "AI credits exhausted. Add credits in Settings → Plans & credits.";
              } else if (status === 429) {
                message = "Rate limited. Try again shortly.";
              } else if (err?.name === 'TimeoutError' || err?.message?.toLowerCase().includes('timed out') || err?.message?.toLowerCase().includes('timeout')) {
                message = 'Audit timed out. The remote MCP server took longer than expected to respond.';
              }
              const {RelayError}=await import('@/lib/scan/relay.server');
              if(err instanceof RelayError)message=err.message;
              if (!request.signal.aborted) emit({ type: "error", message, status: status || (message.includes('401') ? 401 : undefined) });
            } finally {
              try { controller.close(); } catch {}
            }
          },
        });
        return new Response(stream, { headers: { "content-type": "application/x-ndjson", "cache-control": "no-store" } });
      },
    },
  },
});
