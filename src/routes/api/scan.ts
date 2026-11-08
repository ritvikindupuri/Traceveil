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
          const {trustedDestination}=await import('@/lib/scan/destinations');
          if(body.mode==='endpoint'&&token&&!trustedDestination(body.input)?.auth)throw new Error('Credentials not supported for this endpoint');
        } catch {return Response.json({error:'Connection unavailable, disabled or credentials unsupported'},{status:400});}
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
              let message = 'Audit failed or timed out. Check the input and try again.';
              if (status === 402) message = "AI credits exhausted. Add credits in Settings → Plans & credits.";
              if (status === 429) message = "Rate limited. Try again shortly.";
              const {RelayError}=await import('@/lib/scan/relay.server');
              if(err instanceof RelayError)message=err.message;
              if (!request.signal.aborted) emit({ type: "error", message });
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
