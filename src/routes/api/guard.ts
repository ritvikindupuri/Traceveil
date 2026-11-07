import {createFileRoute} from '@tanstack/react-router';
import {z} from 'zod';

export const Route = createFileRoute('/api/guard')({server:{handlers:{POST:async ({request}) => {
  const {authenticateRequest} = await import('@/lib/scan/auth.server');
  let auth: Awaited<ReturnType<typeof authenticateRequest>>;
  try { auth = await authenticateRequest(request); } catch { return Response.json({error:'Sign in to continue'},{status:401}); }
  const {readBounded} = await import('@/lib/scan/http.server');
  const parsed = await readBounded(request.body,25_000).then(text => z.object({auditId:z.string().uuid(),name:z.string().min(1).max(256),arguments:z.record(z.unknown()),token:z.string().max(4096).optional()}).strict().safeParse(JSON.parse(text))).catch(() => null);
  if (!parsed?.success) return Response.json({error:'Invalid call'},{status:400});
  const body = parsed.data;
  const record = await auth.client.from('audit_records').select('*').eq('id',body.auditId).eq('user_id',auth.userId).single();
  if (record.error || !record.data?.endpoint) return Response.json({error:'Endpoint audit not found'},{status:404});
  const approval = await auth.client.from('tool_approvals').select('tools').eq('audit_id',body.auditId).eq('user_id',auth.userId).maybeSingle();
  const {supabaseAdmin} = await import('@/integrations/supabase/client.server');
  const quota = await supabaseAdmin.rpc('consume_audit_quota',{p_user:auth.userId});
  if (quota.error || !quota.data) return Response.json({error:'Call limit reached'},{status:429});
  const log = async (decision:'blocked'|'forwarded'|'failed',reason:string) => {
    const {error} = await supabaseAdmin.from('enforcement_events').insert({user_id:auth.userId,audit_id:body.auditId,tool:body.name,decision,reason});
    if (error) throw new Error('Event could not be recorded');
  };
  try {
    const {checkCall,fingerprint} = await import('@/lib/scan/policy');
    const {fetchEndpoint,rpc} = await import('@/lib/scan/ingest.server');
    const reason = checkCall(record.data.tools as unknown as import('@/lib/scan/types').McpTool[],approval.data?.tools ?? [],body.name,body.arguments);
    if (reason) {await log('blocked',reason); return Response.json({decision:'blocked',reason},{status:403});}
    // Until destination-IP-pinned egress is available, execution is restricted to this trusted public read-only MCP host.
    if (new URL(record.data.endpoint).hostname !== 'mcp.deepwiki.com') {
      const reason = 'Execution for this host requires destination-pinned egress; call blocked';
      await log('blocked',reason); return Response.json({decision:'blocked',reason},{status:403});
    }
    const signal = AbortSignal.any([request.signal,AbortSignal.timeout(60_000)]);
    const live = await fetchEndpoint(record.data.endpoint,signal,body.token);
    if (await fingerprint(live.tools) !== record.data.fingerprint) {
      await log('blocked','Tool definitions changed since approval');
      return Response.json({decision:'blocked',reason:'Tool definitions changed since approval'},{status:409});
    }
    await log('forwarded','Approved schema and unchanged baseline; dispatch authorized');
    const result = await rpc(new URL(record.data.endpoint),{jsonrpc:'2.0',id:50,method:'tools/call',params:{name:body.name,arguments:body.arguments}},live.sid,signal,body.token);
    return Response.json({decision:'forwarded',result:result.msg?.result ?? null},{headers:{'cache-control':'no-store'}});
  } catch {
    await log('failed','Upstream verification or execution failed');
    return Response.json({decision:'failed',reason:'Upstream verification or execution failed'},{status:502});
  }
}}}});