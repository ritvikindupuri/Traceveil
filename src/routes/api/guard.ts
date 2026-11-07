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
  if (approval.error) return Response.json({error:'Approval verification failed'},{status:503});
  const {supabaseAdmin} = await import('@/integrations/supabase/client.server');
  const quota = await supabaseAdmin.rpc('consume_audit_quota',{p_user:auth.userId});
  if (quota.error || !quota.data) return Response.json({error:'Call limit reached'},{status:429});
  const log = async (decision:'blocked'|'forwarded'|'failed',reason:string) => {
    const {error} = await supabaseAdmin.from('enforcement_events').insert({user_id:auth.userId,audit_id:body.auditId,tool:body.name,decision,reason});
    if (error) throw new Error('Event could not be recorded');
  };
  try {
    const {checkCall,fingerprint,runtimeDestinationAllowed,eligibleTools} = await import('@/lib/scan/policy');
    const {validateVerdict}=await import('@/lib/scan/validation');
    const {fetchEndpoint,rpc} = await import('@/lib/scan/ingest.server');
    const tools=record.data.tools as unknown as import('@/lib/scan/types').McpTool[];
    const eligible=eligibleTools(tools,validateVerdict(record.data.verdict,tools.map(t=>t.name)));
    const reason = checkCall(tools,(approval.data?.tools ?? []).filter(name=>eligible.includes(name)),body.name,body.arguments);
    if (reason) {await log('blocked',reason); return Response.json({decision:'blocked',reason},{status:403});}
    // Until destination-IP-pinned egress is available, execution is restricted to this trusted public read-only MCP host.
    if (!runtimeDestinationAllowed(record.data.endpoint,body.name)) {
      const reason = 'Execution for this host requires destination-pinned egress; call blocked';
      await log('blocked',reason); return Response.json({decision:'blocked',reason},{status:403});
    }
    const signal = AbortSignal.any([request.signal,AbortSignal.timeout(60_000)]);
    let token=body.token;
    if(record.data.connection_id){
      const {resolveConnection}=await import('@/lib/scan/connections.server');
      token=await resolveConnection(auth.userId,record.data.connection_id,record.data.endpoint);
    }
    const {trustedDestination}=await import('@/lib/scan/destinations');
    if(token&&!trustedDestination(record.data.endpoint)?.auth){await log('blocked','Credentials unsupported for this endpoint');return Response.json({decision:'blocked',reason:'Credentials unsupported for this endpoint'},{status:403});}
    const live = await fetchEndpoint(record.data.endpoint,signal,token);
    if (await fingerprint(live.tools) !== record.data.fingerprint) {
      await log('blocked','Tool definitions changed since approval');
      return Response.json({decision:'blocked',reason:'Tool definitions changed since approval'},{status:409});
    }
    const currentApproval=await auth.client.from('tool_approvals').select('tools').eq('audit_id',body.auditId).eq('user_id',auth.userId).maybeSingle();
    if(currentApproval.error||!currentApproval.data?.tools.includes(body.name)){await log('blocked','Approval revoked');return Response.json({decision:'blocked',reason:'Approval revoked'},{status:403});}
    const result = await rpc(new URL(record.data.endpoint),{jsonrpc:'2.0',id:50,method:'tools/call',params:{name:body.name,arguments:body.arguments}},live.sid,signal,token);
    if (!result.msg?.result) throw new Error('No upstream result');
    if(result.msg.result.isError)throw new Error('Upstream tool error');
    await log('forwarded','Approved schema and unchanged baseline; upstream responded');
    return Response.json({decision:'forwarded',result:result.msg?.result ?? null},{headers:{'cache-control':'no-store'}});
  } catch {
    await log('failed','Upstream verification or execution failed');
    return Response.json({decision:'failed',reason:'Upstream verification or execution failed'},{status:502});
  }
}}}});