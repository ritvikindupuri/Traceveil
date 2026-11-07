import {createServerFn} from '@tanstack/react-start';
import {requireSupabaseAuth} from '@/integrations/supabase/auth-middleware';
import {z} from 'zod';

export const listAudits = createServerFn({method:'GET'}).middleware([requireSupabaseAuth]).handler(async ({context}) => {
  const {data,error} = await context.supabase.from('audit_records').select('id,created_at,source,mode,fingerprint,inventory,signals,verdict,reports,endpoint').eq('user_id',context.userId).order('created_at',{ascending:false}).limit(50);
  if (error) throw new Error('Could not load audit records');
  return data;
});

export const approveAudit = createServerFn({method:'POST'}).middleware([requireSupabaseAuth]).inputValidator((value:unknown) => z.object({id:z.string().uuid()}).parse(value)).handler(async ({context,data}) => {
  const {data:record,error} = await context.supabase.from('audit_records').select('*').eq('id',data.id).eq('user_id',context.userId).single();
  if (error || !record || !record.endpoint) throw new Error('A live endpoint audit is required');
  const {eligibleTools} = await import('./policy');
  const {validateVerdict} = await import('./validation');
  const tools = record.tools as unknown as import('./types').McpTool[];
  const names = eligibleTools(tools,validateVerdict(record.verdict,tools.map(t => t.name)));
  if (!names.length) throw new Error('No low-risk tools are eligible for approval');
  const {supabaseAdmin} = await import('@/integrations/supabase/client.server');
  const saved = await supabaseAdmin.from('tool_approvals').upsert({audit_id:record.id,user_id:context.userId,tools:names});
  if (saved.error) throw new Error('Approval could not be saved');
  return {tools:names};
});

export const revokeApproval = createServerFn({method:'POST'}).middleware([requireSupabaseAuth]).inputValidator((value:unknown) => z.object({id:z.string().uuid()}).parse(value)).handler(async ({context,data}) => {
  const {data:owned} = await context.supabase.from('tool_approvals').select('audit_id').eq('audit_id',data.id).eq('user_id',context.userId).maybeSingle();
  if (!owned) return {ok:true};
  const {supabaseAdmin} = await import('@/integrations/supabase/client.server');
  const {error} = await supabaseAdmin.from('tool_approvals').delete().eq('audit_id',owned.audit_id).eq('user_id',context.userId);
  if (error) throw new Error('Could not revoke approval');
  return {ok:true};
});

export const getEnforcement = createServerFn({method:'GET'}).middleware([requireSupabaseAuth]).inputValidator((value:unknown) => z.object({id:z.string().uuid()}).parse(value)).handler(async ({context,data}) => {
  const approval = await context.supabase.from('tool_approvals').select('tools').eq('audit_id',data.id).eq('user_id',context.userId).maybeSingle();
  const events = await context.supabase.from('enforcement_events').select('id,created_at,tool,decision,reason').eq('audit_id',data.id).eq('user_id',context.userId).order('created_at',{ascending:false}).limit(20);
  if (approval.error || events.error) throw new Error('Could not load enforcement history');
  return {tools:approval.data?.tools ?? [], events:events.data ?? []};
});