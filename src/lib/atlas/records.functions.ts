import {createServerFn} from '@tanstack/react-start';
import {requireSupabaseAuth} from '@/integrations/supabase/auth-middleware';

export const listApplicationScans = createServerFn({method:'GET'}).middleware([requireSupabaseAuth]).handler(async({context})=>{
  const {data,error}=await context.supabase.from('application_scans').select('*').eq('user_id',context.userId).order('created_at',{ascending:false}).limit(15);
  if(error)throw new Error('Could not load application scans');
  return data;
});

export const archiveApplicationScan = createServerFn({method:'POST'}).middleware([requireSupabaseAuth]).inputValidator((input: unknown) => input as { target: string; commit_sha: string; graph: unknown; reports: unknown }).handler(async({data,context})=>{
  const existing = await context.supabase
    .from('application_scans')
    .select('id')
    .eq('user_id', context.userId)
    .eq('commit_sha', data.commit_sha)
    .maybeSingle();

  if (!existing.data) {
    const {supabaseAdmin} = await import('@/integrations/supabase/client.server');
    await supabaseAdmin.from('application_scans').insert({
      user_id: context.userId,
      target: data.target,
      commit_sha: data.commit_sha,
      status: 'complete',
      graph: data.graph,
      reports: data.reports,
    });
  }
  return { ok: true };
});
