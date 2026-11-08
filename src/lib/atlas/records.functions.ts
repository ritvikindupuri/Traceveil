import {createServerFn} from '@tanstack/react-start';
import {requireSupabaseAuth} from '@/integrations/supabase/auth-middleware';
export const listApplicationScans=createServerFn({method:'GET'}).middleware([requireSupabaseAuth]).handler(async({context})=>{
 const {data,error}=await context.supabase.from('application_scans').select('*').eq('user_id',context.userId).order('created_at',{ascending:false}).limit(15);
 if(error)throw new Error('Could not load application scans');return data;
});
