import {createFileRoute} from '@tanstack/react-router';
export const Route=createFileRoute('/api/application-scan')({server:{handlers:{POST:async({request})=>{
 const {authenticateRequest}=await import('@/lib/scan/auth.server');
 let userId:string;try{({userId}=await authenticateRequest(request));}catch{return Response.json({error:'Sign in to scan'},{status:401});}
 const {readBounded}=await import('@/lib/scan/http.server');const {applicationRequest,repositoryTarget}=await import('@/lib/atlas/validation');
 const parsed=await readBounded(request.body,2500).then(t=>applicationRequest.safeParse(JSON.parse(t))).catch(()=>null);
 if(!parsed?.success)return Response.json({error:'A repository URL and AI processing consent are required'},{status:400});
 try{repositoryTarget(parsed.data.url);}catch{return Response.json({error:'Live application collection requires secure outbound infrastructure. Use a public GitHub repository for now.'},{status:400});}
 const enc=new TextEncoder();let cancelled=false;
 const stream=new ReadableStream({async start(controller){const emit=(e:Record<string,unknown>)=>{if(!cancelled)controller.enqueue(enc.encode(JSON.stringify(e)+'\n'));};
 try{
  const {collectRepository}=await import('@/lib/atlas/github.server');const graph=await collectRepository(parsed.data.url,parsed.data.ref,request.signal,message=>emit({type:'progress',message}));emit({type:'graph',graph});
  const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
  const {data:record,error}=await supabaseAdmin.from('application_scans').insert({user_id:userId,target:graph.target,commit_sha:graph.commit,status:'analyzing',graph:JSON.parse(JSON.stringify(graph))}).select('id').single();
  if(error||!record)throw new Error('Evidence collected but could not be saved');emit({type:'record',id:record.id});
  try {const {analyzeGraph}=await import('@/lib/atlas/agents.server');const reports=await analyzeGraph(graph,request.signal,emit);const saved=await supabaseAdmin.from('application_scans').update({reports,status:'complete'}).eq('id',record.id).eq('user_id',userId);if(saved.error)throw new Error('Could not save agent reports');emit({type:'done'});}
  catch(error){await supabaseAdmin.from('application_scans').update({status:'partial'}).eq('id',record.id).eq('user_id',userId);throw error;}
 }catch(error){if(!request.signal.aborted)emit({type:'error',message:error instanceof Error?error.message:'Application scan failed'});}finally{if(!cancelled)controller.close();}},cancel(){cancelled=true;}});
 return new Response(stream,{headers:{'Content-Type':'application/x-ndjson','Cache-Control':'no-store'}});
}}});
