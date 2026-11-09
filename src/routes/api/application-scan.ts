import {createFileRoute} from '@tanstack/react-router';

export const Route=createFileRoute('/api/application-scan')({server:{handlers:{POST:async({request})=>{
 const {authenticateRequest}=await import('@/lib/scan/auth.server');
 let userId:string;
 try{({userId}=await authenticateRequest(request));}
 catch{return Response.json({error:'Sign in to scan'},{status:401});}

 const {readBounded}=await import('@/lib/scan/http.server');
 const {applicationRequest}=await import('@/lib/atlas/validation');
 const parsed=await readBounded(request.body,2500).then(t=>applicationRequest.safeParse(JSON.parse(t))).catch(()=>null);
 if(!parsed?.success)return Response.json({error:'A repository or live application URL and consent are required'},{status:400});

 const targetUrl = parsed.data.url.trim();
 const isGithub = targetUrl.toLowerCase().includes('github.com');

 const {supabaseAdmin}=await import('@/integrations/supabase/client.server');
 const quota=await supabaseAdmin.rpc('consume_audit_quota',{p_user:userId});
 if(quota.error)return Response.json({error:'Scan service unavailable'},{status:503});
 if(!quota.data)return Response.json({error:'Scan limit reached. Try again in a minute.'},{status:429});

 const enc=new TextEncoder();
 let cancelled=false;
 const stream=new ReadableStream({
  async start(controller){
   const emit=(e:Record<string,unknown>)=>{if(!cancelled)controller.enqueue(enc.encode(JSON.stringify(e)+'\n'));};
   try{
    let graph;
    if(isGithub) {
     const {loadGithubToken}=await import('@/lib/atlas/github-credentials.server');
     const token=await loadGithubToken(userId).catch(()=>null);
     const {collectRepository}=await import('@/lib/atlas/github.server');
     graph=await collectRepository(targetUrl,parsed.data.ref,request.signal,message=>emit({type:'progress',message}),token);
    } else {
     const {collectLiveApplication}=await import('@/lib/atlas/live-scanner.server');
     graph=await collectLiveApplication(targetUrl,request.signal,message=>emit({type:'progress',message}));
    }
    emit({type:'graph',graph});

    const {data:record,error}=await supabaseAdmin.from('application_scans').insert({
     user_id:userId,
     target:graph.target,
     commit_sha:graph.commit,
     status:'analyzing',
     graph:JSON.parse(JSON.stringify(graph))
    }).select('id').single();

    if(error||!record)throw new Error('Evidence collected but could not be saved');
    emit({type:'record',id:record.id});

    try {
     const {analyzeGraph}=await import('@/lib/atlas/agents.server');
     const reports=await analyzeGraph(graph,request.signal,emit);
     const saved=await supabaseAdmin.from('application_scans').update({reports,status:'complete'}).eq('id',record.id).eq('user_id',userId);
     if(saved.error)throw new Error('Could not save agent reports');
     emit({type:'done'});
    } catch(agentError){
     await supabaseAdmin.from('application_scans').update({status:'partial'}).eq('id',record.id).eq('user_id',userId);
     throw agentError;
    }
   } catch(error){
    if(!request.signal.aborted)emit({type:'error',message:error instanceof Error?error.message:'Application scan failed'});
   } finally{
    if(!cancelled)controller.close();
   }
  },
  cancel(){
   cancelled=true;
  }
 });

 return new Response(stream,{headers:{'Content-Type':'application/x-ndjson','Cache-Control':'no-store'}});
}}}});
