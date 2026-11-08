import http from 'node:http';
import {timingSafeEqual} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {validateRequest,REQUEST_LIMIT,MAX_CONCURRENT,DEADLINE_MS} from './policy.mjs';
import {pinnedRequest} from './transport.mjs';

export function authorized(header,secret){
 if(!secret||secret.length<32||typeof header!=='string')return false;
 const expected=Buffer.from(`Bearer ${secret}`);const actual=Buffer.from(header);
 return actual.length===expected.length&&timingSafeEqual(actual,expected);
}
export function createRelay(secret,forward=pinnedRequest){
 let active=0;
 const server=http.createServer(async(req,res)=>{
  const reply=(status,value)=>{if(!res.destroyed){res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(value));}};
  // No permissive CORS and no unauthenticated operational metadata.
  if(!authorized(req.headers.authorization,secret)){reply(401,{error:'Relay authentication required'});req.resume();return;}
  if(req.method!=='POST'||req.url!=='/v1/audit-rpc'){reply(404,{error:'Unsupported relay operation'});req.resume();return;}
  if(active>=MAX_CONCURRENT){reply(429,{error:'Relay capacity reached'});req.resume();return;}
  if(req.headers['content-type']!=='application/json'){reply(400,{error:'JSON required'});req.resume();return;}
  active++;
  const abort=new AbortController();const timer=setTimeout(()=>abort.abort(),DEADLINE_MS);
  req.on('aborted',()=>abort.abort());res.on('close',()=>{if(!res.writableEnded)abort.abort();});
  try{
   const chunks=[];let bytes=0;
   for await(const chunk of req){bytes+=chunk.length;if(bytes>REQUEST_LIMIT){reply(413,{error:'Relay request too large'});req.destroy();return;}chunks.push(chunk);}
   let data;try{data=validateRequest(JSON.parse(Buffer.concat(chunks).toString('utf8')));}catch{reply(400,{error:'Invalid audit collection request'});return;}
   const result=await forward(data,abort.signal);
   reply(200,result);
  }catch{reply(abort.signal.aborted?504:502,{error:abort.signal.aborted?'Relay deadline exceeded':'Destination blocked or unavailable'});}
  finally{clearTimeout(timer);active--;}
 });
 server.requestTimeout=25_000;server.headersTimeout=10_000;server.maxHeadersCount=30;
 return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const secret=process.env.RELAY_SHARED_SECRET;
 if(!secret||secret.length<32)throw new Error('Relay shared credential is not configured');
 createRelay(secret).listen(8081,'127.0.0.1');
}