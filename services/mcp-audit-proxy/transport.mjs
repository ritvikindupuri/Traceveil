import https from 'node:https';
import tls from 'node:tls';
import {lookup} from 'node:dns/promises';
import {chooseAddress,targetUrl,RESPONSE_LIMIT,DEADLINE_MS} from './policy.mjs';

export async function pinnedRequest(data,signal,resolve=lookup,request=https.request){
 const u=targetUrl(data.endpoint);
 const records=await resolve(u.hostname,{all:true,verbatim:true});
 if(signal.aborted)throw new Error('Cancelled');
 const pinned=chooseAddress(records);
 const payload=JSON.stringify(data.rpc);
 const headers={'host':u.host,'content-type':'application/json','accept':'application/json, text/event-stream','mcp-protocol-version':'2025-06-18','content-length':Buffer.byteLength(payload)};
 if(data.session)headers['mcp-session-id']=data.session;
 if(data.token)headers.authorization=`Bearer ${data.token}`;
 return new Promise((resolveResult,reject)=>{
  const req=request({hostname:pinned.address,family:pinned.family,port:443,path:u.pathname,method:'POST',headers,servername:u.hostname,rejectUnauthorized:true,checkServerIdentity:(_host,cert)=>tls.checkServerIdentity(u.hostname,cert),agent:false,signal},res=>{
   if([301,302,303,307,308].includes(res.statusCode)){res.destroy();reject(new Error('Redirect blocked'));return;}
   const chunks=[];let bytes=0;
   res.on('data',chunk=>{bytes+=chunk.length;if(bytes>RESPONSE_LIMIT){res.destroy(new Error('Response too large'));return;}chunks.push(chunk);});
   res.on('error',reject);
   res.on('end',()=>{
    const sid=res.headers['mcp-session-id'];
    if(sid&&(typeof sid!=='string'||sid.length>512||!/^[\x21-\x7e]+$/.test(sid))){reject(new Error('Invalid session'));return;}
    resolveResult({status:res.statusCode??502,contentType:String(res.headers['content-type']??'application/json'),session:sid??null,body:Buffer.concat(chunks).toString('utf8')});
   });
  });
  req.on('error',reject);
  req.setTimeout(DEADLINE_MS,()=>req.destroy(new Error('Deadline exceeded')));
  req.end(payload);
 });
}