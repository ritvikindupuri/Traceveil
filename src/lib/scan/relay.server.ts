import {z} from 'zod';

const resultSchema=z.object({status:z.number().int().min(200).max(599),contentType:z.string().max(256),session:z.string().max(512).nullable(),body:z.string().max(1_000_000)}).strict();
export class RelayError extends Error {}

// Call only within a server request. The explicit verification switch is set
// after deployed end-to-end checks, not automatically when credentials exist.
export function relayConfigured(){return process.env['MCP_AUDIT_RELAY_VERIFIED']==='true'&&Boolean(process.env['MCP_AUDIT_RELAY_URL']&&process.env['MCP_AUDIT_RELAY_SECRET']);}
export async function relayFetch(endpoint:string,init:RequestInit):Promise<Response>{
 if(!relayConfigured())throw new RelayError('Custom MCP audits require a deployed and verified secure proxy.');
 const base=process.env['MCP_AUDIT_RELAY_URL'];const secret=process.env['MCP_AUDIT_RELAY_SECRET'];
 if(!base||!secret)throw new RelayError('Secure audit proxy is unavailable.');
 const url=new URL(base);
 if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||url.pathname!=='/v1/audit-rpc')throw new RelayError('Secure audit proxy configuration is invalid.');
 const headers=new Headers(init.headers);
 let rpc:unknown;try{rpc=JSON.parse(String(init.body));}catch{throw new RelayError('Invalid audit collection request.');}
 const method=rpc&&typeof rpc==='object'&&'method' in rpc?rpc.method:null;
 if(init.method!=='POST'||!['initialize','notifications/initialized','tools/list'].includes(String(method)))throw new RelayError('Secure proxy permits inventory collection only.');
 const authorization=headers.get('authorization');
 const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${secret}`},body:JSON.stringify({endpoint,rpc,session:headers.get('mcp-session-id'),token:authorization?.startsWith('Bearer ')?authorization.slice(7):undefined}),signal:init.signal??null,redirect:'manual'});
 if(!response.ok){await response.body?.cancel();throw new RelayError(response.status===429?'Secure audit proxy is busy. Try again shortly.':'Secure audit proxy rejected the request or is unavailable.');}
 // Bound the relay envelope before parsing. Never reflect arbitrary provider text.
 if(!response.body)throw new RelayError('Secure audit proxy returned no result.');
 const reader=response.body.getReader();let size=0;const parts:Uint8Array[]=[];
 try{for(;;){const r=await reader.read();if(r.done)break;size+=r.value.byteLength;if(size>6_100_000){await reader.cancel();throw new RelayError('Secure audit proxy result exceeds limits.');}parts.push(r.value);}}finally{reader.releaseLock();}
 const bytes=new Uint8Array(size);let offset=0;for(const p of parts){bytes.set(p,offset);offset+=p.length;}
 const parsed=resultSchema.safeParse(JSON.parse(new TextDecoder().decode(bytes)));
 if(!parsed.success)throw new RelayError('Secure audit proxy returned an invalid result.');
 const result=parsed.data;const out=new Headers({'content-type':result.contentType});if(result.session)out.set('mcp-session-id',result.session);
 return new Response([204,205,304].includes(result.status)?null:result.body,{status:result.status,headers:out});
}