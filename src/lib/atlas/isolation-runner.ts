// Exported source runs only in customer-controlled CI, never in the web process.
export const ISOLATION_RUNNER=String.raw`
import {execFileSync} from 'node:child_process';
import {writeFileSync} from 'node:fs';
import http from 'node:http';
import https from 'node:https';
// CONFIG is inserted by Traceveil. Run against a disposable local app checkout.
const base=new URL(process.env.TRACEVEIL_BASE_URL||'http://127.0.0.1:3000');
if(!['http:','https:'].includes(base.protocol)||!['127.0.0.1','[::1]'].includes(base.hostname)||base.username||base.password||base.pathname!=='/'||base.search||base.hash)throw new Error('Only a numeric loopback origin is allowed');
if(Date.now()>Date.parse(CONFIG.expiresAt))throw new Error('Approval expired');
const commit=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
if(commit!==CONFIG.commit)throw new Error('Checkout does not match the approved commit');
if(execFileSync('git',['status','--porcelain'],{encoding:'utf8'}).trim())throw new Error('Checkout must be clean; keep runner and results outside the repository');
const fixtures=[process.env.TRACEVEIL_FIXTURE_A,process.env.TRACEVEIL_FIXTURE_B];
const tokens=[process.env.TRACEVEIL_TOKEN_A,process.env.TRACEVEIL_TOKEN_B];
if(fixtures.some(x=>!x||!/^[A-Za-z0-9_-]{1,120}$/.test(x))||fixtures[0]===fixtures[1]||tokens.some(x=>!x||/[\r\n]/.test(x))||tokens[0]===tokens[1])throw new Error('Two distinct synthetic identities and fixture IDs are required');
const pointer=(value)=>CONFIG.idPointer.slice(1).split('/').reduce((v,k)=>v&&typeof v==='object'?v[k]:undefined,value);
function read(identity,fixture,id){return new Promise(resolve=>{
 const url=new URL(CONFIG.endpoint.replace('{id}',encodeURIComponent(fixtures[fixture])),base);
 const finish=(status=0,matched=false,leaked=false,error=true)=>resolve({id,status,matched,leaked,error});
 const req=(url.protocol==='https:'?https:http).get(url,{headers:{Authorization:'Bearer '+tokens[identity],Accept:'application/json'},timeout:10000},res=>{
  let size=0;const chunks=[];
  res.on('data',chunk=>{size+=chunk.length;if(size>65536){res.destroy();req.destroy();}else chunks.push(chunk);});
  res.on('error',()=>finish());
  res.on('end',()=>{const text=Buffer.concat(chunks).toString('utf8');let value;try{value=JSON.parse(text);}catch{}
   const status=res.statusCode||0;const matched=String(pointer(value))===fixtures[fixture];
   // No response bodies, fixture IDs or tokens leave this runner.
   const leaked=id.endsWith('cross')&&text.includes(fixtures[fixture]);
   finish(status,matched,leaked,status===200&&!value);
  });
 });
 req.on('timeout',()=>req.destroy());req.on('error',()=>finish());
});}
const cases=[];
for(const [identity,fixture,id] of [[0,0,'a-own'],[1,1,'b-own'],[0,1,'a-cross'],[1,0,'b-cross']])cases.push(await read(identity,fixture,id));
const report={version:1,planId:CONFIG.planId,nonce:CONFIG.nonce,commit,suiteDigest:CONFIG.suiteDigest,cases};
writeFileSync(process.env.TRACEVEIL_RESULT_PATH||'/tmp/traceveil-isolation-result.json',JSON.stringify(report,null,2),{mode:0o600});
console.log('Four read-only checks completed. Import the redacted result in Traceveil.');
`;
export function runnerSource(config:{planId:string;nonce:string;commit:string;suiteDigest:string;endpoint:string;idPointer:string;expiresAt:string}) {
 return `const CONFIG=${JSON.stringify(config)};\n${ISOLATION_RUNNER}`;
}