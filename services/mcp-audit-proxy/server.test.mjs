import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRelay} from './server.mjs';
test('unauthenticated and tools/call requests never forward',async()=>{
 let calls=0;const server=createRelay('test-credential-not-used-in-production-32',async()=>{calls++;return {};});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
  const origin=`http://127.0.0.1:${server.address().port}`;
  const anonymous=await fetch(origin+'/v1/audit-rpc',{method:'POST'});assert.equal(anonymous.status,401);
  const rejected=await fetch(origin+'/v1/audit-rpc',{method:'POST',headers:{authorization:'Bearer test-credential-not-used-in-production-32','content-type':'application/json'},body:JSON.stringify({endpoint:'https://github.com/mcp',rpc:{jsonrpc:'2.0',id:1,method:'tools/call',params:{}}})});assert.equal(rejected.status,400);assert.equal(calls,0);
 }finally{await new Promise(r=>server.close(r));}
});