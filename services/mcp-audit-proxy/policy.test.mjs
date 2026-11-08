import {test} from 'node:test';
import assert from 'node:assert/strict';
import {publicAddress,chooseAddress,targetUrl,validateRequest} from './policy.mjs';
test('blocks private, reserved and transition addresses',()=>{
 for(const ip of ['127.0.0.1','10.0.0.1','169.254.169.254','100.64.0.1','192.0.2.1','198.18.0.1','224.0.0.1','::1','::ffff:8.8.8.8','64:ff9b::808:808','2001:db8::1','3fff::1','fec0::1','fc00::1','fe80::1'])assert.equal(publicAddress(ip),false,ip);
 assert.equal(publicAddress('8.8.8.8'),true);assert.equal(publicAddress('2606:4700:4700::1111'),true);
});
test('mixed DNS answers and empty sets fail closed',()=>{
 assert.throws(()=>chooseAddress([{address:'8.8.8.8',family:4},{address:'10.0.0.1',family:4}]));assert.throws(()=>chooseAddress([]));
});
test('rejects HTTP, alternate ports, credential URLs and encoded literal hosts',()=>{
 for(const url of ['http://github.com/mcp','https://github.com:8443/mcp','https://user:pass@github.com/mcp','https://2130706433/mcp','https://0x7f000001/mcp','https://[::1]/mcp','https://github.com/mcp#x','https://github.com/mcp?x=y'])assert.throws(()=>targetUrl(url));
});
test('never accepts tool execution or caller-chosen initialization capabilities',()=>{
 assert.throws(()=>validateRequest({endpoint:'https://github.com/mcp',rpc:{jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'run'}}}));
 assert.throws(()=>validateRequest({endpoint:'https://github.com/mcp',rpc:{jsonrpc:'2.0',id:1,method:'tools/list',params:{cursor:'x',url:'https://evil.com'}}}));
 assert.equal(validateRequest({endpoint:'https://github.com/mcp',rpc:{jsonrpc:'2.0',id:2,method:'tools/list',params:{}}}).rpc.method,'tools/list');
});