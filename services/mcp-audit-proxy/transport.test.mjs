import {test} from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {Readable} from 'node:stream';
import {pinnedRequest} from './transport.mjs';
const data={endpoint:'https://github.com/mcp',rpc:{jsonrpc:'2.0',id:2,method:'tools/list',params:{}},session:null};
function fakeRequest(status,body,optionsOut){return(options,callback)=>{
 optionsOut.push(options);const req=new EventEmitter();req.setTimeout=()=>{};req.end=()=>{const res=Readable.from([Buffer.from(body)]);res.statusCode=status;res.headers={};callback(res);};return req;
};}
test('socket uses the immutable resolved address while TLS verifies original host',async()=>{
 const options=[];let resolves=0;
 await pinnedRequest(data,new AbortController().signal,async()=>{resolves++;return [{address:'8.8.8.8',family:4}];},fakeRequest(200,'{}',options));
 assert.equal(resolves,1);assert.equal(options[0].hostname,'8.8.8.8');assert.equal(options[0].servername,'github.com');assert.equal(options[0].headers.host,'github.com');assert.equal(options[0].agent,false);assert.equal(options[0].rejectUnauthorized,true);
 assert.ok(options[0].checkServerIdentity('8.8.8.8',{subject:{CN:'evil.com'}}) instanceof Error);
});
test('blocks redirects without another request',async()=>{const options=[];await assert.rejects(pinnedRequest(data,new AbortController().signal,async()=>[{address:'8.8.8.8',family:4}],fakeRequest(302,'',options)),/Redirect blocked/);assert.equal(options.length,1);});
test('rejects oversized upstream responses',async()=>{await assert.rejects(pinnedRequest(data,new AbortController().signal,async()=>[{address:'8.8.8.8',family:4}],fakeRequest(200,'x'.repeat(1_000_001),[])),/Response too large/);});
test('rebinding to private DNS answers never opens a socket',async()=>{let calls=0;await assert.rejects(pinnedRequest(data,new AbortController().signal,async()=>[{address:'127.0.0.1',family:4}],()=>{calls++;}),/Destination blocked/);assert.equal(calls,0);});