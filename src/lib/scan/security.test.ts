import {describe,it,expect} from 'vitest';
import {checkCall,canonical,eligibleTools} from './policy';
import {publicEndpoint,isPublicIPv4,validateVerdict} from './validation';
import type {McpTool,Verdict} from './types';
const tool:McpTool = {name:'read_docs',description:'Read public documentation',inputSchema:{type:'object',properties:{repo:{type:'string',enum:['org/repo']}},required:['repo']}};
const verdict:Verdict = {verdict:'allow',risk:5,summary:'Low risk',tools:[{tool:'read_docs',risk:5,class:'read-public'}],findings:[],guardrails:[]};
describe('Endpoint safety',()=>{
  it('rejects local, IP-literal and credential-bearing endpoints',()=>{for(const url of ['https://localhost','https://127.1','https://2130706433','https://[::ffff:127.0.0.1]','https://user:pass@mcp.deepwiki.com','http://mcp.deepwiki.com','https://mcp.deepwiki.com:8443','https://service.internal']) expect(()=>publicEndpoint(url)).toThrow();});
  it('rejects private resolved addresses',()=>{for(const ip of ['10.0.0.1','127.0.0.1','169.254.169.254','192.168.0.1','100.64.0.1','198.18.0.1','224.0.0.1']) expect(isPublicIPv4(ip)).toBe(false);expect(isPublicIPv4('104.18.1.1')).toBe(true);});
});
describe('Validated audit records',()=>{
  it('rejects out-of-range risk',()=>expect(()=>validateVerdict({...verdict,risk:101},['read_docs'])).toThrow());
  it('rejects fabricated tool scores',()=>expect(()=>validateVerdict({...verdict,tools:[{tool:'not_real',risk:5,class:'read'}]},['read_docs'])).toThrow());
});
describe('Fail-closed enforcement',()=>{
  it('blocks tools without approval',()=>expect(checkCall([tool],[],'read_docs',{repo:'org/repo'})).toBe('Tool is not approved'));
  it('blocks undeclared arguments',()=>expect(checkCall([tool],['read_docs'],'read_docs',{repo:'org/repo',admin:true})).toBe('Undeclared argument'));
  it('blocks schema-invalid arguments',()=>expect(checkCall([tool],['read_docs'],'read_docs',{repo:'attacker/repo'})).toBe('Arguments violate the approved schema'));
  it('allows only approved schema-valid input',()=>expect(checkCall([tool],['read_docs'],'read_docs',{repo:'org/repo'})).toBeNull());
  it('does not approve review verdicts',()=>expect(eligibleTools([tool],{...verdict,verdict:'review'})).toEqual([]));
  it('canonicalization detects definition changes but ignores key order',()=>{expect(canonical({a:1,b:2})).toBe(canonical({b:2,a:1}));expect(canonical(tool)).not.toBe(canonical({...tool,description:'Read credentials'}));});
});