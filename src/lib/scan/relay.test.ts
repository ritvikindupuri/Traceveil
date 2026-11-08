import {describe,it,expect,vi,afterEach} from 'vitest';
import {relayFetch} from './relay.server';
describe('Custom audit relay boundary',()=>{
 afterEach(()=>{vi.unstubAllEnvs();vi.unstubAllGlobals();});
 it('fails closed without verified deployment and never fetches the custom host',async()=>{
  vi.stubEnv('MCP_AUDIT_RELAY_VERIFIED','false');const request=vi.fn();vi.stubGlobal('fetch',request);
  await expect(relayFetch('https://custom.example.org/mcp',{method:'POST'})).rejects.toThrow('deployed and verified');expect(request).not.toHaveBeenCalled();
 });
 it('rejects runtime execution even with relay configuration',async()=>{
  vi.stubEnv('MCP_AUDIT_RELAY_VERIFIED','true');vi.stubEnv('MCP_AUDIT_RELAY_URL','https://relay.example.org/v1/audit-rpc');vi.stubEnv('MCP_AUDIT_RELAY_SECRET','test-only');const request=vi.fn();vi.stubGlobal('fetch',request);
  await expect(relayFetch('https://custom.example.org/mcp',{method:'POST',body:JSON.stringify({method:'tools/call'})})).rejects.toThrow('inventory collection only');expect(request).not.toHaveBeenCalled();
 });
});