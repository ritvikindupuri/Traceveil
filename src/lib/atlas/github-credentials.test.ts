import {describe,it,expect,vi,afterEach} from 'vitest';
import {encryptToken,decryptToken} from '@/lib/scan/token-crypto.server';
import {githubBinding,validGithubToken,saveGithubToken} from './github-credentials.server';
describe('private GitHub credential rules',()=>{
 afterEach(()=>{vi.unstubAllEnvs();vi.unstubAllGlobals();});
 it('binds encrypted tokens to the authenticated owner and provider',async()=>{
  vi.stubEnv('MCP_TOKEN_ENCRYPTION_SECRET','test-only-encryption-key');
  const plaintext='test-credential-not-real';
  const encrypted=await encryptToken(plaintext,githubBinding('owner-a'));
  expect(encrypted).not.toContain(plaintext);
  expect(await decryptToken(encrypted,githubBinding('owner-a'))===plaintext).toBe(true);
  await expect(decryptToken(encrypted,githubBinding('owner-b'))).rejects.toThrow();
  await expect(decryptToken(encrypted,'owner-a:https://other.example')).rejects.toThrow();
 });
 it('rejects non-PAT input before sending any credential',async()=>{
  const fetchMock=vi.fn();vi.stubGlobal('fetch',fetchMock);
  expect(validGithubToken('not-a-pat')).toBe(false);
  expect((await saveGithubToken('owner-a','not-a-pat')).ok).toBe(false);
  expect(fetchMock).not.toHaveBeenCalled();
 });
 it('validates only on fixed GitHub HTTPS and prevents redirect credential forwarding',async()=>{
  const fetchMock=vi.fn(async(_url:string,_init:RequestInit)=>new Response(null,{status:401}));vi.stubGlobal('fetch',fetchMock);
  const result=await saveGithubToken('owner-a','github_pat_'+'x'.repeat(30));
  expect(fetchMock.mock.calls[0]?.[0]).toBe('https://api.github.com/user');
  expect(fetchMock.mock.calls[0]?.[1].redirect).toBe('error');
  expect(result.ok).toBe(false);
  expect(Object.keys(result).sort()).toEqual(['error','ok']);
 });
 it('does not propagate credential-bearing transport errors',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>{throw new Error('sensitive transport detail');}));
  const result=await saveGithubToken('owner-a','github_pat_'+'x'.repeat(30));
  expect(result.ok).toBe(false);
  expect(result.error).not.toContain('sensitive transport detail');
 });
});