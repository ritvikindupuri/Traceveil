import {describe,it,expect} from 'vitest';
import {githubFailure} from './github-errors';
describe('GitHub failure classification',()=>{
 it('recognizes an exhausted provider quota and its reset time',()=>{
  const message=githubFailure(403,new Headers({'x-ratelimit-remaining':'0','x-ratelimit-reset':'1794104068'}));
  expect(message).toContain('02:14 UTC');
  expect(message).toContain('unauthenticated request limit');
 });
 it('does not classify an unrelated access denial as quota exhaustion',()=>{
  expect(githubFailure(403,new Headers())).toContain('denied repository access');
  expect(githubFailure(403,new Headers())).not.toContain('limit is exhausted');
 });
});