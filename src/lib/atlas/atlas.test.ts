import {describe,it,expect} from 'vitest';
import {repositoryTarget,redact,validateGraph} from './validation';
import {buildRepositoryGraph} from './analyze';
describe('Repository evidence security',()=>{
 it('allows only canonical public GitHub repository targets',()=>{expect(repositoryTarget('https://github.com/octocat/Hello-World').repo).toBe('Hello-World');for(const url of ['https://evil.com/org/repo','https://github.com@evil.com/org/repo','http://github.com/org/repo','https://github.com/org/repo?x=1','https://github.com/org/repo/tree/main'])expect(()=>repositoryTarget(url)).toThrow();});
 it('redacts credential values',()=>{expect(redact('password="supersecret"')).not.toContain('supersecret');expect(redact('AKIAABCDEFGHIJKLMNOP')).toBe('[REDACTED TOKEN]');});
 it('does not invent resources or findings from empty evidence',()=>{const g=buildRepositoryGraph('https://github.com/o/r','a'.repeat(40),'main',[],0,[]);expect(g.nodes.map(n=>n.kind)).toEqual(['repository']);expect(g.findings).toEqual([]);expect(g.edges).toEqual([]);});
 it('links workflow risk to concrete source evidence',()=>{const g=buildRepositoryGraph('https://github.com/o/r','a'.repeat(40),'main',[{path:'.github/workflows/ci.yml',text:'permissions: write-all\nuses: actions/checkout@v4'}],1,[]);expect(g.findings.find(f=>f.rule==='workflow-write')?.severity).toBe('high');expect(g.evidence.some(e=>e.line===2&&e.excerpt==='uses: actions/checkout@v4')).toBe(true);expect(validateGraph(g)).toBe(g);});
 it('rejects edges to unknown resources',()=>{const g=buildRepositoryGraph('https://github.com/o/r','a'.repeat(40),'main',[],0,[]);g.edges.push({id:'bad',source:'repo',target:'invented',label:'access',evidenceIds:['e0'],provenance:'inferred'});expect(()=>validateGraph(g)).toThrow('Unknown graph entity');});
});
