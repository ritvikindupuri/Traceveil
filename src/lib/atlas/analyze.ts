import type {AttackGraph,EntityKind} from './types';
import {redact,validateGraph} from './validation';
export type SourceFile = {path:string;text:string};
export function buildRepositoryGraph(target:string,commit:string,branch:string,files:SourceFile[],total:number,gaps:string[]):AttackGraph {
 const now=new Date().toISOString();
 const graph:AttackGraph={target,commit,branch,nodes:[],edges:[],evidence:[],findings:[],coverage:{inspected:files.length,total,skipped:Math.max(0,total-files.length),gaps},collectedAt:now};
 const evidence=(path:string,line:number,excerpt:string)=>{const id=`e${graph.evidence.length}`;graph.evidence.push({id,path,line,excerpt:redact(excerpt).slice(0,600),url:path ? `${target}/blob/${commit}/${path.split('/').map(encodeURIComponent).join('/')}#L${line}` : `${target}/commit/${commit}`,collectedAt:now});return id;};
 const rootEvidence=evidence('',1,`Repository snapshot ${commit}`);
 graph.nodes.push({id:'repo',label:target.replace('https://github.com/',''),kind:'repository',evidenceIds:[rootEvidence]});
 function add(id:string,label:string,kind:EntityKind,e:string,parent:string='repo',relation='declares') {
  if(!graph.nodes.some(n=>n.id===id))graph.nodes.push({id,label,kind,evidenceIds:[e]});
  graph.edges.push({id:`r${graph.edges.length}`,source:parent,target:id,label:relation,evidenceIds:[e],provenance:'declared'});
 }
 function finding(parent:string,path:string,line:number,excerpt:string,rule:string,title:string,fix:string,severity:'high'|'medium'|'low'='medium') {
  const e=evidence(path,line,excerpt),id=`f${graph.findings.length}`;
  graph.findings.push({id,title,severity,evidenceIds:[e],rule,fix});
  graph.nodes.push({id,label:title,kind:'finding',severity,evidenceIds:[e]});
  graph.edges.push({id:`r${graph.edges.length}`,source:parent,target:id,label:'has risk',evidenceIds:[e],provenance:'declared',risky:true});
 }
 for(const file of files) {
  const kind:EntityKind=file.path.startsWith('.github/workflows/')?'workflow':'file';
  const id=`file:${file.path}`,e=evidence(file.path,1,file.text.split('\n')[0]??'');add(id,file.path,kind,e);
  if(file.path.endsWith('package.json')) {
   try {const json=JSON.parse(file.text);for(const [name,version] of Object.entries({...json.dependencies,...json.devDependencies}).slice(0,45)) {
    if(typeof version!=='string')continue;const line=Math.max(1,file.text.split('\n').findIndex(l=>l.includes(`"${name}"`))+1);const ev=evidence(file.path,line,`${name}: ${version}`);add(`dep:${file.path}:${name}`,`${name} ${version}`,'dependency',ev,id,'depends on');
   }} catch {graph.coverage.gaps.push(`Unparsed manifest: ${file.path}`);}
  }
  const lines=file.text.split('\n');
  lines.forEach((text,i)=>{
   if(kind==='workflow'&&/uses:\s*[\w.-]+\/[\w./-]+@/.test(text)&& !/@[a-f0-9]{40}\b/i.test(text))finding(id,file.path,i+1,text,'mutable-action','Unpinned workflow action','Pin the action to a reviewed full commit SHA.');
   if(kind==='workflow'&&/permissions:\s*write-all\b/.test(text))finding(id,file.path,i+1,text,'workflow-write','Broad workflow write permission','Replace write-all with the minimum explicit permissions.','high');
   if(/privileged:\s*true\b/.test(text))finding(id,file.path,i+1,text,'privileged','Privileged container declared','Disable privileged mode and grant only required capabilities.','high');
   if(/(?:0\.0\.0\.0\/0|::\/0)/.test(text))finding(id,file.path,i+1,text,'public-cidr','Unrestricted network range declared','Restrict this range to the required callers; verify deployed exposure.');
   if(/^\s*USER\s+root\b/i.test(text)&&/Dockerfile/i.test(file.path))finding(id,file.path,i+1,text,'root-user','Root container user declared','Use a dedicated non-root user and verify file permissions.');
   if(/-----BEGIN [^-]*PRIVATE KEY-----/.test(text)||/\b(?:ghp_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16})\b/.test(text))finding(id,file.path,i+1,'[REDACTED credential pattern]','credential-pattern','Potential committed credential','Remove the credential, rotate it through its owner, and review history. Never test the credential.','high');
  });
 }
 return validateGraph(graph);
}
