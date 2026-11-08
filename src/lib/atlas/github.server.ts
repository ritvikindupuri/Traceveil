import {repositoryTarget} from './validation';
import {buildRepositoryGraph} from './analyze';
import {readBounded} from '@/lib/scan/http.server';
import {githubFailure} from './github-errors';
async function github(path:string,signal:AbortSignal) {
 const response=await fetch(`https://api.github.com${path}`,{headers:{Accept:'application/vnd.github+json','User-Agent':'Traceveil'},redirect:'error',signal});
 if(!response.ok)throw new Error(githubFailure(response.status,response.headers));
 return JSON.parse(await readBounded(response.body,5_000_000));
}
export async function collectRepository(raw:string,ref:string,signal:AbortSignal,progress:(message:string)=>void) {
 const target=repositoryTarget(raw),base=`/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}`;
 progress('Resolving repository snapshot');
 const metadata=await github(base,signal);if(metadata.private)throw new Error('Private repositories require your own GitHub connection');
 const branch=ref||metadata.default_branch;
 const snapshot=await github(`${base}/commits/${encodeURIComponent(branch)}`,signal);
 if(typeof snapshot.sha!=='string'||!/^[a-f0-9]{40}$/.test(snapshot.sha))throw new Error('Invalid repository snapshot');
 const tree=await github(`${base}/git/trees/${snapshot.sha}?recursive=1`,signal);
 if(!Array.isArray(tree.tree))throw new Error('GitHub inventory unavailable');
 const blobs=tree.tree.filter((f:{type:string})=>f.type==='blob');
 const supported=blobs.filter((f:{path:string;size:number})=>f.size<=100_000&&/(?:package(?:-lock)?\.json|Dockerfile[^/]*|\.github\/workflows\/[^/]+\.ya?ml|\.(?:tf|ya?ml|tsx?|jsx?|py|go))$/.test(f.path)&&!/(?:^|\/)(?:node_modules|vendor|dist|build|package-lock\.json)(?:\/|$)/.test(f.path));
 const prioritized=supported.sort((a:{path:string},b:{path:string})=>Number(!/(package.json|Dockerfile|workflows|\.tf$)/.test(a.path))-Number(!/(package.json|Dockerfile|workflows|\.tf$)/.test(b.path))).slice(0,24);
 const files=[];const gaps=['Static declarations only; deployment, reachability and exploitability are not verified.','No dependency advisory matching yet; manifest versions are declarations, not resolved vulnerability evidence.','Bounded inspection: up to 24 supported files, 100 KB per file; dynamic routing and full data flow are not analyzed.'];
 if(tree.truncated)gaps.push('GitHub tree was truncated; total file count is a lower bound.');
 for(const file of prioritized) {
  if(!/^[a-f0-9]{40}$/.test(file.sha))continue;
  progress(`Inspecting ${file.path}`);
  const blob=await github(`${base}/git/blobs/${file.sha}`,signal);
  if(blob.encoding!=='base64'||typeof blob.content!=='string'){gaps.push(`Unsupported encoding: ${file.path}`);continue;}
  const binary=atob(blob.content.replace(/\s/g,''));const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
  files.push({path:file.path,text:new TextDecoder().decode(bytes)});
 }
 return buildRepositoryGraph(target.url,snapshot.sha,branch,files,blobs.length,gaps);
}
