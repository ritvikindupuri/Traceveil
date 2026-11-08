export function githubFailure(status:number,headers:Headers):string {
 if((status===403||status===429)&&headers.get('x-ratelimit-remaining')==='0') {
  const reset=Number(headers.get('x-ratelimit-reset'));
  const time=Number.isFinite(reset)&&reset>0?new Date(reset*1000).toISOString().slice(11,16):null;
  return `GitHub's unauthenticated request limit is exhausted.${time?` Try again after ${time} UTC.`:' Try again after the rate limit resets.'} Per-user GitHub access is not connected yet.`;
 }
 if(status===429)return 'GitHub temporarily rate-limited this request. Wait before starting another scan.';
 if(status===404)return 'Public repository or branch not found. Branch names are case-sensitive; leave the branch empty to use its default.';
 if(status===403)return 'GitHub denied repository access. This is not an AI analysis error.';
 return `GitHub collection failed (${status})`;
}