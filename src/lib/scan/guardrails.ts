import type {McpTool,Verdict} from './types';
import {eligibleTools,runtimeDestinationAllowed} from './policy';
import {scanTools} from './signals';

export function classifyTools(tools:McpTool[],verdict:Verdict,approved:string[],endpoint:string|null) {
  const eligible = eligibleTools(tools,verdict);
  return tools.map(tool => {
    const score = verdict.tools.find(t => t.tool === tool.name)?.risk;
    const severe = scanTools([tool]).some(s => s.severity === 'critical' || s.severity === 'high');
    const permitted = endpoint !== null && runtimeDestinationAllowed(endpoint,tool.name);
    const blocked = severe || verdict.verdict === 'block' || (score !== undefined && score >= 70) || (endpoint !== null && !permitted);
    const allowed = !blocked && permitted && eligible.includes(tool.name) && approved.includes(tool.name);
    return {name:tool.name,risk:score ?? null,status:allowed?'allowed' as const:blocked?'blocked' as const:'review' as const,
      eligible:!blocked && permitted && eligible.includes(tool.name),
      reason:severe?'High-severity static signal':verdict.verdict === 'block'?'Audit blocked':score !== undefined && score >= 70?'High audit risk':endpoint && !permitted?'Outside runtime allowlist':allowed?'Approved baseline':!endpoint?'Live endpoint required':eligible.includes(tool.name)?'Awaiting explicit approval':'Audit review required'};
  });
}

export function sanitizeDefinitions(tools:McpTool[]) {
  const changes:{tool:string;path:string;action:string}[]=[];
  const excluded:string[]=[];
  function dangerous(tool:string,text:string):boolean {
    return scanTools([{name:tool,description:text,inputSchema:{}}]).some(s => s.severity === 'critical' || s.severity === 'high');
  }
  function cleanSchema(tool:string,schema:unknown,path:string):unknown {
    if (!schema || typeof schema !== 'object' || Array.isArray(schema)) return schema;
    const copy = structuredClone(schema) as Record<string,unknown>;
    for (const key of ['description','title','default','examples','enum','const']) {
      if (key in copy && dangerous(tool,JSON.stringify(copy[key]))) {
        if (key === 'enum' || key === 'const') throw new Error('Unsafe constraint');
        delete copy[key];changes.push({tool,path:`${path}.${key}`,action:'removed unsafe annotation'});
      }
    }
    if (copy.properties && typeof copy.properties === 'object' && !Array.isArray(copy.properties)) {
      const props = copy.properties as Record<string,unknown>;
      for (const [key,value] of Object.entries(props)) {
        const signals = scanTools([{name:tool,description:'',inputSchema:{type:'object',properties:{[key]:value}}}]);
        if (signals.some(s=>s.severity === 'critical'||s.severity === 'high')) {
          delete props[key];if(Array.isArray(copy.required))copy.required=copy.required.filter(k=>k!==key);
          changes.push({tool,path:`${path}.${key}`,action:'removed flagged parameter'});
        } else props[key]=cleanSchema(tool,value,`${path}.${key}`);
      }
      copy.additionalProperties=false;
    }
    if(copy.items)copy.items=cleanSchema(tool,copy.items,`${path}[]`);
    return copy;
  }
  const sanitized:McpTool[]=[];
  for(const tool of tools) {
    // Complex constraints can depend on removed fields. Exclude rather than silently weaken them.
    if (/"(?:\$ref|\$defs|definitions|allOf|anyOf|oneOf|not|if|then|else|dependentSchemas|dependentRequired|dependencies|patternProperties|additionalItems|prefixItems)"\s*:/.test(JSON.stringify(tool.inputSchema))) {excluded.push(tool.name);continue;}
    try {
      let description=tool.description;
      if(dangerous(tool.name,description)){description='';changes.push({tool:tool.name,path:'description',action:'removed flagged description'});}
      const candidate={...tool,description,inputSchema:cleanSchema(tool.name,tool.inputSchema,'inputSchema')};
      if(scanTools([candidate]).some(s=>s.severity==='critical'||s.severity==='high')){excluded.push(tool.name);continue;}
      sanitized.push(candidate);
    } catch {excluded.push(tool.name);}
  }
  return {tools:sanitized,changes,excluded,requiresReaudit:true,warning:'Detected content removed; not a safety certification. Required-field removal may break upstream compatibility. Original audit and approvals are unchanged.'};
}