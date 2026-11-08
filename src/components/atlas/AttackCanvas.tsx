import {useMemo,useEffect,useRef,useState} from 'react';
import {ReactFlow,Controls,Background,BackgroundVariant,Handle,Position,type NodeProps,type Node,type ReactFlowInstance} from '@xyflow/react';
import dagre from '@dagrejs/dagre';
import {GitBranch,FileCode,Workflow,Package,Server,ShieldAlert} from 'lucide-react';
import type {AttackGraph,GraphEntity} from '@/lib/atlas/types';
import {cn} from '@/lib/utils';
const icons={repository:GitBranch,file:FileCode,workflow:Workflow,dependency:Package,service:Server,finding:ShieldAlert};
type EntityNode=Node<{entity:GraphEntity},'entity'>;
function Entity({data,selected}:NodeProps<EntityNode>){const n=data.entity,I=icons[n.kind];return <div className={cn('atlas-node',selected&&'atlas-node-selected',n.severity==='high'&&'atlas-node-high',n.severity==='medium'&&'atlas-node-medium')}><Handle type="target" position={Position.Left}/><div className={cn('atlas-glyph',n.kind==='workflow'&&'atlas-glyph-workflow',n.kind==='dependency'&&'atlas-glyph-dependency',n.kind==='finding'&&'atlas-glyph-finding')}><I className="size-5"/></div><div className="min-w-0"><div className="truncate text-xs font-medium" title={n.label}>{n.label}</div><div className="mt-1 font-mono text-[9px] uppercase text-muted-foreground">{n.kind}{n.severity?` · ${n.severity}`:''}</div></div><Handle type="source" position={Position.Right}/></div>;}
const nodeTypes={entity:Entity};
export function AttackCanvas({graph,onSelect,search,riskOnly}:{graph:AttackGraph;onSelect:(ids:string[],label:string)=>void;search:string;riskOnly:boolean}){
 const container=useRef<HTMLDivElement|null>(null);
 const [flow,setFlow]=useState<ReactFlowInstance|null>(null);
 useEffect(()=>{if(!container.current||!flow)return;const observer=new ResizeObserver(()=>{void flow.fitView({padding:0.2});});observer.observe(container.current);return ()=>observer.disconnect();},[flow,graph,search,riskOnly]);
 const {nodes,edges}=useMemo(()=>{
  let entities=graph.nodes;
  if(riskOnly){const ids=new Set(['repo',...graph.edges.filter(e=>e.risky).flatMap(e=>[e.source,e.target])]);entities=entities.filter(n=>ids.has(n.id));}
  if(search)entities=entities.filter(n=>n.label.toLowerCase().includes(search.toLowerCase()));
  const ids=new Set(entities.map(n=>n.id)),relations=graph.edges.filter(e=>ids.has(e.source)&&ids.has(e.target));
  const layout=new dagre.graphlib.Graph();layout.setGraph({rankdir:'LR',nodesep:24,ranksep:90});layout.setDefaultEdgeLabel(()=>({}));entities.forEach(n=>layout.setNode(n.id,{width:240,height:68}));relations.forEach(e=>layout.setEdge(e.source,e.target));dagre.layout(layout);
  return {nodes:entities.map(n=>{const pos=layout.node(n.id);return {id:n.id,type:'entity',data:{entity:n},position:{x:pos.x-120,y:pos.y-34}};}),edges:relations.map(e=>({id:e.id,source:e.source,target:e.target,label:e.label,className:e.risky?'atlas-risk-edge':'atlas-relation-edge',type:'smoothstep',data:e,animated:false}))};
 },[graph,search,riskOnly]);
 return <div ref={container} className="h-full w-full"><ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onInit={instance=>setFlow(instance as ReactFlowInstance)} fitView minZoom={0.15} maxZoom={1.8} nodesDraggable={false} nodesConnectable={false} onNodeClick={(_,n)=>onSelect(n.data.entity.evidenceIds,n.data.entity.label)} onEdgeClick={(_,e)=>{const r=graph.edges.find(r=>r.id===e.id);if(r)onSelect(r.evidenceIds,r.label);}} proOptions={{hideAttribution:true}}><Background variant={BackgroundVariant.Dots} gap={24} size={1}/><Controls showInteractive={false}/></ReactFlow></div>;
}
