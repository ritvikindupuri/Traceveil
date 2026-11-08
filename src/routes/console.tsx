import {createFileRoute} from '@tanstack/react-router';
import {Workspace} from '@/components/atlas/Workspace';
export const Route=createFileRoute('/console')({head:()=>({meta:[{title:'Attack graph — Armorix'},{name:'description',content:'Investigate evidence-backed repository attack surfaces with Armorix security agents.'},{property:'og:title',content:'Attack graph — Armorix'},{property:'og:description',content:'Trace repository risks to source evidence and review agent recommendations.'},{property:'og:type',content:'website'},{name:'twitter:card',content:'summary'}]}),component:Workspace});
