import ipaddr from 'ipaddr.js';
import {z} from 'zod';

export const REQUEST_LIMIT=16_384;
export const RESPONSE_LIMIT=1_000_000;
export const DEADLINE_MS=20_000;
export const MAX_CONCURRENT=4;
export function publicAddress(address){
 try {
  const ip=ipaddr.parse(address);
  // Only ordinary public unicast; ipaddr rejects mapped, transition,
  // multicast, documentation, private, link-local and reserved ranges.
  return ip.range()==='unicast';
 }catch{return false;}
}
export function targetUrl(raw){
 const u=new URL(raw);
 if(raw.length>2048||u.protocol!=='https:'||u.username||u.password||u.hash||u.search||(u.port&&u.port!=='443'))throw new Error('Invalid target');
 if(u.hostname.endsWith('.')||!u.hostname.includes('.')||ipaddr.isValid(u.hostname)||u.hostname.includes(':')||/(^|\.)(localhost|local|internal|test|invalid|example|onion)$/.test(u.hostname))throw new Error('Invalid target');
 return u;
}
const id=z.number().int().min(1).max(1_000_000);
const initialize=z.object({jsonrpc:z.literal('2.0'),id,method:z.literal('initialize'),params:z.object({protocolVersion:z.literal('2025-06-18'),capabilities:z.object({}).strict(),clientInfo:z.object({name:z.literal('traceveil-audit'),version:z.literal('1.0')}).strict()}).strict()}).strict();
const initialized=z.object({jsonrpc:z.literal('2.0'),method:z.literal('notifications/initialized')}).strict();
const list=z.object({jsonrpc:z.literal('2.0'),id,method:z.literal('tools/list'),params:z.object({cursor:z.string().max(4096).optional()}).strict()}).strict();
export const envelope=z.object({endpoint:z.string().min(1).max(2048),rpc:z.union([initialize,initialized,list]),session:z.string().min(1).max(512).regex(/^[\x21-\x7e]+$/).nullable().default(null),token:z.string().max(4096).regex(/^[\x21-\x7e]*$/).optional()}).strict();
export function validateRequest(value){const data=envelope.parse(value);targetUrl(data.endpoint);return data;}
export function chooseAddress(records){
 if(!records.length||records.length>32||records.some(r=>!publicAddress(r.address)||!([4,6].includes(r.family))))throw new Error('Destination blocked');
 // Every answer must be safe; use one immutable numeric address for this socket.
 return records.find(r=>r.family===4)??records[0];
}