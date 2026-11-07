import { isPublicIPv4, publicEndpoint } from './validation';

export async function readBounded(body: ReadableStream<Uint8Array> | null, limit = 1_000_000): Promise<string> {
  if (!body) return '';
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let text = '', bytes = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > limit) { await reader.cancel(); throw new Error('Response exceeds size limit'); }
      text += decoder.decode(chunk.value, {stream:true});
    }
    return text + decoder.decode();
  } finally { reader.releaseLock(); }
}

export async function safeEndpointFetch(raw: string | URL, init: RequestInit): Promise<Response> {
  const url = publicEndpoint(String(raw));
  const signal = AbortSignal.any([init.signal ?? new AbortController().signal, AbortSignal.timeout(20_000)]);
  // Preflight DNS validation is defense-in-depth; execution uses a fixed trusted host below.
  const dns = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(url.hostname)}&type=A`, {headers:{accept:'application/dns-json'}, signal, redirect:'error'});
  if (!dns.ok) throw new Error('Endpoint DNS validation failed');
  const answer = await dns.json() as {Status:number; Answer?: {type:number; data:string}[]};
  const ips = answer.Answer?.filter(a => a.type === 1).map(a => a.data) ?? [];
  if (answer.Status !== 0 || !ips.length || ips.some(ip => !isPublicIPv4(ip))) throw new Error('Endpoint does not resolve to public addresses');
  const response = await fetch(url, {...init, signal, redirect:'error'});
  return response;
}