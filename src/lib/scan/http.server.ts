import { publicEndpoint } from './validation';
import {trustedDestination} from './destinations';
import {relayFetch} from './relay.server';

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
  // Host allowlist is enforced before any outbound connection; DNS preflight cannot prevent rebinding.
  if (!trustedDestination(url.href)) return relayFetch(url.href,{...init,signal});
  const response = await fetch(url, {...init, signal, redirect:'error'});
  return response;
}