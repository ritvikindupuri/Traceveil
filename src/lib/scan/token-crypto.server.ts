async function key() {
  const secret=process.env['MCP_TOKEN_ENCRYPTION_SECRET'];
  if(!secret)throw new Error('Credential storage unavailable');
  const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(secret));
  return crypto.subtle.importKey('raw',bytes,'AES-GCM',false,['encrypt','decrypt']);
}
export async function encryptToken(token:string,binding:string) {
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:new TextEncoder().encode(binding)},await key(),new TextEncoder().encode(token));
  return btoa(String.fromCharCode(...iv,...new Uint8Array(encrypted)));
}
export async function decryptToken(ciphertext:string,binding:string) {
  const bytes=Uint8Array.from(atob(ciphertext),c=>c.charCodeAt(0));
  const decoded=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.slice(0,12),additionalData:new TextEncoder().encode(binding)},await key(),bytes.slice(12));
  return new TextDecoder().decode(decoded);
}