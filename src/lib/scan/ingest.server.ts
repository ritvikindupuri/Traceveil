import { parse as parseYaml } from "yaml";
import type { McpTool, Mode } from "./types";
import { safeEndpointFetch, readBounded } from './http.server';
import { publicEndpoint } from './validation';

export type Ingested = { mode: Mode; source: string; server: string | null; tools: McpTool[]; transcript: string };

function normTools(doc: any): McpTool[] {
  const list = Array.isArray(doc) ? doc : (doc?.tools ?? doc?.result?.tools ?? (doc?.name ? [doc] : null));
  if (!Array.isArray(list) || list.length === 0) throw new Error("No tool definitions found (expected tools[] array)");
  if (list.length > 200) throw new Error('Tool inventory exceeds 200 tools');
  const names = new Set<string>();
  return list.map((t: any, i: number) => {
    if (!t || typeof t !== "object") throw new Error(`Tool #${i + 1} is not an object`);
    if (typeof t.name !== 'string' || !t.name.trim() || t.name.length > 256 || names.has(t.name)) throw new Error('Tool names must be unique nonempty strings');
    names.add(t.name);
    if (JSON.stringify(t).length > 60_000) throw new Error('Tool definition exceeds size limit');
    return {
      name: String(t.name ?? `tool_${i + 1}`),
      description: String(t.description ?? ""),
      inputSchema: t.inputSchema ?? t.input_schema ?? t.parameters ?? t.schema ?? {},
    };
  });
}

function parseDefs(raw: string) {
  try { return JSON.parse(raw); } catch {}
  try { return parseYaml(raw); } catch (e: any) { throw new Error(`Could not parse JSON or YAML: ${e?.message ?? ""}`); }
}

export async function rpc(url: URL, body: object, session: string | null, signal: AbortSignal, token?: string) {
  const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18" };
  if (session) headers["mcp-session-id"] = session;
  if (token) headers["authorization"] = `Bearer ${token}`;
  const res = await safeEndpointFetch(url, { method: "POST", headers, body: JSON.stringify(body), signal });
  if (res.status === 401) {
    const err: any = new Error(`Endpoint requires authentication (HTTP 401 Unauthorized). The MCP server at ${url.host} rejected unauthenticated requests. Please enter a valid Bearer token in the 'Bearer token' field.`);
    err.status = 401;
    throw err;
  }
  if (res.status === 403) {
    const err: any = new Error(`Access forbidden (HTTP 403 Forbidden). The provided Bearer token was rejected by ${url.host}.`);
    err.status = 403;
    throw err;
  }
  if (res.status === 404) {
    const err: any = new Error(`MCP endpoint not found (HTTP 404 Not Found at ${url.pathname}). Check the endpoint URL path.`);
    err.status = 404;
    throw err;
  }
  if (!res.ok && res.status !== 202) {
    const err: any = new Error(`MCP endpoint at ${url.host} returned HTTP ${res.status}: ${res.statusText || 'Error'}`);
    err.status = res.status;
    throw err;
  }
  const sid = res.headers.get("mcp-session-id");
  const text = await readBounded(res.body);
  if (!text.trim()) return { sid, msg: null };
  let payload = text;
  if ((res.headers.get("content-type") ?? "").includes("event-stream")) {
    const datas = text.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim());
    payload = datas.find((d) => d.includes('"result"') || d.includes('"error"')) ?? datas[0] ?? "";
  }
  let msg: any;
  try {
    msg = JSON.parse(payload);
  } catch {
    throw new Error(`MCP server at ${url.host} returned non-JSON response: ${payload.slice(0, 150)}`);
  }
  if (msg.error) throw new Error(`MCP error from ${url.host}: ${msg.error.message ?? JSON.stringify(msg.error)}`);
  return { sid, msg };
}

export function parseMcpEndpoint(raw: string): URL {
  let target = raw.trim();
  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    target = `https://${target}`;
  }
  const url = new URL(target);
  if (url.username || url.password || url.hash) {
    throw new Error('Endpoint must not contain embedded basic auth credentials');
  }
  return url;
}

export async function fetchEndpoint(raw: string, signal: AbortSignal, token?: string) {
  let url: URL;
  try {
    url = parseMcpEndpoint(raw);
  } catch {
    url = publicEndpoint(raw);
  }
  const init = await rpc(url, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "traceveil-audit", version: "1.0" } } }, null, signal, token);
  const sid = init.sid;
  await rpc(url, { jsonrpc: "2.0", method: "notifications/initialized" }, sid, signal, token);
  const tools: any[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 10; page++) {
    const r = await rpc(url, { jsonrpc: "2.0", id: 2 + page, method: "tools/list", params: cursor ? { cursor } : {} }, sid, signal, token);
    tools.push(...(r.msg?.result?.tools ?? []));
    if (tools.length > 200) throw new Error('Tool inventory exceeds 200 tools');
    cursor = r.msg?.result?.nextCursor;
    if (!cursor) break;
  }
  if (cursor) throw new Error('Incomplete tool inventory: pagination limit reached');
  const info = init.msg?.result?.serverInfo;
  return { server: info ? `${info.name ?? "server"} ${info.version ?? ""}`.trim() : url.host, tools: normTools(tools), sid };
}

export async function ingest(mode: Mode, input: string, signal: AbortSignal, token?: string): Promise<Ingested> {
  const raw = input.trim();
  if (!raw) throw new Error("Input is empty");
  if (raw.length > 400_000) throw new Error("Input exceeds 400KB");
  if (mode === "definitions") {
    const doc = parseDefs(raw);
    return { mode, source: "pasted definitions", server: doc?.serverInfo?.name ?? doc?.name ?? null, tools: normTools(doc), transcript: "" };
  }
  if (mode === "endpoint") {
    const r = await fetchEndpoint(raw, signal, token);
    const parsed = parseMcpEndpoint(raw);
    return { mode, source: parsed.host, server: r.server, tools: r.tools, transcript: "" };
  }
  let tools: McpTool[] = [];
  try { tools = normTools(parseDefs(raw)); } catch {}
  return { mode, source: "pasted transcript", server: null, tools, transcript: raw.slice(0, 120_000) };
}
