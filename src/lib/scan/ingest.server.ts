import { parse as parseYaml } from "yaml";
import type { McpTool, Mode } from "./types";

export type Ingested = { mode: Mode; source: string; server: string | null; tools: McpTool[]; transcript: string };

function normTools(doc: any): McpTool[] {
  const list = Array.isArray(doc) ? doc : (doc?.tools ?? doc?.result?.tools ?? (doc?.name ? [doc] : null));
  if (!Array.isArray(list) || list.length === 0) throw new Error("No tool definitions found (expected tools[] array)");
  return list.slice(0, 200).map((t: any, i: number) => {
    if (!t || typeof t !== "object") throw new Error(`Tool #${i + 1} is not an object`);
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

function assertPublicUrl(raw: string) {
  let u: URL;
  try { u = new URL(raw); } catch { throw new Error("Invalid URL"); }
  if (u.protocol !== "https:") throw new Error("Endpoint must use https");
  const h = u.hostname;
  if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.|\[?::1|\[?f[cd])/i.test(h) || h.endsWith(".internal") || h.endsWith(".local")) {
    throw new Error("Private or internal hosts are not allowed");
  }
  return u;
}

async function rpc(url: URL, body: object, session: string | null, signal: AbortSignal, token?: string) {
  const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": "2025-06-18" };
  if (session) headers["mcp-session-id"] = session;
  if (token) headers["authorization"] = `Bearer ${token}`;
  const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(body), signal });
  if (res.status === 401) throw new Error("Endpoint requires authentication (401)");
  if (!res.ok && res.status !== 202) throw new Error(`Endpoint returned ${res.status}`);
  const sid = res.headers.get("mcp-session-id");
  const text = await res.text();
  if (!text.trim()) return { sid, msg: null };
  let payload = text;
  if ((res.headers.get("content-type") ?? "").includes("event-stream")) {
    const datas = text.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim());
    payload = datas.find((d) => d.includes('"result"') || d.includes('"error"')) ?? datas[0] ?? "";
  }
  const msg = JSON.parse(payload);
  if (msg.error) throw new Error(`MCP error: ${msg.error.message ?? "unknown"}`);
  return { sid, msg };
}

async function fetchEndpoint(raw: string, signal: AbortSignal, token?: string) {
  const url = assertPublicUrl(raw);
  const init = await rpc(url, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "vigil-audit", version: "1.0" } } }, null, signal, token);
  const sid = init.sid;
  await rpc(url, { jsonrpc: "2.0", method: "notifications/initialized" }, sid, signal, token).catch(() => null);
  const tools: any[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 10; page++) {
    const r = await rpc(url, { jsonrpc: "2.0", id: 2 + page, method: "tools/list", params: cursor ? { cursor } : {} }, sid, signal, token);
    tools.push(...(r.msg?.result?.tools ?? []));
    cursor = r.msg?.result?.nextCursor;
    if (!cursor) break;
  }
  const info = init.msg?.result?.serverInfo;
  return { server: info ? `${info.name ?? "server"} ${info.version ?? ""}`.trim() : url.host, tools: normTools(tools) };
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
    return { mode, source: new URL(raw).host, server: r.server, tools: r.tools, transcript: "" };
  }
  let tools: McpTool[] = [];
  try { tools = normTools(parseDefs(raw)); } catch {}
  return { mode, source: "pasted transcript", server: null, tools, transcript: raw.slice(0, 120_000) };
}
