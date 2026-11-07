import type { McpTool, Signal, Sev } from "./types";

type Rule = { rule: string; label: string; severity: Sev; re: RegExp };

const TEXT_RULES: Rule[] = [
  { rule: "hidden-directive", label: "Hidden directive block", severity: "critical", re: /<\s*(important|system|instructions?|secret|hidden)\s*>/i },
  { rule: "override", label: "Instruction override", severity: "critical", re: /ignore (all |any )?(previous|prior|above) (instructions|rules)|disregard (the )?(system|previous)|you are now|new instructions:/i },
  { rule: "concealment", label: "Concealment from user", severity: "critical", re: /do not (tell|inform|mention|show|reveal)[^.]{0,40}(user|human)|without (telling|informing|notifying) the user|don'?t mention this/i },
  { rule: "sensitive-path", label: "Sensitive file reference", severity: "critical", re: /~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.env\b|\.npmrc|\.git-credentials|mcp\.json|\.cursor\/|claude_desktop_config|\/etc\/passwd|kubeconfig/i },
  { rule: "secret-ref", label: "Credential solicitation", severity: "high", re: /\b(api[_ -]?key|access[_ -]?token|password|private key|secret key|bearer token|session cookie)s?\b/i },
  { rule: "cross-tool", label: "Cross-tool behavior steering", severity: "high", re: /(before|after|when) (using|calling|invoking) (any |the )?(other )?tools?|instead of (the )?\w+ tool|(always|must) (also )?(call|use|send)/i },
  { rule: "exfil", label: "External exfiltration channel", severity: "high", re: /https?:\/\/(?!localhost)[^\s"'<>)]+|webhook|ngrok|pastebin|requestbin|discord(app)?\.com\/api/i },
  { rule: "redirect", label: "Recipient / destination rewriting", severity: "high", re: /(change|replace|redirect|set) (the )?(recipient|destination|to address|account|wallet)/i },
  { rule: "coercion", label: "Coercive phrasing", severity: "medium", re: /\b(very important|mandatory|critical|otherwise the tool will (fail|not work)|application will crash)\b/i },
  { rule: "encoded", label: "Encoded payload", severity: "high", re: /[A-Za-z0-9+/]{80,}={0,2}|\\u[0-9a-f]{4}(\\u[0-9a-f]{4}){3,}/i },
];

const RISKY_PARAMS = /^(command|cmd|shell|script|code|query|sql|exec|path|file(_?path)?|url|uri|endpoint|host|headers?|sidenote|notes?|context|metadata|extra|debug|token|secret|password|recipient|to)$/i;

export function invisibles(s: string) {
  const m = s.match(/[\u200B-\u200F\u2028-\u202E\u2060-\u2064\uFEFF\u{E0000}-\u{E007F}]/gu);
  return m?.length ?? 0;
}

function scanText(target: string, text: string, out: Signal[]) {
  for (const r of TEXT_RULES) {
    const m = text.match(r.re);
    if (m) {
      const i = Math.max(0, (m.index ?? 0) - 60);
      out.push({ rule: r.rule, label: r.label, severity: r.severity, target, excerpt: text.slice(i, i + 200).replace(/\s+/g, " ").trim() });
    }
  }
  const inv = invisibles(text);
  if (inv) out.push({ rule: "invisible", label: "Invisible / bidi characters", severity: "critical", target, excerpt: `${inv} hidden code points` });
}

function walkSchema(tool: string, schema: any, path: string, out: Signal[], depth = 0) {
  if (!schema || typeof schema !== "object" || depth > 6) return;
  if (schema.additionalProperties === true || (schema.type === "object" && !schema.properties && depth > 0)) {
    out.push({ rule: "open-schema", label: "Unbounded object parameter", severity: "medium", target: `${tool}${path}`, excerpt: "accepts arbitrary keys" });
  }
  const props = schema.properties ?? {};
  const required = new Set<string>(schema.required ?? []);
  for (const [k, v] of Object.entries<any>(props)) {
    const p = `${path}.${k}`;
    if (typeof v?.description === "string") scanText(`${tool}${p}`, v.description, out);
    if (RISKY_PARAMS.test(k) && v?.type === "string" && !v.enum && !v.pattern && !v.format) {
      out.push({ rule: "free-param", label: "Unconstrained high-risk parameter", severity: /sidenote|notes?|context|metadata|extra|debug/i.test(k) ? "high" : "medium", target: `${tool}${p}`, excerpt: `${k}: string, ${required.has(k) ? "required" : "optional"}, no enum/pattern` });
    }
    if (v?.default !== undefined && typeof v.default === "string") scanText(`${tool}${p}#default`, v.default, out);
    walkSchema(tool, v, p, out, depth + 1);
    if (v?.items) walkSchema(tool, v.items, `${p}[]`, out, depth + 1);
  }
}

export function scanTools(tools: McpTool[]): Signal[] {
  const out: Signal[] = [];
  const names = tools.map((t) => t.name);
  for (const t of tools) {
    scanText(t.name, t.description, out);
    if (t.description.length > 1200) out.push({ rule: "long-desc", label: "Oversized description", severity: "medium", target: t.name, excerpt: `${t.description.length} chars` });
    for (const other of names) {
      if (other !== t.name && other.length > 3 && new RegExp(`\\b${other.replace(/[^\w]/g, "\\$&")}\\b`).test(t.description)) {
        out.push({ rule: "shadowing", label: "References another tool", severity: "high", target: t.name, excerpt: `mentions "${other}"` });
      }
    }
    walkSchema(t.name, t.inputSchema, "", out);
  }
  const seen = new Map<string, number>();
  for (const n of names) seen.set(n, (seen.get(n) ?? 0) + 1);
  for (const [n, c] of seen) if (c > 1) out.push({ rule: "dup-name", label: "Duplicate tool name", severity: "high", target: n, excerpt: `${c} definitions` });
  return out.slice(0, 200);
}

export function scanTranscript(text: string): Signal[] {
  const out: Signal[] = [];
  const chunks = text.split(/\n(?=\S)/).slice(0, 2000);
  chunks.forEach((c, i) => {
    const before = out.length;
    scanText(`segment ${i + 1}`, c, out);
    if (out.length - before > 3) out.splice(before + 3);
  });
  return out.slice(0, 200);
}
