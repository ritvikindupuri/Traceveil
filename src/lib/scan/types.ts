export type Sev = "critical" | "high" | "medium" | "low";
export type Mode = "definitions" | "transcript" | "endpoint";
export type McpTool = { name: string; description: string; inputSchema: unknown };
export type Signal = { rule: string; label: string; severity: Sev; target: string; excerpt: string };
export type Inventory = {
  mode: Mode;
  source: string;
  server: string | null;
  tools: { name: string; params: string[]; descLength: number }[];
  transcriptChars: number;
};
export type ToolScore = { tool: string; risk: number; class: string };
export type Verdict = {
  verdict: "block" | "review" | "allow";
  risk: number;
  summary: string;
  tools: ToolScore[];
  findings: { severity: Sev; title: string; detail: string; evidence: string }[];
  guardrails: string[];
};
