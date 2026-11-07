import { streamText } from "ai";
import { createLovableAiGatewayProvider } from "@/lib/ai/gateway.server";
import { collectEvidence } from "./registry.server";

export const MODEL = "google/gemini-4-argon";

type Emit = (e: Record<string, unknown>) => void;

const PROVENANCE_PROMPT = `You are the Provenance agent in a software supply-chain defense system. You analyze npm registry metadata for signs of account takeover and worm propagation (e.g. Shai-Hulud style campaigns: compromised maintainer tokens republishing packages with new preinstall/postinstall hooks, loss of provenance attestation, publisher changes, sudden version bumps). Be terse, factual, cite concrete fields. Output 3-6 bullet points, no preamble. If nothing is anomalous, say so plainly.`;

const CODE_PROMPT = `You are the Code agent in a software supply-chain defense system. You review static-analysis hits and code excerpts from an npm tarball. Determine whether behavior is malicious: credential harvesting (npm/GitHub/cloud tokens), secret scanning, self-propagation (publishing other packages), exfiltration, workflow injection, destructive payloads, wallet hijacking. Distinguish legitimate tooling from abuse; many hits are benign in build tools. Be terse. Output 3-8 bullet points citing file:line, no preamble.`;

const VERDICT_PROMPT = `You are the Verdict agent. Combine the Provenance and Code agent reports into a final decision. Respond with ONLY minified JSON, no code fences, matching:
{"verdict":"block"|"review"|"allow","risk":0-100,"summary":"one sentence","findings":[{"severity":"critical"|"high"|"medium"|"low","title":"short","detail":"one sentence","evidence":"file:line or field"}],"actions":["short imperative"]}
Max 6 findings, max 4 actions. Be calibrated: popular, provenance-attested packages with benign hits should be allow.`;

async function runAgent(
  gateway: ReturnType<typeof createLovableAiGatewayProvider>,
  agent: string,
  system: string,
  prompt: string,
  emit: Emit,
  signal: AbortSignal,
) {
  emit({ type: "agent:start", agent });
  const result = streamText({
    model: gateway(MODEL),
    system,
    prompt,
    abortSignal: signal,
    providerOptions: { lovable: { reasoningEffort: "low" } },
  });
  let text = "";
  for await (const part of result.fullStream) {
    if (part.type === "text-delta") {
      text += part.text;
      if (agent !== "verdict") emit({ type: "agent:delta", agent, text: part.text });
    } else if (part.type === "error") {
      throw part.error;
    }
  }
  emit({ type: "agent:end", agent });
  return text;
}

export async function runScan(spec: string, emit: Emit, signal: AbortSignal) {
  const key = process.env["LOVABLE_API_KEY"];
  if (!key) throw new Error("AI key not configured");
  const gateway = createLovableAiGatewayProvider(key, undefined, { baseURL: "https://ai.gateway.lovable.dev/v1" });

  emit({ type: "stage", stage: "collect" });
  const ev = await collectEvidence(spec);
  emit({ type: "evidence", recon: ev.recon, signals: ev.signals });

  const reconJson = JSON.stringify(ev.recon, null, 1);
  const sigText = ev.signals.map((s) => `[${s.severity}] ${s.label} — ${s.file}:${s.line} — ${s.excerpt}`).join("\n") || "none";
  const excerptText = ev.excerpts.map((x) => `--- ${x.path} ---\n${x.content}`).join("\n\n") || "none";

  emit({ type: "stage", stage: "agents" });
  const [prov, code] = await Promise.all([
    runAgent(gateway, "provenance", PROVENANCE_PROMPT, `Registry metadata:\n${reconJson}`, emit, signal),
    runAgent(
      gateway,
      "code",
      CODE_PROMPT,
      `Package ${ev.recon.name}@${ev.recon.version}\nLifecycle scripts: ${JSON.stringify(ev.recon.scripts)}\nStatic hits:\n${sigText}\n\nExcerpts:\n${excerptText}`,
      emit,
      signal,
    ),
  ]);

  emit({ type: "stage", stage: "verdict" });
  const raw = await runAgent(
    gateway,
    "verdict",
    VERDICT_PROMPT,
    `Package: ${ev.recon.name}@${ev.recon.version} (${ev.recon.weeklyDownloads ?? "?"} weekly downloads)\n\nProvenance report:\n${prov}\n\nCode report:\n${code}`,
    emit,
    signal,
  );
  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) throw new Error("Verdict agent returned no decision");
  emit({ type: "verdict", ...JSON.parse(match[0]) });
  emit({ type: "done" });
}
