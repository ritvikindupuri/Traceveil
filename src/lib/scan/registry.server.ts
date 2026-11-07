import { gunzip, parseTar } from "./tar";
import { scanFile, type Signal } from "./signals";

import type { Recon } from "./types";
export type { Recon };

export type Evidence = { recon: Recon; signals: Signal[]; excerpts: { path: string; content: string }[] };

const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare", "preuninstall"];

export function parseSpec(raw: string) {
  const s = raw.trim().replace(/^npm:/, "");
  const at = s.lastIndexOf("@");
  if (at > 0) return { name: s.slice(0, at), version: s.slice(at + 1) || null };
  return { name: s, version: null };
}

async function tarFiles(url: string) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Tarball fetch failed (${res.status})`);
  const buf = await res.arrayBuffer();
  if (buf.byteLength > 25_000_000) throw new Error("Tarball exceeds 25MB scan limit");
  return { size: buf.byteLength, entries: parseTar(await gunzip(buf)) };
}

export async function collectEvidence(spec: string): Promise<Evidence> {
  const { name, version } = parseSpec(spec);
  if (!/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i.test(name)) throw new Error("Invalid package name");
  const encoded = name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
  const res = await fetch(`https://registry.npmjs.org/${encoded}`, { headers: { accept: "application/json" } });
  if (res.status === 404) throw new Error(`Package "${name}" not found on npm`);
  if (!res.ok) throw new Error(`Registry error (${res.status})`);
  const doc = (await res.json()) as any;

  const v = version && version !== "latest" ? (doc["dist-tags"]?.[version] ?? version) : doc["dist-tags"]?.latest;
  const meta = doc.versions?.[v];
  if (!meta) throw new Error(`Version ${v} not found`);

  const ordered = Object.keys(doc.time ?? {})
    .filter((k) => k !== "created" && k !== "modified" && doc.versions?.[k])
    .sort((a, b) => +new Date(doc.time[a]) - +new Date(doc.time[b]));
  const idx = ordered.indexOf(v);
  const prev = idx > 0 ? ordered[idx - 1] : null;
  const prevMeta = prev ? doc.versions[prev] : null;

  const dl = await fetch(`https://api.npmjs.org/downloads/point/last-week/${name}`)
    .then((r) => (r.ok ? r.json() : null))
    .catch(() => null);

  const [cur, old] = await Promise.all([
    tarFiles(meta.dist.tarball),
    prevMeta ? tarFiles(prevMeta.dist.tarball).catch(() => null) : Promise.resolve(null),
  ]);
  const oldPaths = new Set(old?.entries.map((e) => e.path) ?? []);
  const dec = new TextDecoder();

  const scripts: Record<string, string> = meta.scripts ?? {};
  const scriptRefs = new Set<string>();
  for (const k of LIFECYCLE) {
    const cmd = scripts[k];
    if (cmd) for (const m of cmd.matchAll(/([\w./-]+\.(?:c?js|mjs|sh|ts))/g)) scriptRefs.add((m[1] ?? "").replace(/^\.\//, ""));
  }

  const signals: Signal[] = [];
  const excerpts: { path: string; content: string }[] = [];
  let budget = 48_000;
  const priority = [...cur.entries].sort((a, b) => {
    const score = (e: typeof a) => (scriptRefs.has(e.path) ? 3 : 0) + (old && !oldPaths.has(e.path) ? 2 : 0);
    return score(b) - score(a);
  });
  for (const e of priority) {
    if (e.size > 4_000_000) continue;
    const text = dec.decode(e.data);
    const hits = scanFile(e.path, text);
    signals.push(...hits);
    const important = scriptRefs.has(e.path) || hits.some((h) => h.severity === "critical" || h.severity === "high");
    if (important && budget > 0) {
      const slice = text.slice(0, Math.min(budget, 12_000));
      budget -= slice.length;
      excerpts.push({ path: e.path, content: slice });
    }
  }

  const provenance = (m: any) => Boolean(m?.dist?.attestations);
  return {
    recon: {
      name,
      version: v,
      previousVersion: prev ?? null,
      publishedAt: doc.time?.[v] ?? null,
      previousPublishedAt: prev ? doc.time[prev] : null,
      totalVersions: ordered.length,
      weeklyDownloads: dl?.downloads ?? null,
      maintainers: (doc.maintainers ?? []).map((m: any) => m.name),
      publisher: meta._npmUser?.name ?? null,
      previousPublisher: prevMeta?._npmUser?.name ?? null,
      hasProvenance: provenance(meta),
      previousHadProvenance: provenance(prevMeta),
      scripts: Object.fromEntries(Object.entries(scripts).filter(([k]) => LIFECYCLE.includes(k))),
      previousScripts: Object.fromEntries(
        Object.entries((prevMeta?.scripts ?? {}) as Record<string, string>).filter(([k]) => LIFECYCLE.includes(k)),
      ),
      repository: typeof meta.repository === "string" ? meta.repository : (meta.repository?.url ?? null),
      tarballSize: cur.size,
      fileCount: cur.entries.length,
      addedFiles: old ? cur.entries.filter((e) => !oldPaths.has(e.path)).map((e) => e.path).slice(0, 40) : [],
      largestFiles: [...cur.entries].sort((a, b) => b.size - a.size).slice(0, 5).map((e) => ({ path: e.path, size: e.size })),
    },
    signals: signals.slice(0, 120),
    excerpts,
  };
}
