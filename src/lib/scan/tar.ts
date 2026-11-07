export type TarEntry = { path: string; size: number; data: Uint8Array };

function str(buf: Uint8Array, start: number, len: number) {
  let end = start;
  while (end < start + len && buf[end] !== 0) end++;
  return new TextDecoder().decode(buf.subarray(start, end));
}

export function parseTar(buf: Uint8Array): TarEntry[] {
  const out: TarEntry[] = [];
  let off = 0;
  let longName: string | null = null;
  while (off + 512 <= buf.length) {
    const header = buf.subarray(off, off + 512);
    if (header.every((b) => b === 0)) break;
    const name = str(header, 0, 100);
    const size = parseInt(str(header, 124, 12).trim() || "0", 8) || 0;
    const type = String.fromCharCode(header[156] || 48);
    const prefix = str(header, 345, 155);
    const dataStart = off + 512;
    const data = buf.subarray(dataStart, dataStart + size);
    off = dataStart + Math.ceil(size / 512) * 512;
    if (type === "L") {
      longName = str(data, 0, size);
      continue;
    }
    if (type === "x" || type === "g") continue;
    if (type !== "0" && type !== "\0" && type !== "7") continue;
    let path = longName ?? (prefix ? `${prefix}/${name}` : name);
    longName = null;
    path = path.replace(/^[^/]+\//, "");
    out.push({ path, size, data });
  }
  return out;
}

export async function gunzip(bytes: ArrayBuffer): Promise<Uint8Array> {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
