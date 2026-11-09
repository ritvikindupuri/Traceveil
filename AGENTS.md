# Traceveil Security Guidelines


- Authenticated scans stream NDJSON from `/api/scan`; validated results persist as server-written, owner-readable audit records because browser-authored evidence is not trustworthy.
- Live endpoint audits and runtime calls use a fixed trusted destination allowlist; arbitrary hosts fail closed until destination-pinned egress is available because DNS preflight alone cannot prevent rebinding. Runtime also requires explicit approval, an independent read-tool allowlist, interpreted Worker-safe schema validation and live SHA-256 baseline checks.
- Audit graphics derive categories and inferred reference edges only from static signals and inventory; model risk stays explicitly separate to avoid implying measured attacks or observed data flow.
- MCP destination and independent read-tool allowlists share a browser-safe registry; user connection configuration cannot expand network authority, to prevent SSRF and unsafe tool execution.
- Per-user connection tokens are AES-GCM encrypted server-side, bound to owner and exact endpoint, and never returned to browsers; disabled connections invalidate associated runtime access.
- Sanitization creates a derived export with change evidence and mandatory re-audit, never mutates audited baselines or grants approval, because definition edits cannot guarantee upstream safety.
- Runtime policies are owner-scoped, server-written restrictions on exact hosts/tools and audit/tool scores; approvals and per-call execution share their evaluator and recheck revisions before forwarding so policies cannot expand platform authority or bypass drift checks.
- Application graphs use bounded immutable public GitHub snapshots and deterministic evidence-linked entities; model reports never create graph facts, because analysis is not runtime or exploit proof.
- Application scans are stored separately from historical MCP audits with owner-readable, server-written records; this preserves evidence meaning across the product pivot.
- The interactive application graph loads client-side using React Flow and Dagre; server collection never executes repository code or fetches arbitrary application destinations.
- GitHub collection classifies provider quota headers separately from access denials without automatic retries, so request exhaustion is not misreported as an AI or authorization failure.
- Tenant-isolation plans bind owner attestation, immutable scan commit and expiring suite approval; one-time manual results stay customer-reported and never become graph or trusted execution facts.
- Exported tenant runners execute only in customer-controlled CI against numeric loopback targets, with four bounded GETs and no response bodies or credentials in results; the web process never executes repository code.
- The public root renders the branded landing page and uses the existing account dialog; authenticated identity transitions enter `/console`, keeping the workspace separate from the sign-in entry.
- Custom audit transport lives in a separately deployed Node relay with pinned numeric HTTPS sockets and an inventory-only method schema; server-side integration fails closed unless deployment verification is explicitly enabled, and runtime destination authority remains unchanged.
- GitHub PATs use the existing server-only AES-GCM key with a distinct owner/provider binding and service-role-only storage; authenticated functions return status only, and collection forwards tokens only to the fixed GitHub API with redirects rejected and sanitized errors.
