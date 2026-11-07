<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.

## What Lovable manages

Rules outside this block are the project's own. Change the pieces below in
Lovable, not by hand. With the [Lovable MCP](https://mcp.lovable.dev)
connected, `send_message` asks Lovable to do it; otherwise ask the user to
use the editor.

- **Database.** Do not add or edit `supabase/migrations/` or `drizzle/`.
  Ask Lovable to change the schema.
- **Generated files.** Do not edit a file whose header says it is automatically
  generated.
- **AI gateway.** Keep model calls on Lovable's gateway, and keep
  `LOVABLE_API_KEY` out of browser code.
- **Connectors.** Lovable provides native connectors. `list_connectors` shows
  which are enabled; `add_connector` only returns the dashboard link. When a
  connector is enabled, calls go through the connector gateway and need
  `LOVABLE_API_KEY`. When Lovable does not provide one, users can bring their
  own key and store it in Secrets.
- **Secrets.** Lovable manages them. Do not put secret values in the repo.
<!-- LOVABLE:END -->

- Authenticated scans stream NDJSON from `/api/scan`; validated results persist as server-written, owner-readable audit records because browser-authored evidence is not trustworthy.
- Live endpoint audits and runtime calls use a fixed trusted destination allowlist; arbitrary hosts fail closed until destination-pinned egress is available because DNS preflight alone cannot prevent rebinding. Runtime also requires explicit approval, an independent read-tool allowlist, interpreted Worker-safe schema validation and live SHA-256 baseline checks.
- Audit graphics derive categories and inferred reference edges only from static signals and inventory; model risk stays explicitly separate to avoid implying measured attacks or observed data flow.
- MCP destination and independent read-tool allowlists share a browser-safe registry; user connection configuration cannot expand network authority, to prevent SSRF and unsafe tool execution.
- Per-user connection tokens are AES-GCM encrypted server-side, bound to owner and exact endpoint, and never returned to browsers; disabled connections invalidate associated runtime access.
- Sanitization creates a derived export with change evidence and mandatory re-audit, never mutates audited baselines or grants approval, because definition edits cannot guarantee upstream safety.
