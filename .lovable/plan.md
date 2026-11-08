# Armorix — evidence-first application attack graph

## Product direction
Rebuild Armorix around one workflow: **GitHub repository or live application URL → collected evidence → interactive attack graph → approved verification → reviewed fixes → recurring rechecks**.

Keep Armorix's name, faceted shield, balanced charcoal surfaces and emerald accent. Borrow Wiz's relationship-first approach, not its branding, screens or proprietary icons. No mock inventories, fabricated findings or invented connections.

## New experience
- A compact project workspace with a repository/application URL input as the starting point.
- A graph-first investigation screen: scoped asset list on the left, large interactive graph in the center, evidence drawer on the right.
- Separate views for findings, agent runs, remediation and monitoring; no extra dashboard charts that obscure the graph.
- Graph controls for fit, zoom, search, severity, relationship type and path focus. Selecting a node or edge opens the underlying source and timestamp.
- Purpose-specific outlined icons for repositories, routes, dependencies, identities, workflows, services and data stores. Show a resource only when it was actually discovered.
- Neutral connections for discovered relationships; amber/red for supported risky relationships. Dashed edges denote hypotheses. Keep confidence and risk separate; color alone never communicates status.
- Preserve existing Google/email sign-in and private historical MCP audit records; do not reinterpret old records as application scans.

## Evidence collection
### GitHub repository
- Start with public repository URLs, an explicit branch/ref and an immutable commit snapshot.
- Read bounded source files, dependency manifests/lockfiles, workflows, infrastructure definitions and relevant configuration through trusted GitHub destinations.
- Use deterministic checks for supported ecosystems, advisory lookups for identifiable dependency versions, and structured code analysis. Redact suspected secrets before AI prompts and UI output.
- Identify endpoints and relationships where source analysis supports them. Dynamic routes, private services and runtime permissions remain unknown unless separately observed.
- Never execute repository code, install its dependencies or follow instructions inside source files.
- Private repositories and fix pull requests require each user's own GitHub authorization; never use the builder's shared account to access customer repositories.

### Live application
- Start with public HTTPS responses and a bounded same-origin inspection: headers, linked assets, advertised routes and exposed configuration.
- A URL alone does not reveal private cloud resources, IAM permissions, database contents or a complete cloud attack graph. Display explicit collection gaps.
- Arbitrary-domain collection requires a secure outbound service that pins resolved public destinations and blocks private ranges, metadata services and unsafe redirects on every hop. The existing custom-host safety restriction remains until that service is connected.
- Verify ownership before active testing or recurring application checks. No browser-side scanning and no unrestricted crawling.

## Agent loop
1. **Red-team agent:** produce evidence-linked attack hypotheses, prerequisites and bounded test plans. The user chose approved safe tests: verify ownership and record explicit scope/approval before running non-destructive checks. Never treat an AI prediction as an observed exploit.
2. **Remediation agent:** propose a minimal patch tied to specific findings; show the diff and expected graph change. Export patches first. With per-user GitHub access, create reviewed pull requests, never auto-merge or silently change production.
3. **Defense agent:** run enabled recurring checks, compare commit/response/evidence snapshots, flag new or reopened paths and revalidate fixes. “Defended” means verified remediation or an actually installed blocking integration, not merely an alert.

Use the latest available Gemini model verified against the workspace catalog at implementation time. Retain server-side streaming, cancellation and traceable run records. Source content and agent outputs are untrusted; agents cannot grant themselves test, write or network authority.

## Differentiated features
- **Evidence ledger:** every graph connection has a source location or captured response, collection time and observed/inferred/verified status.
- **Patch-to-path preview:** show which supported paths a proposed fix would interrupt, explicitly marked as a prediction until re-scanned.
- **Attack-path delta:** compare commits or monitoring runs to show introduced, removed and unchanged paths.
- **Coverage lens:** highlight uninspected files, unsupported languages, truncated inventories and missing runtime visibility instead of hiding blind spots.
- **Independent verification:** a separate verifier checks whether claimed findings and fixes are supported; unsupported agent claims do not become graph facts.
- **Repository-to-deployment correlation:** explicitly link a repository snapshot to an ownership-verified application and show which code-side risks have supporting deployment evidence; never assume a URL runs that repository.

## Delivery sequence
1. Replace the MCP-centric front screen with the graph workspace; implement a real public-GitHub evidence pipeline and durable scan records. Empty states remain empty until a real scan completes.
2. Add evidence-linked Gemini analysis, independent validation, path investigation and reviewed patch export. Verify the full flow on a real public repository.
3. Connect secure outbound collection and ownership verification, then enable live-application inspection and approved non-destructive tests. If external infrastructure is unavailable, show a clear blocked state rather than a fake scan.
4. Add per-user GitHub access, reviewed pull requests, scheduled rechecks and alerts. Monitoring displays actual last-run/next-run timestamps and pauses when access or AI credits are unavailable.

## Technical details
- Keep TanStack Start and Lovable Cloud; preserve existing authenticated boundaries, encrypted tokens and fail-closed network restrictions.
- Add separate application projects, scan runs, evidence, graph nodes/edges, findings, scoped approvals, remediation artifacts and monitoring configuration. Owner-scoped reads; validated server-written evidence and execution decisions.
- Use an established interactive graph library with automatic layout. Layout positions may be generated; resource identities and risk edges must originate in evidence.
- Keep repository/API collection bounded and server-side. Heavy static analyzers and active verification belong in isolated jobs, not the hosted request process.
- Managed recurring callbacks may dispatch work; long-running scans need durable jobs rather than holding a scheduled callback open. Do not purchase external infrastructure without approval.
- Add concrete tests for URL and ownership validation, isolation, evidence provenance, unknown-node rejection, permission/approval enforcement, patch review and monitoring lifecycle. Keep current guardrail regression tests.
- Update each content page's Armorix-specific metadata and verify the graph, drawers and central workflow on desktop and mobile.

## Acceptance criteria
- A real supported repository produces a graph whose nodes and edges can be traced to collected evidence; no sample scan is substituted.
- Incomplete scans disclose gaps, and unsupported targets fail clearly.
- Active tests cannot run without verified ownership and scoped approval; remediation cannot silently modify a repository or live application.
- Monitoring is shown as running only when recurring jobs are configured and actual runs are recorded.
- Existing private audit history and sign-in continue to work.