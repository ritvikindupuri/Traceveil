# Secure custom-host MCP audits

## Outcome
Audit custom HTTPS MCP servers through a separate protected service. Browsers submit requests only to Traceveil; they never connect to the MCP server. Existing approved-tool runtime forwarding stays unchanged.

## Hosting approval
AWS has no existing network in the checked region. Create one dedicated proxy deployment: one small compute instance, one public IP, one isolated network/subnet and restricted firewall. No NAT gateway, database or autoscaling resources.

Estimated ongoing AWS cost: **$25–40/month plus traffic**, not a provider quote. Resources continue billing until removed. Confirm the region and current pricing before creation. Add a budget alert before deployment. If permissions or TLS hostname setup are unavailable, deliver the service and deployment instructions but keep custom-host audits disabled.

## Build
1. Add a separately deployable, hardened Node/Docker service with non-root execution, bounded concurrency and request/response limits.
2. Accept only authenticated audit collection requests. Reuse Traceveil user authentication at the app boundary; authorize the app-to-proxy request separately with a securely configured shared credential. Never return or log credentials.
3. Restrict collection to MCP initialization and tool inventory, including bounded pagination. Reject tool execution, arbitrary HTTP methods, redirects and non-HTTPS destinations.
4. Resolve all destination addresses, reject private/reserved/metadata ranges, and connect to the validated numeric address without another DNS lookup. Preserve the original hostname for TLS verification and SNI. Revalidate every new connection; block IPv4-mapped IPv6 and mixed public/private answers.
5. Restrict the host firewall’s outbound traffic, including metadata/private network destinations, as defense in depth. No user-supplied configuration can expand the proxy’s network privileges.
6. Connect the existing audit collector to the proxy for custom hosts only after deployment verification. Continue validated server-side evidence persistence, existing scan quotas and safe error reporting. Keep vetted destinations and runtime tool permissions independent.

## Technical scope
- New isolated `services/mcp-audit-proxy/` service, deployment configuration and tests; never import its Node transport into the hosted application.
- Add a server-only relay client alongside `src/lib/scan/http.server.ts` and adapt the collector’s custom-host path.
- Update the endpoint form to reflect verified relay availability, not merely the presence of a configuration value.
- Document the separate deployment/security boundary in `AGENTS.md`.
- Configure the relay address and shared credential through secure settings after a real deployment address exists.

## Verification before enabling
- Test private IPs, alternate IP encodings, IPv6, mixed DNS answers, rebinding attempts, redirects, invalid TLS, oversized responses, cancellation and unauthorized relay access.
- Confirm the actual socket connects only to the validated address while certificate validation uses the requested hostname.
- Run an authenticated custom MCP inventory audit end-to-end and read its saved record back through Traceveil.
- Verify browsers make no requests to the external MCP host and runtime `tools/call` remains blocked for custom hosts.

## Not included
Arbitrary runtime tool forwarding, live-app attacks, autonomous changes and claims of enterprise readiness. Custom hosts stay blocked if deployment or destination-pinning verification fails.