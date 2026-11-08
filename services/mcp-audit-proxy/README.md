# Traceveil audit relay

This standalone Node service is **not deployed or production-verified**. Custom hosts remain disabled in Traceveil. It is not a runtime tool proxy.

## Deployment prerequisites

- A dedicated HTTPS hostname you control, valid public TLS certificate and TLS gateway (for example Caddy) forwarding only `/v1/audit-rpc` to `127.0.0.1:8081`.
- One small Linux EC2 host in us-east-1, 8 GiB encrypted disk, one public IPv4, dedicated network. Approximate monthly cost $25–40 plus traffic; verify current AWS prices before creation. Set T3 CPU credit mode to standard to avoid surplus-credit charges. Configure budget alerts first.
- Require IMDSv2 and disable instance metadata once bootstrapped. No instance IAM role is needed by the relay.
- Host firewall: default-deny ingress; expose TLS 443 only. Relay listens on loopback. No public SSH. Outbound allow established replies and DNS to the exact VPC resolver; reject private/reserved/metadata IPv4 and IPv6 destinations before allowing public TCP 443. Do not leave Docker forwarding chains bypassing these rules; use host networking with a non-root, capability-free read-only container. Review nftables/iptables rules on the actual host.
- Use one shared service credential, entered securely on the relay and in Traceveil; never place it in cloud-init, infrastructure templates, image layers or logs. Do not run the relay until it is configured. No request/access log may include authorization, tokens or bodies.

## Local development

`bun install` then `bun run test` in this directory. Start with `RELAY_SHARED_SECRET` supplied by your secret manager; `node server.mjs` binds loopback 8081. Container requires `--network host --read-only --cap-drop ALL --security-opt no-new-privileges` and a secret supplied outside image layers.

## Enablement checklist

1. Deploy hostname, TLS gateway, restricted network and shared secret.
2. Verify live TLS host checking, pinned sockets, private/metadata denial, no redirects, deadlines, cancellation, capacity and size limits. Tests using controlled transports are not deployed proof.
3. Configure server-only `MCP_AUDIT_RELAY_URL` (exact HTTPS `/v1/audit-rpc` URL) and `MCP_AUDIT_RELAY_SECRET`.
4. Only after a real authenticated inventory audit and saved-record readback, set `MCP_AUDIT_RELAY_VERIFIED=true` and enable the endpoint UI. This release deliberately leaves the UI’s custom-host restriction in place pending these checks.

The relay forwards only initialize, initialized notification and paginated tools/list. Each connection resolves the entire DNS answer set, rejects any unsafe answer, and connects to one immutable numeric address with original hostname SNI and certificate validation. Responses are capped at 1 MB; requests at 16 KB; each request at 20 seconds; concurrency at four. Query strings, literal IPs, redirects and non-443 destinations are intentionally unsupported.

Future work: trusted deployment attestation, independent network penetration review, protocol streaming parsing hardening and operational monitoring. Do not claim enterprise readiness or arbitrary-host runtime support.