# Tenant-isolation verification

## Goal
Make Traceveil focus on a concrete security outcome: checking whether one customer's identity can read another customer's records, then repeating those checks after changes. No claims of competitive exclusivity or universal security assurance.

## First working stage
- Add a compact **Tenant isolation** view alongside the repository graph.
- Bind a verification plan to a saved repository commit. Collect the app's real tenant rules, read endpoint contract, two synthetic identities and fixture identifiers. Credentials stay in the customer's test environment, never in browser forms or exported reports.
- Require explicit owner authorization for the exact test scope. Distinguish owner attestation from independently verified ownership.
- Export a runnable read-only regression suite and manifest for the customer's CI. Run it against the actual application at the approved commit and disposable fixtures—not mocked authorization.
- Test both tenants' own-record access as positive controls and cross-tenant access in both directions as negative controls. Inspect response contents, not just status codes. Failed login, missing fixtures and skipped controls yield **inconclusive**, never pass.
- Import bounded, redacted results into private saved runs. Bind each result to its plan, commit, suite digest and nonce; calculate the outcome on the server rather than trusting an uploaded verdict.
- Label manual imports **customer-reported**, not independently verified. Compare subsequent runs to expose returned risks; do not imply monitoring is scheduled.

## GitHub error and access
The reproduced 403 is GitHub's exhausted unauthenticated request quota, not an AI failure. Clear reset-time handling is implemented and its tests pass. GitHub reports a reset at 02:14 UTC for this failure; retrying cannot guarantee capacity remains available.

Configure a per-user GitHub connection through the existing connector flow for more reliable authenticated repository access. No workspace GitHub OAuth client currently exists, so setup requires the owner's configuration and approval. Do not substitute shared builder credentials.

## Technical details
- Keep verification plans/runs separate from application scan evidence, with explicit grants, owner-read RLS and server-only writes.
- Validate referenced scan ownership, non-anonymous identity, approval scope, commit, nonce, digest and result bounds on every write.
- Use a browser-safe deterministic evaluator for case outcomes and a standalone test suite run only in customer-controlled CI; never execute repository code in Traceveil's web process.
- Add tests for broken positive controls, cross-tenant leakage, missing cases, stale commit/suite results and cross-owner denial.
- Verify the signed-in plan → export → real CI run → import → saved readback flow against an owner-supplied target. Without that target and fixture adapter, report execution as unverified.

## Later, separately gated
Trusted CI attestation can upgrade provenance after repository/workflow/commit binding is verified. Hosted tests require an isolated runner, verified deployment ownership and destination-pinned egress. Writes, fixture creation, automatic fixes and recurring jobs are outside this first read-only stage.

## Acceptance
One real tenant-isolation regression can be reproduced, a reviewed fix can be rechecked, and its evidence can be read back privately. No mock scan findings, fabricated passes, automatic production changes or uniqueness claims.