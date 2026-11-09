# Traceveil — Comprehensive Technical Documentation

## 1. Executive Architecture & Design Philosophy

Traceveil is an evidence-first cloud-native security and agentic defense platform. Traditional cloud security posture managers (CSPMs) and AI security copilots often suffer from **hallucination risk**—inferring non-existent security risks or proposing synthetic remediations ungrounded in real code and wire evidence.

Traceveil enforces a strict **deterministic evidence baseline**:
1. **Zero Hallucinated Facts**: No entity or relationship in the Attack Surface Graph is generated purely by generative LLM inference. All nodes and edges derive from immutable Git commit snapshots, parsed Containerfiles/manifests, or real HTTP/TLS wire probes.
2. **Cryptographic Provenance**: Every security finding references one or more SHA-256 fingerprints, exact file line intervals, or raw network response headers.
3. **Autonomous Multi-Model Specialization**: High-complexity adversarial and tenant isolation operations leverage Google Argon 4; multi-file code refactoring and PR generation leverage Gemini 1.5 Pro; high-frequency background monitoring uses low-latency Gemini 1.5 Flash.
4. **Self-Contained Local Execution**: All persistent states, session records, and encrypted tokens reside in a local embedded SQLite engine powered by Drizzle ORM, with zero external database dependencies.

---

## 2. Ingestion & Asset Discovery Engine

### 2.1 Git Repository Ingestion
* **Target Snapshots**: Binds to specific, immutable Git commit SHAs.
* **Credential Vault**: If scanning private repositories, user GitHub Personal Access Tokens (PATs) are encrypted server-side using AES-256-GCM with PBKDF2/scrypt key derivation. PATs are never returned to the client browser after storage.
* **Deterministic Parsers**:
  * `package.json` / lockfiles: Extracts dependency graphs, pinning vulnerable libraries.
  * `Dockerfile` / `Containerfile`: Inspects base images, `USER` statements, Linux capabilities (`cap_drop`), and exposed ports.
  * Kubernetes Manifests: Evaluates `SecurityContext`, `allowPrivilegeEscalation`, `readOnlyRootFilesystem`, and `NetworkPolicy` declarations.

### 2.2 Live Web Application Ingress Scanner
* **HTTP/TLS Fingerprinting**: Directly queries targets via Node.js native `fetch` over TLS 1.3 / 1.2.
* **Perimeter Security Checks**:
  * Content Security Policy (CSP): Evaluates `default-src`, `script-src`, `frame-ancestors`, and `object-src`.
  * HTTP Strict Transport Security (HSTS): Validates `max-age`, `includeSubDomains`, and `preload`.
  * Anti-Clickjacking: Evaluates `X-Frame-Options` and frame sandboxing.
  * Server Banner & Header Leakage: Detects upstream reverse proxies (`nginx`, `envoy`, `cloudflare`) and framework banners.
  * Sensitive Path Probes: Safely tests for exposed `/.env` or configuration files.

### 2.3 Model Context Protocol (MCP) Auditor
* **Protocol Manifest Analysis**: Ingests JSON/YAML tool manifests defined by Anthropic/CNCF MCP standards.
* **Risk Categorization**: Flags arbitrary code execution tools, unbounded filesystem read/write primitives, network egress capabilities, and prompt injection vectors.
* **Fail-Closed Relay**: Forwarding proxies require explicit cryptographic approvals and check destination allowlists before routing requests.

---

## 3. Attack Graph & Toxic Combination Synthesis

Traceveil models attack surfaces as directed multi-stage graphs using the Wiz-style toxic combination paradigm:
$$\text{Toxic Risk} = \text{Public Ingress} \times \text{Workload Vulnerability} \times \text{Privilege Boundary} \times \text{Crown Jewel Target}$$

### 3.1 Graph Schema
* **Entities (`GraphEntity`)**:
  * `kind`: `internet`, `server`, `container`, `vulnerability`, `credential`, `database`, `actor`, `policy`.
  * `provenance`: `declared` (explicitly in code), `inferred` (synthesized from verified dependencies), `observed` (detected via network probe).
* **Edges (`GraphRelation`)**:
  * `category`: `network` (network reachability), `trust` (identity/access delegation), `data` (data flow).
  * `risky`: Boolean indicator identifying malicious traversal edges.
* **Attack Paths (`AttackPath`)**:
  * Formatted as linear, multi-stage sequences (`AttackPathStep`) connecting an ingress actor to a crown jewel datastore.
  * Stages: `internet` ➔ `server` ➔ `vulnerability` ➔ `privilege` ➔ `target`.

### 3.2 Dynamic Visualizer
* Powered by `@xyflow/react` (React Flow) and the `dagre` horizontal layout engine (`rankdir: 'LR'`).
* Custom SVG edge animations for active toxic paths.
* Step-by-step breadcrumb steppers and floating walkthrough cards linked directly to raw evidence drawers.

---

## 4. Multi-Agent Intelligence Matrix

| Agent Role | Model Architecture | Responsibilities | Output Artifacts |
| :--- | :--- | :--- | :--- |
| **Tenant Isolation Copilot** | **Google Argon 4** | Conversational triage of tenant boundaries, cross-tenant leak probes, RLS synthesis | PostgreSQL RLS policies, Kubernetes NetworkPolicies |
| **Red Team Adversary** | **Google Argon 4** | Live attack command execution, boundary bypass verification, privilege escalation tests | Real command logs, terminal output, exploit assessments |
| **Remediation Engine** | **Gemini 1.5 Pro** | Code patch synthesis, pull request creation, automated GitHub branch merges | Unified Git diffs, GitHub PRs, live execution streams |
| **Perimeter Watchdog** | **Gemini 1.5 Flash** | Continuous 60-second polling of live endpoints for configuration drift | Drift alerts, timestamped probe logs, severity updates |

---

## 5. Security & Cryptographic Model

### 5.1 Symmetric Credential Encryption
* **Cipher**: AES-256-GCM.
* **Key Derivation**: Derived from server-only `SESSION_SECRET` via HKDF (HMAC-based Extract-and-Expand Key Derivation).
* **IV & Tag**: 12-byte random initialization vector (IV) and 16-byte authentication tag per encrypted payload.

### 5.2 Password Hashing
* Uses Node.js native `crypto.scrypt` with a minimum $N = 16384$, $r = 8$, $p = 1$, salted with 16 cryptographically secure random bytes.

### 5.3 Local Storage Isolation
* SQLite database running under Write-Ahead Logging (WAL) mode (`journal_mode = WAL`).
* Automatic table schema migration managed by Drizzle ORM.

---

## 6. End-to-End Execution Flow

```text
+-----------------------+     +------------------------+     +-------------------------+
| GitHub / Live Web /   | --> | Deterministic Evidence | --> | Google Gemini / Argon 4 |
| MCP Target Endpoints  |     | Extraction & SHA Hash  |     | Multi-Agent Pipeline    |
+-----------------------+     +------------------------+     +-------------------------+
                                                                          |
                                                                          v
+-----------------------+     +------------------------+     +-------------------------+
| Zero-Trust Guardrails | <-- | Autonomous Remediation | <-- | Wiz-Style Attack Graph  |
| & Live Watchdog       |     | & GitHub Pull Requests |     | Interactive Topology    |
+-----------------------+     +------------------------+     +-------------------------+
```

1. **Target Ingestion**: User enters repository URL or live web domain in Workspace.
2. **Evidence Extraction**: System fetches trees or sends HTTP preflight requests, computing SHA-256 digests.
3. **Graph Construction**: Entities and relations are synthesized deterministically and arranged with Dagre.
4. **Agent Analysis**: Argon 4 and Gemini 1.5 stream adversarial assessment and tenant validation over NDJSON.
5. **Remediation & Triage**: User reviews unified diffs, launches automated PR creation, or isolates workloads using generated NetworkPolicies.
