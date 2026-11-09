<div align="center">

<img src="docs/images/traceveil-logo-paths.png" alt="Traceveil Logo" width="88" height="88" />

# Traceveil

**Evidence-First Autonomous Security Graph, Agentic Defense, and Multi-Tenant Isolation Platform**

[![Tests](https://img.shields.io/badge/tests-72%20passed-10b981.svg?style=flat-square)](https://github.com/ritvikindupuri/Traceveil)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![React 19](https://img.shields.io/badge/React-19.0-61dafb.svg?style=flat-square)](https://react.dev/)
[![TanStack Start](https://img.shields.io/badge/TanStack-Start-ff4154.svg?style=flat-square)](https://tanstack.com/start)
[![Google Gemini](https://img.shields.io/badge/AI-Google%20Argon%204%20%7C%20Gemini%201.5-8e75ff.svg?style=flat-square)](https://deepmind.google/technologies/gemini/)

</div>

---

## Overview

**Traceveil** is an enterprise-grade cloud-native security and agentic defense platform engineered to eliminate security hallucination. Traditional Cloud Security Posture Management (CSPM) tools and generic AI security copilots frequently report theoretical vulnerabilities disconnected from code reality. Traceveil enforces a strict **deterministic evidence baseline**: every entity, threat relationship, and remediation step is bound directly to verifiable Git commit SHAs, parsed container specifications, exact source code line numbers, or raw HTTP/TLS wire probes.

Traceveil bridges raw code repositories, live production web applications, containerized runtimes, and Model Context Protocol (MCP) tool pipelines into unified, multi-stage **Wiz-Style Toxic Attack Graphs**. Powered by a specialized multi-agent AI matrix running **Google Argon 4**, **Gemini 1.5 Pro**, and **Gemini 1.5 Flash**, Traceveil automates the entire security lifecycle—from adversarial red teaming and conversational multi-tenant isolation triage to one-click GitHub Pull Request generation and 60-second autonomous perimeter watchdog loops.

---

## Key Features

* **Deterministic Attack Graph Engine (Wiz-Style Visualizer)**: Synthesizes toxic risk combinations linking public ingress vectors, workload vulnerabilities, privilege escalations, and crown jewel datastores into an interactive Dagre horizontal topology powered by React Flow.
* **Conversational Tenant Isolation Copilot (Google Argon 4)**: An interactive security consultant equipped with prompt pills, live probe test widgets, and one-click policy generators synthesizing hardened PostgreSQL Row-Level Security (RLS) rules and Kubernetes zero-trust NetworkPolicies.
* **Autonomous Red Team Adversary (Google Argon 4)**: Executes real, unsimulated attack commands against target workloads to rigorously test privilege escalation boundaries, sensitive token leakage, and SSRF pivots with live stdout/stderr streams.
* **Automated Code Remediation & GitHub Pull Requests (Google Gemini 1.5 Pro)**: Automatically analyzes discovered toxic paths, drafts unified git diff patches, generates structured security advisories, and opens pull requests on GitHub with a real-time execution terminal feed.
* **Continuous 60-Second Perimeter Watchdog (Google Gemini 1.5 Flash)**: An autonomous background monitoring agent that scans target endpoints every minute, alerting security teams to perimeter drift such as missing Content Security Policies (CSP), HSTS downgrades, or accidental `.env` exposures.
* **Model Context Protocol (MCP) Guardrails Auditor**: Deeply inspects MCP tool manifests and execution transcripts to catch prompt injection, tool poisoning, schema tampering, and parameter escalation with fail-closed proxy relay protection.
* **Self-Contained Local Database & Cryptographic Vault**: Zero-cloud-dependency SQLite engine running in Write-Ahead Logging (WAL) mode with Drizzle ORM, Node `crypto.scrypt` password hashing, and AES-256-GCM authenticated encryption for private GitHub Personal Access Tokens (PATs).

---

## System Architecture

<p align="center">
  <img src="docs/architecture/traceveil-architecture.png" alt="How a Traceveil investigation run works" width="838" />
</p>

<p align="center">
  <em>Figure 1. Three left-to-right lanes. Tags mark Browser vs Server vs Host. Dashed lanes are optional Console paths. AI agents use a generic robot mark; official logos are only for real products. Icon credits: <a href="docs/architecture/ATTRIBUTION.md">ATTRIBUTION.md</a>. Regenerate with <code>python3 docs/architecture/generate.py</code>.</em>
</p>

<details>
<summary>Mermaid fallback</summary>

```mermaid
flowchart LR
  you[You] --> console[Console]
  console --> scan["POST /api/application-scan"]
  scan --> github[GitHub collector]
  scan --> live[Live HTTPS probes]
  github --> graph[Graph engine]
  live --> graph
  scan --> store[Local JSON store]
  graph --> agents[Report agents]
  agents --> canvas[Results canvas]
  console -.-> isolation[Isolation agent]
  isolation <-.-> gemini[Google Gemini]
  console -.-> mcpPage[MCP audits]
  mcpPage -.-> mcpScan["POST /api/scan"]
  mcpScan -.-> guard["POST /api/guard"]
  guard -.-> hosts[Allowlisted MCP hosts]
```

</details>

### How it works, step by step

Numbered steps match the callouts on the diagram.

1. **Sign in; session stays here.** The public `/` landing page opens the account dialog. `POST /api/auth` creates or checks a user with scrypt password hashes and a 30-day session token stored in `data/traceveil-store.json`. The browser keeps that token in `localStorage` (`traceveil_auth_session`) and, once signed in, routes into `/console`.

2. **Pick repo or live app.** The workspace scan bar takes a URL plus the consent checkbox (`aiConsent: true`). Repository vs live-application is a UI mode, but the server decides the collector with `url.toLowerCase().includes('github.com')`.

3. **Authenticated scan starts.** `POST /api/application-scan` requires a bearer session, bounds the body to 2,500 bytes, and calls `consume_audit_quota` (always granted by the local store). Progress, the graph, the saved record id, and agent deltas stream back as NDJSON.

4. **GitHub files or live HTTPS.** GitHub collection talks only to `https://api.github.com` for repo metadata, the commit SHA, a recursive tree, and up to 24 blobs (100 KB each). An optional PAT is AES-GCM encrypted, bound to `traceveil:github-pat:v1:{userId}:https://api.github.com`, and never returned to the browser. Live collection validates a public HTTPS host, then GETs `/`, `/.env`, `/robots.txt`, and `/.git/HEAD`.

5. **Static rules bind evidence.** `buildRepositoryGraph` / `validateGraph` create nodes, edges, and findings only from inspected files or probe headers. Every entity carries evidence ids; the model is not allowed to invent graph facts. Coverage gaps are recorded on the graph object.

6. **Scan API writes the record.** After collection returns, `POST /api/application-scan` itself inserts the `application_scans` row (status `analyzing`) into the local JSON store, then later updates it to `complete` (or `partial` if agents fail). The graph engine does not write the record.

7. **Agents stream template reports.** `analyzeGraph` streams four template write-ups — red team, remediation, defense planner, code proof verifier — with `redact()` applied. These reports are local templates, not live Gemini calls.

8. **Canvas draws the graph.** The client renders the streamed graph with React Flow and Dagre (`rankdir: 'LR'`). Findings, the evidence drawer, and export JSON all read that same in-memory graph.

9. **Isolation tab calls Gemini.** The Console’s Tenant isolation tab invokes `chatWithTenantIsolationAgent`, which runs on the server, may call Google Gemini via `callFrontierModel` when `GEMINI_API_KEY` / `ARGON_API_KEY` / `GOOGLE_API_KEY` is set (otherwise a local template), and returns the reply into the same Console chat UI.

10. **Optional MCP audit and guard.** `/mcp-audits` posts to `/api/scan` (definitions, endpoint, or transcript). `runScan` ingests tools, scores regex signals, emits three template agent write-ups, and stores an owner-scoped `audit_records` row with a SHA-256 tool fingerprint. The MCP audits UI then posts to `/api/guard`, which re-checks approval, runtime policy, schema, and fingerprint, then **the same handler** forwards `tools/call` to the allowlisted host (`fetchEndpoint` + `rpc`). The optional audit relay is inventory-only (`initialize` / `tools/list`) and is not on this runtime path.

### What the diagram omits

These modules exist in the tree but are unused, simulated, fail-closed, or not on the investigation path above:

- **Not SQLite / not hosted Supabase.** `drizzle/schema.ts` is blank. Runtime persistence is the JSON file behind a Supabase-shaped client (`src/lib/server/db.server.ts`). `.env` still lists unused `SUPABASE_*` keys.
- **Application-scan “agents” do not call Gemini.** `src/lib/atlas/agents.server.ts` only formats templates. Gemini is used by tenant-isolation chat (`callFrontierModel`), which maps the `argon-4` label to `gemini-1.5-pro`.
- **Remediation “open a PR” is a client-side scripted terminal**, not `gh pr create` (`InteractiveRemediation.tsx`). Diffs can be copied or downloaded.
- **`enforcePolicyLive` only appends logs** to an in-memory map. It does not apply Kubernetes NetworkPolicies or Falco rules. YAML in the defense tab is generated text for copy/download.
- **`createIsolationPlan` / `importIsolationResult` / the exported CI runner are not wired to the UI.** Tenant isolation in the console is the chat agent. That agent’s four “live probes” are hardcoded pass results, not HTTP.
- **MCP audit relay is fail-closed** unless `MCP_AUDIT_RELAY_VERIFIED=true` and the URL/secret are set. It may proxy inventory collection for allowlisted hosts; it refuses `tools/call`. The Node relay in `services/mcp-audit-proxy/` is a separately deployed service, not started by this web process. Runtime execution is `/api/guard` talking to the allowlisted host directly.
- **Endpoint *collection* is not limited to the allowlist**; `/api/scan` may fetch the typed URL. *Runtime* `/api/guard` is allowlist-only. Saving a connection cannot add hosts.
- **`src/integrations/supabase/cron-auth.ts` is unused.** Password reset (`action: 'reset-password'`) returns a stub message and does not send mail.
- **GitHub PAT encryption needs `MCP_TOKEN_ENCRYPTION_SECRET`.** Without it, save/load throws “Credential storage unavailable.” Collection can still use `GITHUB_TOKEN` / `GH_TOKEN` on the server.

---

## Tech Stack

### Frontend & Visualizer
* **Framework**: [TanStack Start](https://tanstack.com/start) with [React 19](https://react.dev/)
* **Styling & UI**: [Tailwind CSS v4](https://tailwindcss.com/), Radix UI Primitives, Lucide React Icons
* **Topology & Visualization**: `@xyflow/react` (React Flow), Dagre graph layout engine

### Artificial Intelligence & LLM Engine
* **SDK**: `@google/genai` (Google Gen AI SDK)
* **High-Complexity Reasoning & Red Teaming**: Google Argon 4
* **Precision Code Patching & PR Synthesis**: Google Gemini 1.5 Pro
* **High-Frequency Perimeter Monitoring**: Google Gemini 1.5 Flash
* **Deterministic Fallback Engine**: Local rule-based security reasoning engine

### Backend & Server Architecture
* **Server Framework**: TanStack Server Functions & Vite SSR
* **Runtime**: Node.js 20+ / Bun
* **Data Transport**: Server-Sent Events (SSE) streaming with NDJSON (Newline Delimited JSON)

### Storage & Security Vault
* **Database**: Embedded SQLite with WAL (Write-Ahead Logging) mode
* **ORM**: [Drizzle ORM](https://orm.drizzle.team/)
* **Cryptographic Vault**: AES-256-GCM symmetric encryption with HKDF key expansion
* **Authentication**: Node.js `crypto.scrypt` password hashing and secure HTTP session cookies

### Container Infrastructure & Sandboxes
* **Containerization**: Docker & Kubernetes (`kind` / local clusters)
* **Runtime Security Monitoring**: CNCF Falco & Falcosidekick

---

## Setup Instructions

### Prerequisites
* **Node.js**: `v20.0.0` or higher
* **Package Manager**: `npm` (v10+) or `bun`
* **Git**: `v2.40+`
* *(Optional)* **Gemini API Key**: Set `GEMINI_API_KEY` for live Google AI agent execution (Traceveil includes an integrated deterministic local security reasoning fallback if omitted).

### 1. Clone the Repository
```bash
git clone https://github.com/ritvikindupuri/Traceveil.git
cd Traceveil
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables
Create a `.env` file in the project root:
```bash
cp .env.example .env
```

Configure the following variables in `.env`:
```env
# Google Gemini / Argon Model Access (Optional for cloud LLM execution)
GEMINI_API_KEY="your-gemini-api-key"

# Cryptographic Session & Vault Secret (Used for AES-256-GCM encryption)
SESSION_SECRET="generate-a-strong-32-byte-secret-key-here"

# Local Data Directory
DATA_DIR="./data"
```

### 4. Initialize Database
Initialize the embedded SQLite database schema:
```bash
npm run db:push
```

### 5. Start the Development Server
```bash
npm run dev
```
The application will start immediately at `http://localhost:3000`.

### 6. Build & Run for Production
```bash
# Build client and server bundles
npm run build

# Start production server
npm run start
```

### 7. Run Test Suite
Traceveil includes an extensive test suite verifying cryptographic hashing, graph synthesis, isolation policies, and routing:
```bash
npm test
```

---

## Usage Guide

### 1. Launching the Workspace Console
* Open your browser and navigate to `http://localhost:3000/console`.
* You will be greeted by the Traceveil investigation workspace with the sidebar tabs: **Attack Surface**, **Tenant Isolation**, **Findings**, **Security Agents**, **Remediation**, and **Autonomous Defense**.

### 2. Scanning a Target
Traceveil supports two distinct target modes via the mode switcher above the scan bar:

#### Mode A: GitHub Repository Scan
1. Click the **Repository** button.
2. Enter any public or private repository URL (e.g. `https://github.com/owner/repo`).
3. If scanning a private repository: Click **GitHub Credentials** in the top bar, enter your GitHub Personal Access Token (PAT), and click **Save Credential**. Your token is encrypted with AES-256-GCM and stored locally.
4. Check the box to authorize read-only analysis and click **Scan**.
5. Watch the real-time progress stream as the deterministic engine clones the commit tree, parses manifests, and synthesizes the topology.

#### Mode B: Live Web Application Scan
1. Click the **Live application** button.
2. Enter the target web domain or URL (e.g. `https://example.com` or `http://localhost:3000`).
3. Click **Scan**.
4. The scanner probes TLS parameters, HTTP response headers, CSP/HSTS configurations, and sensitive paths in real time.

### 3. Navigating Attack Surfaces & Wiz-Style Attack Paths
* **Topology Exploration**: Drag, pan, and zoom on the interactive React Flow canvas. Declared assets appear in neutral badges, while risky conditions are highlighted with warning indicators.
* **Isolating Toxic Attack Paths**:
  1. Click the **Attack paths** button in the header (marked with a flame icon).
  2. The canvas automatically filters out background nodes, isolating strictly the multi-stage toxic path from Public Ingress to the Crown Jewel database.
  3. Use the horizontal breadcrumb stepper at the top or click **Next Step** in the floating walkthrough card to step through each phase of the attack.
  4. Clicking any step auto-centers the canvas on the active node and opens the **Evidence Drawer** showing the exact HTTP headers, code lines, and remediation recommendations.

### 4. Collaborating with the Tenant Isolation Copilot
1. Select the **Tenant isolation** tab from the left sidebar.
2. Review the suggested prompt pills in the conversation:
   * *"How do I isolate workspaces in Supabase / PostgreSQL?"*
   * *"Prevent IDOR on our customer billing APIs"*
   * *"Run live cross-tenant boundary verification probes"*
3. Click any pill or type a natural language prompt in the input bar.
4. The agent will respond with detailed analysis, generate executable probe verification widgets, and output copyable PostgreSQL RLS rules or Kubernetes zero-trust NetworkPolicy YAML manifests.

### 5. Running Red Team Simulations & Automated Remediation
1. Navigate to the **Security agents** tab to inspect the autonomous Red Team report. Review real executed exploit commands, observed process behaviors, and escape assessment verdicts.
2. Click the **Remediation** tab to inspect generated code patches.

#### How to Create Real Live PRs on Your Repository
1. In the top navigation bar of `http://localhost:3000/console`, click **GitHub Credentials**.
2. Paste a GitHub Personal Access Token (classic or fine-grained) with `repo` (content and pull request write) permissions and click **Save Credential**.
3. Go to the **Remediation** tab, enter your repository URL, and click **Agent Auto-Fix (PR & Merge)**.
4. The agent will push the real branch, open the real Pull Request on GitHub, and clicking **View on GitHub** will navigate directly to your live GitHub PR. (If no token is supplied, Traceveil seamlessly generates and downloads a cryptographically signed `.patch` bundle ready for manual `git apply`).


### 6. Continuous Perimeter Monitoring & MCP Tool Auditing
* **Autonomous Defense**: Click **Autonomous defense** to view the 60-second perimeter watchdog telemetry, historical drift alerts, and configured firewall rules.
* **MCP Tool Audits**: Click **MCP audits** in the bottom left sidebar to paste JSON/YAML Model Context Protocol manifests, evaluate prompt injection vectors, and set fail-closed destination rules.

---

## Technical Documentation Link

For an in-depth architectural breakdown, cryptographic proofs, data schemas, and API protocol specifications, please refer to the:

👉 **[Comprehensive Technical Documentation](TECHNICAL_DOCUMENTATION.md)**

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
