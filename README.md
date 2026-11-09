# Traceveil

Evidence-first application security and agentic guardrail auditing platform. Trace repository attack surfaces to verifiable source evidence, evaluate tenant isolation, and audit agent interactions.

## Features

- **Evidence-First Security Analysis**: Resolves immutable Git commit snapshots and maps findings to concrete source lines and excerpts.
- **Autonomous Security Agents**: Red team, remediation reviewer, defense planner, and independent evidence verifiers.
- **Self-Contained Secure Authentication**: Local scrypt password hashing, session tokens, and zero external database dependencies.
- **MCP Guardrail Audits**: Inspect tool manifests and agent transcripts for prompt injection, tool poisoning, and parameter escalation.

## Getting Started

### Prerequisites

- Node.js >= 20
- npm or bun

### Installation & Run

```sh
# Install dependencies
npm install

# Start development server
npm run dev
```

Open `http://localhost:3000` in your browser.
