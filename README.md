# SHIELD Security Platform

**Enterprise-grade security for the indie developer era.**

SHIELD is an all-in-one security scanner built for modern JavaScript/TypeScript developers. Ship secure code without the enterprise price tag or alert fatigue.

---

## Why SHIELD?

| Feature | SHIELD | Snyk | Aikido | SonarQube |
|---------|--------|------|--------|-----------|
| SAST (AST-based) | ✅ | ❌ | Partial | ✅ |
| SCA (OSV database) | ✅ | ✅ | ✅ | ✅ |
| Secrets detection | ✅ 18+ patterns | Partial | ✅ | ❌ |
| IaC analysis | ✅ | ❌ | ✅ | ❌ |
| AI guardrails (MCP) | ✅ | ❌ | ❌ | ❌ |
| Noise reduction | ✅ intelligent triage | ❌ | Partial | ❌ |
| Open source | ✅ | ❌ | ❌ | Partial |
| Price | Free | $99+/mo | $299+/mo | $150+/mo |

---

## Features

- **SAST Scanner** — AST-based analysis with `@babel/parser`. Detects SQL injection, XSS, command injection, path traversal, IDOR, NoSQL injection, prototype pollution, hardcoded credentials, and missing auth.
- **SCA Scanner** — Queries the [OSV vulnerability database](https://osv.dev) for known CVEs in npm/PyPI packages. Shows CVSS scores, exploit availability, and fix versions.
- **Secrets Detection** — 18+ regex patterns for AWS, GitHub, Stripe, OpenAI, Anthropic, Supabase, Slack, Firebase, and more. Shannon entropy analysis catches unknown patterns.
- **IaC Analysis** — Analyzes Dockerfile, docker-compose.yml, next.config.js, vercel.json for security misconfigurations.
- **Intelligent Triage** — Reduces noise by 40-60%. Auto-ignores dev-only deps with low CVSS, secrets in test files, unreachable vulnerabilities.
- **Priority Scoring** — 0-100 score per finding based on severity (40%), exploitability (25%), reachability (20%), business impact (15%).
- **MCP Server** — Native Model Context Protocol server for AI assistant integration (Claude, Cursor, etc.).
- **Beautiful Dashboard** — React dashboard with security score, trend charts, dependency health visualization.

---

## Quick Start

```bash
# Scan your project
npx @shield/cli scan

# Quick scan (secrets + SCA only, ~30s)
npx @shield/cli scan --quick

# CI/CD mode (exit 1 on critical/high)
npx @shield/cli ci

# Initialize config
npx @shield/cli init

# Get fix guidance for a finding
npx @shield/cli fix <finding-id>

# Generate a markdown report
npx @shield/cli report --format markdown
```

### Install globally

```bash
npm install -g @shield/cli
shield scan ./my-project
```

---

## Architecture

```
shield/
├── packages/
│   ├── shared/          TypeScript types shared across packages
│   ├── core/            Scanners + triage engine
│   │   ├── scanners/
│   │   │   ├── sast/    AST analysis with @babel/parser + @babel/traverse
│   │   │   ├── sca/     OSV API batch queries for npm/PyPI CVEs
│   │   │   ├── secrets/ Regex + entropy-based secret detection
│   │   │   └── iac/     Dockerfile, compose, next.config analysis
│   │   └── triage/
│   │       ├── reachability.ts   Import graph analysis
│   │       ├── deduplication.ts  Group same CVE/secret across files
│   │       ├── contextual.ts     Context-aware severity adjustment
│   │       └── priority.ts       0-100 priority scoring
│   ├── cli/             Commander.js CLI with chalk/ora output
│   ├── mcp-server/      MCP server for AI assistant integration
│   └── dashboard/       React + Vite + Tailwind security dashboard
├── rules/
│   ├── sast/            YAML rule definitions
│   ├── secrets/         Secret pattern definitions
│   └── guardrails/      Framework security guardrails (markdown)
└── test-fixtures/       Intentionally vulnerable test files
```

---

## MCP Server (AI Integration)

Add SHIELD to Claude Desktop, Cursor, or any MCP-compatible AI assistant:

```json
// ~/.claude/claude_desktop_config.json
{
  "mcpServers": {
    "shield": {
      "command": "npx",
      "args": ["@shield/mcp-server"]
    }
  }
}
```

Available tools:
- `shield_scan_file` — Scan a specific file for vulnerabilities
- `shield_check_dependency` — Check npm/PyPI package for CVEs
- `shield_get_guardrails` — Get security guardrails for a framework
- `shield_validate_env` — Check .env file for exposed secrets
- `shield_scan_project` — Full project security scan

Available prompts:
- `secure_code_review` — Review code for security vulnerabilities
- `secure_api_endpoint` — Generate a secure API endpoint

---

## Dashboard

```bash
cd packages/dashboard
npm install
npm run dev
# Open http://localhost:5173
```

---

## Development

```bash
# Clone and install
git clone https://github.com/shield-security/shield
cd shield
npm install

# Build all packages
npm run build

# Run CLI in dev mode
npm run shield -- scan ./test-fixtures
```

---

## Pricing

| Plan | Price | Features |
|------|-------|---------|
| Open Source | Free | All scanners, CLI, MCP server |
| Pro | $29/mo | + Dashboard, CI integrations, Slack alerts |
| Team | $99/mo | + Multi-project, RBAC, audit logs |
| Enterprise | Custom | + SSO, on-prem, compliance reports |

---

## License

MIT © 2026 SHIELD Security Platform
