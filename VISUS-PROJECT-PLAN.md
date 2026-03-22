---
**Status:** Original Specification — Superseded
This document captures the original design intent written before development began. Phases 1 and 2 are complete. For the current living roadmap, see ROADMAP.md.
**Archived:** 2026-03-22

---

# Visus — Project Plan
**Lateos Feature: Secure AI-Connected Browser via MCP**
*"What the web shows you, Lateos reads safely."*

---

## Strategic Context

### Why Visus

Every existing MCP browser/scraping tool (Firecrawl, ScrapeGraphAI, Octoparse, Playwright MCP) passes
raw web content directly to the LLM with no sanitization. OpenAI has publicly admitted prompt injection
in browser agents may never be fully solved. Perplexity Comet was hijacked via crafted URL parameters.
OpenAI Atlas had its long-term memory poisoned via CSRF.

Visus occupies the only defensible position in this market: **user-session browsing + mandatory
injection sanitization before Claude sees a single token.**

### Competitive Moat
- User's own browser session (no ToS violation, no credential exposure on our servers)
- 43 validated injection patterns run on every fetched page
- PII redaction before content reaches Bedrock
- DynamoDB audit log of every URL fetch + sanitization result
- Bedrock Guardrails as a second layer
- KMS encryption at rest

---

## Architecture

```
User provides URL
  ↓
Visus MCP Tool (Lambda)
  ↓
[Tier check: open-source vs Lateos hosted]
  ↓
Browser rendering layer (Playwright headless OR user-session relay)
  ↓
Raw HTML / text extraction
  ↓
Lateos Injection Sanitizer (43 patterns)
  ↓
PII Redactor
  ↓
[Lateos hosted only] DynamoDB audit log + Bedrock Guardrails
  ↓
Clean content → Claude via MCP
```

### Two rendering modes

| Mode | Mechanism | Use case | ToS risk |
|---|---|---|---|
| Headless (Playwright) | Lambda-side Playwright | Public pages, no auth required | Low |
| User-session relay | Local MCP server in user's browser | Login-gated pages (LinkedIn, email, etc.) | None |

Start with headless. User-session relay is Phase 2.

---

## Three-Tier Product Model

| Tier | What ships | Who installs | Monetization |
|---|---|---|---|
| Open-source MCP | Basic headless fetch + minimal sanitization | Developers, self-hosters | GitHub stars, community |
| Lateos self-hosted | Full 43-pattern sanitizer, PII redaction, audit logs | Security-conscious teams | Open-source + paid support |
| Lateos cloud (me-central-1) | Managed, KMS-encrypted, zero-config, Bedrock Guardrails | Enterprise, non-technical users | SaaS subscription |

---

## Phased Roadmap

### Phase 1 — Open-Source MCP Tool (2 weeks)
**Goal:** Ship a working `visus-mcp` npm package. Get GitHub traction.

- [ ] New repo: `lateos-visus` (or `visus-mcp`)
- [ ] Lambda function: accepts URL, runs Playwright headless, returns text/markdown
- [ ] Inject Lateos sanitization pipeline (port from existing Lateos code)
- [ ] MCP server wrapper exposing two tools:
  - `visus_fetch(url)` → sanitized page content
  - `visus_fetch_structured(url, schema)` → sanitized + JSON extraction
- [ ] npm publish: `npx visus-mcp`
- [ ] Claude Desktop config snippet in README
- [ ] README includes security-first narrative + comparison table vs Firecrawl/ScrapeGraphAI
- [ ] SECURITY.md documenting the 43-pattern engine and what it catches
- [ ] Basic rate limiting (no API key required for open-source tier)

### Phase 2 — Lateos Integration (1 week)
**Goal:** Wire Visus into existing Lateos platform as a first-class feature.

- [ ] New DynamoDB table: `visus_fetch_log` (url, timestamp, user_id, patterns_detected, pii_found)
- [ ] Cognito JWT auth gate on Lateos-hosted endpoint
- [ ] KMS encryption for fetched content stored in audit log
- [ ] Bedrock Guardrails pass-through before content returned to caller
- [ ] Lateos dashboard widget: fetch history, patterns caught, PII redacted count
- [ ] Upgrade wedge: open-source vs hosted feature comparison in README

### Phase 3 — User-Session Relay (2-3 weeks)
**Goal:** Enable login-gated page access without credential exposure.

- [ ] Local MCP relay: lightweight Node process user runs locally
- [ ] User opens URL in their own browser, relay captures rendered content
- [ ] Content posted to Lateos sanitization endpoint
- [ ] Sanitized result returned to Claude via MCP
- [ ] Chrome extension wrapper (optional UX improvement)
- [ ] Documentation: "your credentials never leave your machine"

### Phase 4 — LinkedIn / LinkedIn-class Pages (1 week)
**Goal:** The demo everyone wants. Claude reads LinkedIn profiles safely.

- [ ] User-session relay handles LinkedIn auth
- [ ] Structured extraction schema for LinkedIn profiles, job postings
- [ ] Demo video: "Ask Claude to summarize this LinkedIn profile" with Visus
- [ ] LinkedIn use case featured prominently in README and LinkedIn launch post

---

## Naming & Branding

| Element | Value |
|---|---|
| Feature name | Visus |
| Latin meaning | sight / vision |
| npm package | `visus-mcp` |
| Repo | `lateos-visus` |
| Tagline | *"What the web shows you, Lateos reads safely."* |
| Core differentiator | Treats all web content as untrusted by default |

---

## Files to Create

```
lateos-visus/
├── README.md                    # Security-first narrative
├── SECURITY.md                  # 43-pattern engine documentation
├── SECURITY-AUDIT-v1.md         # Red team results (publish after Phase 1)
├── package.json
├── src/
│   ├── index.ts                 # MCP server entry point
│   ├── tools/
│   │   ├── fetch.ts             # visus_fetch tool
│   │   └── fetch-structured.ts  # visus_fetch_structured tool
│   ├── sanitizer/
│   │   ├── injection-detector.ts  # Port from Lateos
│   │   ├── pii-redactor.ts        # Port from Lateos
│   │   └── patterns.ts            # 43 validated patterns
│   └── browser/
│       └── playwright-renderer.ts
├── lambda/
│   └── visus-fetch/             # AWS Lambda handler
└── tests/
    ├── sanitizer.test.ts        # Port existing 73 tests
    └── injection-corpus.ts      # Test payload library
```

---

## Launch Narrative (LinkedIn Post Hook)

> Every AI browser tool passes raw web content to your LLM.
> Every one of them. Firecrawl, Playwright MCP, Octoparse — no exceptions.
> OpenAI admits prompt injection in browser agents may never be solved.
> We disagree.
> Visus treats web content as untrusted by default.
> 43 validated injection patterns. PII redaction. Full audit trail.
> What the web shows you, Lateos reads safely.
> Open-source. Ship it today. [link]

---

## Success Metrics (Phase 1)

- GitHub stars: 100+ in first week
- npm weekly downloads: 500+
- Claude Desktop config discussions mentioning Visus: 5+
- Security community engagement (OWASP, Lakera, etc.): 1+ mention

---

## Dependencies on Existing Lateos Code

| Lateos component | Visus usage |
|---|---|
| Injection detection (43 patterns) | Core sanitizer — direct port |
| PII redactor | Pre-Claude content filter |
| DynamoDB client | Audit log (Phase 2) |
| KMS encryption helper | Audit log encryption (Phase 2) |
| Bedrock Guardrails wrapper | Second-layer safety (Phase 2) |
| Cognito JWT validator | Auth gate (Phase 2) |
| MCP endpoint infrastructure | Extend existing endpoint |

---

*Last updated: March 2026*
*Owner: Leo (leochong / Roongrunchai Chongolnee)*
*Platform: Lateos — Security-by-Design AI Agent Platform*
