# Claude Code Session Prompt — Visus Phase 1
## Lateos: Secure AI-Connected Browser MCP Tool

Paste this entire prompt at the start of a new Claude Code session from your `lateos-visus` repo root.

---

## Context

You are building **Visus**, an MCP tool that gives Claude safe, sanitized access to web pages.
This is a new open-source repo (`lateos-visus`) that will be published as `visus-mcp` on npm.

Visus is part of the **Lateos** platform — a security-by-design AI agent framework built by Leo
(Roongrunchai Chongolnee / leochong). Lateos is deployed on AWS serverless (Lambda, Step Functions,
API Gateway, Cognito, Bedrock with Guardrails, DynamoDB with KMS encryption, Secrets Manager) in
me-central-1. The platform holds CISSP/CEH-informed design, 43 validated injection patterns, PII
redaction, and 122/122 passing tests.

The core differentiator: **every other MCP browser/scraping tool passes raw web content directly to
the LLM**. Visus does not. Every fetched page passes through the Lateos injection sanitization
pipeline before Claude reads a single character.

Tagline: *"What the web shows you, Lateos reads safely."*

---

## Your Mission (Phase 1)

Build a working, publishable `visus-mcp` npm package that:

1. Exposes an MCP server with two tools: `visus_fetch` and `visus_fetch_structured`
2. Fetches web pages using Playwright headless (Chromium)
3. Runs ALL fetched content through the injection sanitizer before returning
4. Is installable via `npx visus-mcp` with zero config for the open-source tier
5. Has a README that leads with security narrative, not features
6. Passes a full test suite covering both sanitizer logic and MCP tool interfaces

---

## Repo Structure to Create

```
lateos-visus/
├── README.md
├── SECURITY.md
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts                    # MCP server entry, tool registration
│   ├── tools/
│   │   ├── fetch.ts                # visus_fetch(url, options?)
│   │   └── fetch-structured.ts     # visus_fetch_structured(url, schema)
│   ├── sanitizer/
│   │   ├── index.ts                # Sanitizer orchestrator
│   │   ├── injection-detector.ts   # Pattern matching engine
│   │   ├── pii-redactor.ts         # PII detection and redaction
│   │   └── patterns.ts             # 43 injection pattern definitions
│   ├── browser/
│   │   └── playwright-renderer.ts  # Headless Chromium page fetcher
│   └── types.ts                    # Shared TypeScript interfaces
└── tests/
    ├── sanitizer.test.ts
    ├── fetch-tool.test.ts
    └── injection-corpus.ts         # Test payload library
```

---

## Tool Specifications

### `visus_fetch`
```typescript
Input: {
  url: string,                    // Required
  format?: "markdown" | "text",   // Default: "markdown"
  timeout_ms?: number             // Default: 10000
}

Output: {
  url: string,
  content: string,                // Sanitized content
  sanitization: {
    patterns_detected: string[],  // Names of injection patterns found and neutralized
    pii_types_redacted: string[], // e.g. ["email", "phone", "ssn"]
    content_modified: boolean
  },
  metadata: {
    title: string,
    fetched_at: string,           // ISO timestamp
    content_length_original: number,
    content_length_sanitized: number
  }
}
```

### `visus_fetch_structured`
```typescript
Input: {
  url: string,
  schema: Record<string, string>, // Field name → description, e.g. { "title": "page title", "price": "product price" }
  timeout_ms?: number
}

Output: {
  url: string,
  data: Record<string, string | null>,  // Extracted fields, sanitized
  sanitization: { /* same as above */ },
  metadata: { /* same as above */ }
}
```

---

## Injection Sanitizer Requirements

The sanitizer is the product's core moat. Build it to be comprehensive.

### Pattern categories to cover (43 total minimum):
1. **Direct instruction injection** — "Ignore previous instructions", "Forget what you were told"
2. **Role hijacking** — "You are now", "Your new persona is", "Act as"
3. **System prompt extraction** — "Repeat your instructions", "Print your system prompt"
4. **Privilege escalation** — "Admin mode", "Developer override", "Emergency protocol"
5. **Context poisoning** — "The user said", "As confirmed earlier", "You already agreed"
6. **Data exfiltration** — "Send this to", "Email the following", "Call this URL with"
7. **Encoding obfuscation** — Base64 instructions, Unicode lookalikes, hex-encoded commands
8. **Whitespace hiding** — Zero-width characters, invisible Unicode, CSS `display:none` text
9. **HTML/script injection** — `<script>`, `<iframe>`, `onclick`, `data:` URIs
10. **Markdown injection** — Malicious link syntax, image tags with instruction payloads
11. **URL fragment attacks** — Instructions after `#` in page content (HashJack pattern)
12. **Social engineering** — Urgency language designed to override caution ("CRITICAL: you must now")

### Sanitizer behavior:
- **Detect** → log pattern name to `sanitization.patterns_detected`
- **Neutralize** → strip, replace with `[REDACTED: injection_pattern_name]`, or escape
- **Never block** the entire page fetch due to a detection — degrade gracefully
- **PII types**: email addresses, phone numbers, SSN patterns, credit card patterns, IP addresses

### PII redaction output format:
```
[REDACTED:EMAIL], [REDACTED:PHONE], [REDACTED:CC], [REDACTED:SSN], [REDACTED:IP]
```

---

## README Structure

The README must lead with security narrative. Structure:

```markdown
# Visus — Secure Web Access for Claude

> Every MCP browser tool passes raw web content to your LLM. Visus doesn't.

[One-sentence description]

## The problem with other tools
[Brief comparison: Firecrawl / ScrapeGraphAI / Playwright MCP pass untrusted content unfiltered]

## How Visus works
[Architecture: fetch → sanitize → return clean content]

## Security
[43 patterns. PII redaction. Audit trail. Link to SECURITY.md]

## Quickstart
[npx visus-mcp, claude_desktop_config.json snippet]

## Tools
[visus_fetch, visus_fetch_structured]

## Lateos Platform
[Link to lateos repo, enterprise/hosted tier info]
```

---

## SECURITY.md Structure

```markdown
# Visus Security Model

## Threat model
[What attacks Visus defends against: indirect prompt injection, PII leakage]

## Injection detection
[43 pattern categories, examples of each]

## PII redaction
[Types detected, redaction format]

## What Visus does NOT protect against
[Honest limitations: novel obfuscation, AI-generated instructions that appear benign]

## Reporting vulnerabilities
[Contact: security@lateos.ai or GitHub Security tab]
```

---

## package.json Requirements

```json
{
  "name": "visus-mcp",
  "version": "0.1.0",
  "description": "Secure web access for Claude — sanitizes all web content before it reaches your LLM",
  "bin": { "visus-mcp": "dist/index.js" },
  "keywords": ["mcp", "claude", "web-scraping", "security", "prompt-injection", "ai-safety"],
  "engines": { "node": ">=18" }
}
```

---

## Test Requirements

All tests must pass before Phase 1 is complete.

### sanitizer.test.ts — must cover:
- Each of the 43 pattern categories with at least one positive test case
- PII detection: email, phone, SSN, credit card
- Content that is clean passes through unmodified (no false positives on normal pages)
- `content_modified: false` when no patterns detected
- `content_modified: true` and `patterns_detected` populated when injection found

### fetch-tool.test.ts — must cover:
- `visus_fetch` returns expected shape
- `visus_fetch_structured` extracts fields correctly
- Timeout handling
- Invalid URL handling
- Sanitizer is always called (cannot be bypassed)

### injection-corpus.ts — build a library of:
- 43 injection payloads (one per pattern category, sourced from public red team research)
- 10 clean pages / content samples (should produce no detections)

---

## Coding Standards (Lateos conventions from CLAUDE.md)

- TypeScript strict mode
- No `any` types
- All public functions JSDoc documented
- Error handling: never throw raw errors — return typed Result objects
- Logging: structured JSON to stderr (not stdout — MCP protocol uses stdout)
- No secrets in code — read from environment variables
- Tests: Jest, co-located in `/tests`, minimum 80% coverage
- Build: `tsc`, output to `/dist`

---

## Environment Variables

```bash
# Optional — for Lateos hosted tier features (Phase 2)
LATEOS_API_KEY=          # Enables audit logging to Lateos cloud
LATEOS_ENDPOINT=         # Defaults to https://api.lateos.ai

# Optional — browser config
VISUS_TIMEOUT_MS=10000   # Default fetch timeout
VISUS_MAX_CONTENT_KB=512 # Max content size before truncation
```

No API key required for open-source tier. `npx visus-mcp` works out of the box.

---

## Claude Desktop Config Snippet (for README)

```json
{
  "mcpServers": {
    "visus": {
      "command": "npx",
      "args": ["-y", "visus-mcp"]
    }
  }
}
```

---

## Definition of Done — Phase 1

- [ ] `npx visus-mcp` starts an MCP server with both tools registered
- [ ] `visus_fetch("https://example.com")` returns sanitized markdown
- [ ] All 43 pattern categories have test cases that pass
- [ ] No false positives on 10 clean content samples
- [ ] README leads with security narrative
- [ ] SECURITY.md documents the threat model
- [ ] `npm test` passes with 0 failures
- [ ] `npm run build` produces clean `/dist`
- [ ] `npm publish --dry-run` succeeds

---

## What NOT to Build in Phase 1

- No AWS Lambda deployment (Phase 2)
- No DynamoDB audit logging (Phase 2)
- No Cognito auth (Phase 2)
- No user-session relay / Chrome extension (Phase 3)
- No Lateos dashboard integration (Phase 2)
- No paid tier gating (Phase 2)

Keep Phase 1 lean. The goal is a working, publishable open-source MCP tool with a
security-first README that can be announced on LinkedIn and the MCP community.

---

## Start Here

1. Read this entire prompt
2. Read `CLAUDE.md` in the repo root (if it exists) for Lateos-specific conventions
3. Run `ls` to see what already exists in the repo
4. Start with `src/sanitizer/patterns.ts` — define all 43 patterns first
5. Build the sanitizer engine against those patterns
6. Build the Playwright renderer
7. Wire into MCP tools
8. Write tests
9. Write README and SECURITY.md last

Do not proceed past the sanitizer until the pattern library and basic detection logic
are complete and unit-tested. The sanitizer is the product.
