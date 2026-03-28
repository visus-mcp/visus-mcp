# Anthropic MCP Directory — Submission Package

## Server Details

- **Name:** Visus — Secure Web Access for Claude
- **npm package:** visus-mcp
- **Current version:** 0.11.0
- **Install command:** `npx visus-mcp`
- **License:** MIT
- **Category:** Web Fetch / Security

## One-liner (≤100 chars)

"Strips prompt injection & PII from web content before it enters Claude's context window."

## Short description (≤300 chars)

"Visus is a security-first MCP pre-filter. It sanitizes web pages for 43 prompt injection patterns, redacts PII, and uses reader mode to cut token usage by up to 70% — all before content reaches Claude. Built on NIST AI 600-1, OWASP LLM Top 10, MITRE ATLAS, ISO 42001."

## Tools exposed

1. `visus_fetch` — Fetch + sanitize any URL (HTML/JSON/XML/RSS auto-detected)
2. `visus_read` — Reader mode extraction via Mozilla Readability
3. `visus_search` — DuckDuckGo search with sanitized results
4. `visus_fetch_structured` — Schema-based structured data extraction

## Claude Desktop config snippet

```json
{
  "mcpServers": {
    "visus": {
      "command": "npx",
      "args": ["visus-mcp"]
    }
  }
}
```

## Links

- GitHub: https://github.com/visus-mcp/visus-mcp
- npm: https://www.npmjs.com/package/visus-mcp
- Security policy: https://github.com/visus-mcp/visus-mcp/blob/main/SECURITY.md
- License: https://github.com/visus-mcp/visus-mcp/blob/main/LICENSE

## Security frameworks

- OWASP LLM Top 10 (2025)
- NIST AI 600-1 Generative AI Profile
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- ISO/IEC 42001:2023 AI Management System

## Test evidence

- 246 passing tests (as of v0.6.0)
- 43 validated injection pattern categories
- Real-world benchmark: npmjs.com page reduced from 149,589 bytes → 44,129 bytes

## Known Limitations / Phase Status

- **Phase 1 (current):** Open-source tier fully functional. `npx visus-mcp` works out of the box with no API key. Uses Playwright locally with full JavaScript execution support. 246 tests passing.
- **Phase 2 (in development):** Managed Playwright renderer (`renderer.lateos.ai`) — not yet live. BYOC (self-hosted Lambda) renderer available now via [visus-mcp-renderer](https://github.com/visus-mcp/visus-mcp-renderer).
- **Phase 3:** Chrome extension for authenticated page access (LinkedIn, dashboards).

Anthropic directory listing is for the Phase 1 open-source tier. All 4 tools are fully functional in Phase 1.
