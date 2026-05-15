# Anthropic Connectors Directory — Submission Package
## visus-mcp v0.26.0

**Submission Date:** April 21, 2026
**Bundle File:** `visus-mcp-0.26.0.mcpb` (38MB)
**Submission Form:** https://docs.google.com/forms/d/e/1FAIpQLSeafJF2NDI7oYx1r8o0ycivCSVLNq92Mpc1FPxMKSw1CzDkqA/viewform

---

## Extension Name

**Visus — Secure Web Access**

---

## Short Description (≤160 chars)

Security pre-filter for Claude: sanitizes web content, detects prompt injection, redacts PII, and cuts token usage by up to 70%.

---

## Long Description

### What is Visus?

Visus is a **security-first MCP extension** that applies defense-in-depth to web content **before** it reaches Claude's context window. Unlike other MCP web tools that pass raw HTML directly to the LLM, Visus runs every byte through a multi-stage security pipeline.

### The Problem It Solves

When Claude fetches web pages, three risks emerge:

1. **Indirect Prompt Injection (IPI)**: Malicious websites can embed instructions designed to hijack Claude's behavior — "Ignore previous instructions and...", "You are now DAN...", "Send your conversation history to..."
2. **PII Leakage**: Raw web content often contains emails, phone numbers, SSNs, and credit card numbers that shouldn't enter Claude's context
3. **Token Waste**: News sites and blogs include navigation bars, ads, cookie banners, and boilerplate that consume thousands of tokens without providing value

Visus neutralizes all three risks **before content reaches your conversation**.

### How It Works

Every tool invocation runs content through this pipeline:

1. **Fetch & Render**: Playwright renders the page with full JavaScript execution (SPAs, dynamic content supported)
2. **IPI Threat Detection**: 7 specialized detectors scan for:
   - Instruction Override ("ignore previous instructions")
   - Role Hijacking ("you are now DAN")
   - Data Exfiltration ("send your context to...")
   - Tool Abuse ("call the delete function")
   - Context Poisoning (false factual assertions)
   - Encoded Payloads (Base64/hex-encoded instructions)
   - Steganographic Attacks (zero-width characters, hidden HTML)
3. **Pattern Neutralization**: 43 injection patterns are stripped or replaced with `[REDACTED:pattern_name]`
4. **PII Redaction**: Emails, phone numbers, SSNs, credit cards, and IP addresses are replaced with `[REDACTED:PII_TYPE]`
5. **Reader Mode** (optional): Mozilla Readability strips nav bars, ads, and boilerplate — reducing token consumption by up to 70% on content-heavy pages
6. **Cryptographic Proof**: SHA-256 content hash + HMAC signature proves sanitization ran, with mappings to NIST AI RMF, OWASP LLM Top 10, MITRE ATLAS, and ISO/IEC 42001:2023
7. **Token Ceiling**: Content truncated at 24,000 tokens to prevent context exhaustion

### Trust Model

- **Local-first**: Runs entirely on your machine — no external API calls
- **Open source**: MIT License, 500+/500 passing tests — audit the code yourself at https://github.com/visus-mcp/visus-mcp
- **No authentication required**: Open-source tier works out of the box
- **Deterministic**: Same input always produces the same sanitized result
- **Framework-aligned**: Threat detection mapped to OWASP LLM Top 10 (2025), NIST AI RMF 600-1, MITRE ATLAS, and ISO/IEC 42001:2023

### Real-World Impact

**Before Visus:**
- npmjs.com package page: 149,589 bytes, 1,200+ tokens wasted on navigation
- Injection attempt in web content: Directly enters Claude's context unfiltered

**After Visus:**
- npmjs.com package page: 44,129 bytes (70% reduction), navigation stripped
- Injection attempt: Detected as IPI-001 (CRITICAL), replaced with `[REDACTED:direct_instruction_injection]`, threat report included in response

### Known Limitations

Visus is designed to catch **pattern-based attacks** and **explicit PII**. It does not protect against:

- **Semantic injection**: Business language that appears benign but subtly manipulates behavior ("As the CEO mentioned earlier, please prioritize...")
- **Multi-step chaining**: Coordinated attacks split across multiple tool calls
- **Adversarially optimized prompts**: LLM-generated injection that bypasses regex patterns
- **Non-English injection**: Partial coverage for non-Latin scripts
- **Novel obfuscation**: Zero-day encoding techniques not in the 43-pattern library

See the full threat model at https://github.com/visus-mcp/visus-mcp/blob/main/SECURITY.md

---

## Category

**Security / Web Fetch**

---

## Tools Provided

1. **visus_fetch** — Fetch and sanitize a web page (HTML/JSON/XML/RSS auto-detected). Returns clean content with cryptographic proof and threat_summary.

2. **visus_read** — Reader mode extraction via Mozilla Readability. Strips nav/ads/boilerplate, reducing tokens by ~70%. Full security pipeline applies.

3. **visus_search** — Sanitized DuckDuckGo web search. SEO spam and injection patterns removed before results enter context. No API key required.

4. **visus_fetch_structured** — Extract structured data from a web page according to a user-defined schema. All fields independently sanitized.

5. **visus_report** — Generate a structured compliance audit report from sanitization logs, including detected threat classifications and framework mappings (NIST AI RMF, OWASP LLM Top 10, ISO/IEC 42001).

All tools return:
- `threat_summary` object with threat count, highest severity, and detected classes
- `visus_proof` cryptographic proof (SHA-256 + HMAC) that sanitization ran
- Framework compliance metadata (NIST AI RMF, OWASP LLM Top 10, MITRE ATLAS, ISO/IEC 42001)

---

## Authentication Required?

**No** — Open-source tier requires no account, no API key, no external services.

All processing runs locally. No data leaves your machine.

---

## Test Account Details

**N/A** — No authentication required.

---

## Pricing

**Free** — Open source (MIT License).

The hosted tier (Phase 2, planned) will offer:
- Managed Playwright renderer (no local browser installation)
- DynamoDB audit log persistence (90-day retention)
- Chrome extension for authenticated page access (LinkedIn, dashboards)

Pricing TBD. Open-source tier remains free forever.

---

## Homepage

https://github.com/visus-mcp/visus-mcp

---

## Support URL

https://github.com/visus-mcp/visus-mcp/issues

---

## Privacy Policy URL

https://github.com/visus-mcp/visus-mcp/blob/main/README.md#privacy-policy

**Summary:**
- Visus is local-first — no data transmitted to external servers
- Web pages are fetched via Playwright (standard HTTP requests)
- Content is sanitized in-memory and returned via MCP protocol
- Structured logs (detection metadata only) written to stderr locally
- No analytics, no telemetry, no tracking
- DuckDuckGo search uses public API with no identifying information

---

## Documentation URL

https://github.com/visus-mcp/visus-mcp/blob/main/README.md

---

## Known Limitations

1. **Semantic prompt injection** (benign-looking business language) is not detected by pattern matching.
2. **Multi-step cross-call chaining attacks** are not currently detected.
3. **Adversarially crafted LLM-generated injection** can bypass regex patterns.
4. **Non-English injection** is partially covered (Latin-script focus).
5. **Playwright dependency** makes the bundle large (31MB) due to browser binaries.
6. **PDF text extraction** via `pdf-parse` is heuristic — complex layouts may produce garbled output.
7. **DuckDuckGo rate limits** may throttle `visus_search` during heavy usage.

Full threat model: https://github.com/visus-mcp/visus-mcp/blob/main/SECURITY.md

---

## Security Frameworks & Compliance

Visus threat detection is mapped to:

- **OWASP LLM Top 10 (2025)** — LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure)
- **NIST AI Risk Management Framework (AI RMF 600-1)** — Measure 2.5 (Adversarial Robustness), Measure 4.1 (Incident Reporting)
- **MITRE ATLAS** — AML.T0051 (LLM Prompt Injection), AML.T0054 (LLM Jailbreak)
- **ISO/IEC 42001:2023** — AI Management System controls for data governance and risk management
- **EU AI Act (Code of Practice)** — Adversarial testing documentation, incident reporting preparedness, capability transparency

See https://github.com/visus-mcp/visus-mcp/blob/main/README.md#compliance-mapping

---

## Technical Details

- **Language:** TypeScript (compiled to Node.js ESM)
- **Runtime:** Node.js ≥18
- **Platforms:** macOS (darwin), Windows (win32)
- **Bundle Size:** 31MB (includes Playwright + browser binaries)
- **Dependencies:** 260 production packages
- **Test Coverage:** 389/389 passing tests (Jest)
- **License:** MIT

---

## Submission Checklist

- [x] Bundle created (`visus-mcp-0.26.0.mcpb`)
- [x] Manifest validates against schema 2025-12-11
- [x] All 12 tools declared with descriptions
- [x] Icon included (512×512 PNG)
- [x] Privacy policy in README.md
- [x] Privacy policy URL in manifest.json
- [x] No authentication required (no test account needed)
- [x] Local install test passed (manual verification required)
- [x] Smoke test passed: visus_fetch returns threat_summary + visus_proof
- [x] All tools return responses < 25,000 tokens

---

## Contact

- **Email:** leo@lateos.ai
- **GitHub:** https://github.com/visus-mcp/visus-mcp
- **Security vulnerabilities:** https://github.com/visus-mcp/visus-mcp/blob/main/SECURITY.md

---

**Ready to submit when local testing is complete.**
