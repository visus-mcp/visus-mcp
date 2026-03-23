# Visus — Secure Web Access for Claude

[![npm version](https://img.shields.io/npm/v/visus-mcp?color=crimson&label=npm)](https://www.npmjs.com/package/visus-mcp)
[![tests](https://img.shields.io/badge/tests-246%20passing-brightgreen)](https://github.com/visus-mcp/visus-mcp)
[![license](https://img.shields.io/badge/license-MIT-blue)](https://github.com/visus-mcp/visus-mcp/blob/main/LICENSE)
[![security](https://img.shields.io/badge/frameworks-NIST%20%7C%20OWASP%20%7C%20MITRE%20%7C%20ISO42001-orange)](https://github.com/visus-mcp/visus-mcp/blob/main/SECURITY.md)
[![iso42001](https://img.shields.io/badge/ISO%2FIEC-42001%3A2023-blueviolet)](https://www.iso.org/standard/81230.html)

> **Your AI agent shouldn't have to read garbage.**
> **visus-mcp makes sure it doesn't.**

When your agent fetches a webpage it reads everything — nav bars, cookie banners, tracking scripts, ads, SEO spam. Every token costs money. Some pages also embed hidden instructions designed to manipulate your agent's behaviour.

Claude handles most of it. But it still has to read all of it first. You still pay for every token.

**visus-mcp is a pre-filter.** It strips the noise before a single character enters Claude's context window — reducing token consumption on bloated pages by up to 70%, redacting PII before it enters conversation history, and producing a compliance-grade audit log when it finds something worth flagging.

Built as infrastructure, not a replacement for Claude's own safety training. The two layers together are stronger than either alone.
```bash
npx visus-mcp@0.6.0
```

*"What the web shows you, Lateos reads safely."*

---

## Why Your Agent Is Reading Too Much

A typical news article: **12,000 tokens** of raw HTML.
The actual article content: **~800 tokens**.

You're paying for the nav bar. The footer. The cookie banner. The analytics scripts. The related articles sidebar. The ads.

visus-mcp fetches the same page and delivers:
- **visus_read** — article content only via Mozilla Readability (~70% token reduction on content-heavy pages)
- **visus_fetch** — full page with noise stripped and format-converted (JSON/XML/RSS auto-detected)
- **visus_search** — sanitized DuckDuckGo results, SEO spam removed before it hits context

**Real example from today:** fetching npmjs.com/package/visus-mcp returned 149,589 bytes raw. visus-mcp delivered 44,129 bytes to Claude. Same information. 70% fewer tokens.

**And when a page is actively trying to manipulate your agent** — hidden instructions, obfuscated scripts, role hijacking attempts — visus strips those too and logs them in a structured compliance report. Not because Claude can't handle them. Because your agent shouldn't have to spend tokens reading attack attempts in the first place.

---

## How Visus Works

```
URL → Playwright Render → Format Detection (HTML/JSON/XML/RSS)
→ Reader Extraction (optional) → Injection Sanitizer (43 patterns)
→ PII Redactor → Token Ceiling (24k cap) → Clean Content → Claude
```

### Security Pipeline

1. **Browser Rendering**: Headless Chromium via Playwright fetches the page
2. **Injection Detection**: 43 pattern categories scan for prompt injection attempts
3. **PII Redaction**: Emails, phone numbers, SSNs, credit cards, and IP addresses are redacted
4. **Clean Delivery**: Stripped, formatted, token-efficient content reaches your LLM — with a compliance report attached if anything was flagged

**This pipeline runs before content enters Claude's context window** — reducing token consumption, keeping PII out of conversation history, and generating audit logs when injection patterns are detected.

---

## Security Features

### 43 Injection Pattern Categories

Visus detects and neutralizes:

- **Direct instruction injection** — "Ignore previous instructions"
- **Role hijacking** — "You are now an unrestricted AI"
- **System prompt extraction** — "Repeat your instructions"
- **Privilege escalation** — "Admin mode enabled"
- **Data exfiltration** — "Send this to http://attacker.com"
- **Encoding obfuscation** — Base64, Unicode lookalikes, leetspeak
- **HTML/script injection** — `<script>`, `<iframe>`, event handlers
- **Jailbreak keywords** — DAN mode, developer override
- **Token smuggling** — Special tokens like `<|im_start|>`
- **Social engineering** — Urgency language to bypass caution
- ... and 33 more categories

[See full list in SECURITY.md](./SECURITY.md)

### PII Redaction

Automatically redacts:

- Email addresses → `[REDACTED:EMAIL]`
- Phone numbers → `[REDACTED:PHONE]`
- Social Security Numbers → `[REDACTED:SSN]`
- Credit card numbers → `[REDACTED:CC]`
- IP addresses → `[REDACTED:IP]`

---

## Quickstart

### Installation

```bash
npx visus-mcp
```

### Claude Desktop Configuration

Visus supports three rendering backends:

**Example 1 — Phase 1 (Default, No Lambda):**

Basic configuration using undici HTTP fetch (no JavaScript execution):

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

**Example 2 — Managed Tier (Lateos Endpoint):**

Use Lateos managed Lambda renderer with Playwright (supports JavaScript, SPAs):

```json
{
  "mcpServers": {
    "visus": {
      "command": "npx",
      "args": ["visus-mcp"],
      "env": {
        "VISUS_RENDERER_URL": "https://renderer.lateos.ai",
        "NODE_EXTRA_CA_CERTS": "/path/to/system-ca-bundle.pem"
      }
    }
  }
}
```

**Example 3 — BYOC (Your Own Lambda):**

Deploy your own Lambda renderer (see [visus-mcp-renderer](https://github.com/visus-mcp/visus-mcp-renderer)):

```json
{
  "mcpServers": {
    "visus": {
      "command": "npx",
      "args": ["visus-mcp"],
      "env": {
        "VISUS_RENDERER_URL": "https://YOUR_API_ID.execute-api.YOUR_REGION.amazonaws.com",
        "NODE_EXTRA_CA_CERTS": "/path/to/system-ca-bundle.pem"
      }
    }
  }
}
```

Replace `YOUR_API_ID` and `YOUR_REGION` with values from your CDK deployment output.

**CRITICAL SECURITY NOTE:** The sanitizer ALWAYS runs locally, regardless of which renderer you use. Rendered HTML is returned to your local visus-mcp process before Claude sees it. PHI never touches Lateos infrastructure (even when using the managed tier).

Restart Claude Desktop. Visus tools are now available to Claude.

---

## MCP Tools

### `visus_fetch`

Fetch and sanitize a web page with automatic format detection. Supports HTML, JSON, XML, and RSS/Atom feeds. Includes NIST AI 600-1 / OWASP LLM / MITRE ATLAS aligned threat report when injection or PII is detected.

**Supported Formats:**
- **HTML** (`text/html`, `application/xhtml+xml`) - Standard web pages, returned as-is
- **JSON** (`application/json`) - API responses, formatted with 2-space indentation
- **XML** (`application/xml`, `text/xml`) - XML documents, converted to clean text representation
- **RSS/Atom** (`application/rss+xml`, `application/atom+xml`) - Feeds converted to Markdown with up to 10 items

### `visus_read`

Extract clean article content from a web page using Mozilla Readability (reader mode). Includes NIST AI 600-1 / OWASP LLM / MITRE ATLAS aligned threat report when injection or PII is detected.

**Input:**
```json
{
  "url": "https://example.com/article",
  "timeout_ms": 10000    // optional
}
```

**Output:**
```json
{
  "url": "https://example.com/article",
  "content": "This is the main article content, stripped of navigation, ads, and boilerplate...",
  "metadata": {
    "title": "Article Title",
    "author": "Jane Doe",
    "published": "2024-01-15T10:00:00Z",
    "word_count": 1250,
    "reader_mode_available": true,
    "sanitized": true,
    "injections_removed": 0,
    "pii_redacted": 1,
    "truncated": false,
    "fetched_at": "2024-01-15T10:30:00.000Z"
  }
}
```

### `visus_search`

Search the web via DuckDuckGo and return sanitized results with prompt injection and PII removed. Use before `visus_fetch` or `visus_read` to safely discover and then read pages. Includes NIST AI 600-1 / OWASP LLM / MITRE ATLAS aligned threat report when injection or PII is detected.

**Input:**
```json
{
  "query": "TypeScript programming",
  "max_results": 5    // optional, default: 5, max: 10
}
```

**Output:**
```json
{
  "query": "TypeScript programming",
  "result_count": 5,
  "sanitized": true,
  "results": [
    {
      "title": "TypeScript is a strongly typed programming language.",
      "url": "https://typescriptlang.org",
      "snippet": "TypeScript is a strongly typed programming language that builds on JavaScript...",
      "injections_removed": 0,
      "pii_redacted": 0
    }
  ],
  "total_injections_removed": 0
}
```

All search result titles and snippets are independently sanitized before reaching the LLM.

### `visus_fetch_structured`

Extract structured data from a web page according to a schema. Includes NIST AI 600-1 / OWASP LLM / MITRE ATLAS aligned threat report when injection or PII is detected.

**Input:**
```json
{
  "url": "https://shop.example.com/product",
  "schema": {
    "title": "product name",
    "price": "product price",
    "description": "product description"
  },
  "timeout_ms": 10000  // optional
}
```

**Output:**
```json
{
  "url": "https://shop.example.com/product",
  "data": {
    "title": "Awesome Product",
    "price": "$99.99",
    "description": "A great product for your needs"
  },
  "sanitization": {
    "patterns_detected": [],
    "pii_types_redacted": [],
    "content_modified": false
  },
  "metadata": {
    "title": "Product Page",
    "fetched_at": "2024-01-15T10:30:00.000Z",
    "content_length_original": 8000,
    "content_length_sanitized": 8000
  }
}
```

All extracted fields are individually sanitized.

---

## Threat Reporting

When prompt injection or PII is detected, Visus automatically generates a structured threat report with two output layers:

### 1. TOON-Formatted Findings (Token-Efficient)

Findings are encoded using [TOON format](https://toonformat.dev) for token efficiency while preserving machine readability. Each finding includes:

- Pattern ID and category
- Severity level (CRITICAL, HIGH, MEDIUM, LOW)
- Confidence score
- Framework alignments (OWASP LLM Top 10, NIST AI 600-1, MITRE ATLAS)
- Remediation status

### 2. Markdown Compliance Report (Human-Readable)

A formatted Markdown table renders cleanly in Claude Desktop and GitHub, showing:

- Overall severity assessment
- Findings summary by severity
- Detailed findings table with framework mappings
- PII redaction statistics
- Remediation confirmation

### Framework Alignments

Every detected threat is mapped to four compliance frameworks:

- **[OWASP LLM Top 10 (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)**: Industry-standard LLM security risks
- **[NIST AI 600-1](https://csrc.nist.gov/pubs/ai/600/1/final)**: Generative AI Profile for risk management
- **[MITRE ATLAS](https://atlas.mitre.org/)**: Adversarial Threat Landscape for AI Systems
- **[ISO/IEC 42001:2023](https://www.iso.org/standard/81230.html)**: International AI Management System standard — Annex A controls for AI system security, data quality, and responsible AI governance. Globally recognized for enterprise and regulatory procurement.

### When Reports Are Generated

Threat reports are included in tool responses **only when findings exist**:
- ✅ Injections detected → Report included
- ✅ PII redacted → Report included
- ❌ Clean content → Report omitted (zero overhead)

### Human-in-the-Loop Security

When Visus detects a **CRITICAL** severity threat, it pauses execution and surfaces a confirmation dialog before returning content:

```
⚠️ Visus blocked a CRITICAL threat on this page.

2 injection attempt(s) detected on: https://malicious.example.com

Highest severity finding: role_hijacking
(LLM01:2025 | AML.T0051.000)

Content has been sanitized. Proceed with clean version?

[ ✓ Proceed with sanitized content ]  [ ✓ Include threat report ]
```

**Three outcomes:**
- **Accept** → Sanitized content delivered, threat report attached if requested
- **Decline** → Request blocked, threat details returned for review
- **No response / timeout** → Sanitized content delivered (fail-safe)

**Important:** HITL triggers only on CRITICAL findings. HIGH/MEDIUM/LOW findings are sanitized silently with threat report attached — no interruption to workflow.

**Security model:** Sanitization is the security gate. HITL is UX. Content is ALWAYS sanitized before reaching the LLM, whether or not you accept the elicitation prompt.

### Example Threat Report

When a HIGH severity injection is detected:

```markdown
---
## 🟠 Visus Threat Report
**Generated:** 2026-03-23T14:30:00.000Z
**Source:** https://malicious.example.com
**Overall Severity:** HIGH
**Framework:** OWASP LLM Top 10 | NIST AI 600-1 | MITRE ATLAS | ISO/IEC 42001

### Findings Summary
| Severity | Count |
|---|---|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 1 |
| 🟡 MEDIUM | 0 |
| 🟢 LOW | 0 |

### Findings Detail
| # | Category | Severity | Confidence | OWASP | MITRE |
|---|---|---|---|---|---|
| 1 | role_hijacking | CRITICAL | 95% | LLM01:2025 | AML.T0051.000 |

### Remediation Status
✅ All findings sanitized. Content delivered clean.

*Report generated by Visus MCP — Security-first web access for Claude*
---
```

**Note:** PDF export for compliance artifacts is on the roadmap for a future `visus_report` tool.

---

## Examples

### Example 1: Public Health Page with PII Allowlist

Fetching a MedlinePlus health information page demonstrates both injection pattern detection and the domain-scoped PII allowlist feature.

**Tool Call:**
```json
{
  "url": "https://medlineplus.gov/poisoning.html",
  "format": "markdown"
}
```

**Sanitized Output (excerpt):**
```json
{
  "url": "https://medlineplus.gov/poisoning.html",
  "content": "# Poisoning\n\n**Call 1-800-222-1222** for immediate help...\n\n**Contact:** [REDACTED:EMAIL] for general inquiries...",
  "sanitization": {
    "patterns_detected": [],
    "pii_types_redacted": ["email"],
    "pii_allowlisted": [
      {
        "type": "phone",
        "value": "1-800-222-1222",
        "reason": "Trusted health authority number on medlineplus.gov (Poison Control)"
      }
    ],
    "content_modified": true
  },
  "metadata": {
    "title": "Poisoning: MedlinePlus",
    "content_length_original": 15234,
    "content_length_sanitized": 15180
  }
}
```

**What Visus caught:** Regular email addresses were redacted (`[REDACTED:EMAIL]`), but the Poison Control hotline number was preserved because it appears on a trusted `.gov` health domain. This demonstrates the PII allowlist in action — critical health resources remain accessible while general contact info is scrubbed.

---

### Example 2: Structured Data Extraction from Documentation

Extract navigation links and headings from a documentation page.

**Tool Call:**
```json
{
  "url": "https://docs.github.com/en",
  "schema": {
    "main_heading": "h1",
    "first_link": "link url",
    "first_link_text": "link text",
    "description": "paragraph text"
  }
}
```

**Sanitized Output:**
```json
{
  "url": "https://docs.github.com/en",
  "data": {
    "main_heading": "GitHub Docs",
    "first_link": "/en/get-started",
    "first_link_text": "Get started",
    "description": "Help for wherever you are on your GitHub journey."
  },
  "sanitization": {
    "patterns_detected": [],
    "pii_types_redacted": [],
    "pii_allowlisted": [],
    "content_modified": false
  },
  "metadata": {
    "title": "GitHub Docs",
    "content_length_original": 45123,
    "content_length_sanitized": 45123
  }
}
```

**What Visus caught:** This page was clean — no injection patterns or PII detected. The structured extraction returned all requested fields with `content_modified: false`, indicating the sanitizer validated the content but made no changes.

---

### Example 3: JavaScript-Heavy SPA with Playwright Rendering

Modern single-page applications require JavaScript execution. Visus uses headless Chromium via Playwright to render dynamic content before sanitization.

**Tool Call:**
```json
{
  "url": "https://github.com/anthropics/anthropic-sdk-typescript",
  "format": "markdown",
  "timeout_ms": 15000
}
```

**Sanitized Output (excerpt):**
```json
{
  "url": "https://github.com/anthropics/anthropic-sdk-typescript",
  "content": "# anthropic-sdk-typescript\n\n**Repository:** anthropics/anthropic-sdk-typescript\n\n**Description:** TypeScript SDK for Anthropic's Claude API...\n\n**Latest commit:** [REDACTED:COMMIT_HASH] by [REDACTED:EMAIL]...",
  "sanitization": {
    "patterns_detected": [],
    "pii_types_redacted": ["email"],
    "pii_allowlisted": [],
    "content_modified": true
  },
  "metadata": {
    "title": "GitHub - anthropics/anthropic-sdk-typescript",
    "content_length_original": 23456,
    "content_length_sanitized": 23401
  }
}
```

**What Visus caught:** The page rendered completely via Playwright (including React components, lazy-loaded content, and dynamic navigation). Email addresses in commit author fields were redacted. No injection patterns were detected in this legitimate repository page.

**Key difference from static fetchers:** Tools like `curl` or basic HTTP clients would return an empty `<div id="root">` for SPAs. Visus renders the full JavaScript application before sanitization, ensuring you get the actual page content Claude sees.

---

### Example 4: Reader Mode for Context-Efficient Article Reading

When you need clean article content without navigation clutter, use `visus_read` to extract the main text using Mozilla Readability.

**Tool Call:**
```json
{
  "url": "https://en.wikipedia.org/wiki/Prompt_injection",
  "timeout_ms": 15000
}
```

**Sanitized Output (excerpt):**
```json
{
  "url": "https://en.wikipedia.org/wiki/Prompt_injection",
  "content": "Prompt injection is a type of cyberattack that involves adding malicious instructions to a prompt for an AI system...\n\n[Main article content continues, stripped of navigation, sidebars, and Wikipedia UI elements]\n\nSee also:\n- AI safety\n- Adversarial machine learning\n- Computer security...",
  "metadata": {
    "title": "Prompt injection - Wikipedia",
    "author": null,
    "published": null,
    "word_count": 892,
    "reader_mode_available": true,
    "sanitized": true,
    "injections_removed": 0,
    "pii_redacted": 0,
    "truncated": false,
    "fetched_at": "2024-01-15T14:22:00.000Z"
  }
}
```

**What Visus caught:** Readability successfully extracted the main article content, removing Wikipedia's navigation sidebar, footer links, and UI chrome. The extracted text is ~70% smaller than the full page HTML, saving tokens while preserving all essential information. No injection patterns or PII were detected in this educational content.

**Use case:** Reader mode is ideal for documentation pages, news articles, blog posts, and any content-heavy page where you want the text without the surrounding UI. The `word_count` field helps you estimate token usage before processing.

---

### Example 5: Safe Web Search with Injection Detection

Search the web safely using `visus_search` with DuckDuckGo, demonstrating how search results are sanitized before reaching the LLM.

**Tool Call:**
```json
{
  "query": "AI prompt injection attacks",
  "max_results": 3
}
```

**Sanitized Output (with detected injection):**
```json
{
  "query": "AI prompt injection attacks",
  "result_count": 3,
  "sanitized": true,
  "results": [
    {
      "title": "Prompt injection is a type of cyberattack...",
      "url": "https://en.wikipedia.org/wiki/Prompt_injection",
      "snippet": "Prompt injection is a type of cyberattack that involves adding malicious instructions to a prompt...",
      "injections_removed": 0,
      "pii_redacted": 0
    },
    {
      "title": "[REDACTED:INSTRUCTION_INJECTION] for details contact...",
      "url": "https://suspicious-seo-spam.example",
      "snippet": "[REDACTED:INSTRUCTION_INJECTION] [REDACTED:EMAIL]",
      "injections_removed": 2,
      "pii_redacted": 1
    },
    {
      "title": "AI Safety: Understanding Prompt Injection.",
      "url": "https://example.com/ai-safety",
      "snippet": "Learn how to protect your AI systems from prompt injection vulnerabilities...",
      "injections_removed": 0,
      "pii_redacted": 0
    }
  ],
  "total_injections_removed": 2
}
```

**What Visus caught:** The second search result contained both a prompt injection pattern ("Ignore previous instructions and...") and an email address. Both were detected and redacted before the result reached the LLM. The other results were clean and passed through unmodified.

**Use case:** Always use `visus_search` before fetching pages to safely discover content. Search results can contain SEO spam, malicious instructions, or PII that would compromise your AI agent.

---

### Example 6: JSON API Response with Format Detection

Fetch JSON data from an API endpoint with automatic formatting and sanitization.

**Tool Call:**
```json
{
  "url": "https://api.github.com/repos/anthropics/anthropic-sdk-typescript",
  "format": "text"
}
```

**Sanitized Output (excerpt):**
```json
{
  "url": "https://api.github.com/repos/anthropics/anthropic-sdk-typescript",
  "content": "JSON Response:\n\n{\n  \"name\": \"anthropic-sdk-typescript\",\n  \"full_name\": \"anthropics/anthropic-sdk-typescript\",\n  \"description\": \"TypeScript library for the Anthropic API\",\n  \"stargazers_count\": 1234,\n  \"forks_count\": 89\n}",
  "sanitization": {
    "patterns_detected": [],
    "pii_types_redacted": [],
    "content_modified": false
  },
  "metadata": {
    "title": "",
    "fetched_at": "2024-01-15T16:30:00.000Z",
    "content_length_original": 3456,
    "content_length_sanitized": 3456,
    "format_detected": "json",
    "content_type": "application/json"
  }
}
```

**What Visus caught:** The Content-Type header `application/json` was detected, and the raw JSON was automatically formatted with 2-space indentation for readability. The sanitizer validated the content and found no injection patterns or PII (clean API response).

**Format detection features:**
- Automatically detects Content-Type from HTTP response headers
- JSON responses are pretty-printed with indentation
- XML/RSS feeds are converted to clean Markdown
- All formats pass through the sanitizer pipeline
- `format_detected` and `content_type` included in metadata

---

### Example 7: RSS Feed with Automatic Markdown Conversion

Fetch an RSS feed and have it automatically converted to clean Markdown format.

**Tool Call:**
```json
{
  "url": "https://blog.example.com/feed.xml"
}
```

**Sanitized Output (excerpt):**
```json
{
  "url": "https://blog.example.com/feed.xml",
  "content": "RSS Feed:\n\n# Example Blog\nThe latest news and updates\n\n## Items\n\n### New Feature Release\n\nWe're excited to announce our latest feature update...\n\nLink: https://blog.example.com/new-feature\nPublished: Mon, 15 Jan 2024 10:00:00 GMT\n\n---\n\n### Security Best Practices\n\nLearn about the latest security recommendations...\n\nLink: https://blog.example.com/security\nPublished: Tue, 16 Jan 2024 14:30:00 GMT\n\n---",
  "sanitization": {
    "patterns_detected": [],
    "pii_types_redacted": [],
    "content_modified": false
  },
  "metadata": {
    "title": "",
    "fetched_at": "2024-01-15T16:45:00.000Z",
    "content_length_original": 5678,
    "content_length_sanitized": 5678,
    "format_detected": "rss",
    "content_type": "application/rss+xml"
  }
}
```

**What Visus caught:** The Content-Type header `application/rss+xml` triggered RSS feed parsing. The feed XML was converted to clean Markdown showing the channel title, description, and up to 10 feed items with titles, links, descriptions (truncated to 200 chars), and publication dates. All content was sanitized for injection patterns.

**RSS/Atom support:**
- RSS 2.0, RSS 1.0 (RDF), and Atom feed formats supported
- Extracts channel metadata and up to 10 items
- Converts to clean Markdown with proper formatting
- Item descriptions truncated to 200 characters for readability
- Graceful fallback to XML parsing for invalid feeds

---

### Safe Research Loop (3-Step Workflow)

Combine all three tools for safe, context-efficient web research:

**Step 1: Discover** – Use `visus_search` to find relevant pages safely:
```json
{
  "query": "TypeScript async patterns",
  "max_results": 5
}
```

**Step 2: Read** – Use `visus_read` to extract clean article content:
```json
{
  "url": "https://blog.example.com/typescript-async-guide"
}
```

**Step 3: Extract** – Use `visus_fetch_structured` to pull specific data:
```json
{
  "url": "https://docs.typescript.com/reference/async",
  "schema": {
    "syntax": "async/await syntax",
    "example": "code example",
    "best_practices": "recommended patterns"
  }
}
```

All three steps run content through the sanitization pipeline, ensuring end-to-end security from search to extraction.

---

## Environment Variables

```bash
# Optional — for Lateos hosted tier features (Phase 2)
LATEOS_API_KEY=your-api-key          # Enables audit logging to Lateos cloud
LATEOS_ENDPOINT=https://api.lateos.ai

# Optional — browser config
VISUS_TIMEOUT_MS=10000   # Default fetch timeout (milliseconds)
VISUS_MAX_CONTENT_KB=512 # Max content size before truncation (kilobytes)
```

**No API key required for open-source tier.** `npx visus-mcp` works out of the box.

---

##  Lateos Platform

Visus is part of the **Lateos** platform — a security-by-design AI agent framework:

- **AWS Serverless**: Lambda, Step Functions, API Gateway, Cognito
- **Security**: Bedrock Guardrails, KMS encryption, Secrets Manager
- **Validated Patterns**: 43 injection patterns, 274/274 passing tests
- **CISSP/CEH-Informed**: Designed by security professionals

Learn more: [lateos.ai](https://lateos.ai) (Phase 2)

---

## Development

### Prerequisites

**macOS / Windows:** No additional setup required.

**Linux:** Playwright requires the following system libraries. Install them before running `npm install`:

```bash
# Ubuntu / Debian
sudo apt-get install -y \
  libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
  libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
  libxrandr2 libgbm1 libnss3 libxss1 libasound2

# Fedora / RHEL
sudo dnf install -y atk at-spi2-atk libXrandr libgbm \
  nss alsa-lib libXss cups-libs libdrm libxkbcommon
```

> If `npm test` fails with a Chromium launch error on Linux, see [TROUBLESHOOT-PLAYWRIGHT.md](./TROUBLESHOOT-PLAYWRIGHT-20260321-1549.md) for detailed troubleshooting steps.

```bash
# Clone repo
git clone https://github.com/visus-mcp/visus-mcp.git
cd visus-mcp

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Start MCP server
npm start
```

---

## Project Status

| Version | Status | Highlights |
|---|---|---|
| v0.6.0 | ✅ Current | Content-Type detection (JSON/XML/RSS) |
| v0.5.0 | ✅ Released | TOON threat reports, NIST/OWASP/MITRE/ISO42001 |
| v0.4.0 | ✅ Released | Safe DuckDuckGo search |
| v0.3.2 | ✅ Released | Reader mode (Mozilla Readability) |
| v0.3.1 | ✅ Released | Security hardening, 100% compliance |
| v0.3.0 | ✅ Released | PII allowlist (health authority numbers) |

**Phase 3 — Anthropic MCP Directory submission in progress.**

Roadmap: `visus_report` PDF export · Docker image ·
`visus-file-mcp` (document sanitization) ·
Chrome extension for authenticated pages (LinkedIn, X, dashboards)

---

## Security

For detailed threat model, pattern examples, and vulnerability reporting:

**[→ Read SECURITY.md](./SECURITY.md)**

Report vulnerabilities: **security@lateos.ai** or [GitHub Security](https://github.com/visus-mcp/visus-mcp/security)

---

## License

MIT License

Copyright (c) 2026 Lateos (Leo Chongolnee)

---

## Credits

Built by [Leo Chongolnee](https://github.com/leochong) (@leochong) as part of the Lateos platform.

Inspired by the MCP ecosystem and informed by CISSP/CEH security principles.

---

## FAQ

**Q: Does visus-mcp replace Claude's own safety features?**
A: No — and it's not trying to. Claude handles most injection attempts natively through its safety training. visus-mcp is a pre-filter that runs before content enters Claude's context window. The benefit is efficiency: your agent doesn't spend tokens processing noise, ads, tracking scripts, or known injection patterns that would be stripped anyway. Think of it as a pre-processor, not a replacement for model-level safety. The two layers together are more robust than either alone.

**Q: Does Visus slow down web fetching?**
A: Minimal overhead. Sanitization adds ~50-200ms per page.

**Q: Can attackers bypass the sanitizer?**
A: Novel obfuscation techniques or AI-generated benign-looking instructions may evade detection. See [SECURITY.md](./SECURITY.md) for honest limitations.

**Q: Does Visus work with authenticated pages?**
A: Phase 1 uses headless-only rendering. Phase 2 will add user session relay via Chrome extension.

**Q: How does Visus compare to Firecrawl?**
A: Firecrawl is excellent for web scraping but doesn't sanitize for prompt injection. Visus focuses on **security-first** content delivery.

**Q: Is Visus free?**
A: Yes! Open-source tier is free forever. Phase 2 will introduce a hosted tier with SLA guarantees for enterprise use.

---

**Built with by Lateos**
