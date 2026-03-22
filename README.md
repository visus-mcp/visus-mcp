# Visus — Secure Web Access for Claude

> **Every MCP browser tool passes raw web content to your LLM. Visus doesn't.**

Visus is an MCP (Model Context Protocol) tool that provides Claude with secure, sanitized access to web pages. Built by [Lateos](https://lateos.ai), Visus runs **all** fetched content through a comprehensive injection sanitization pipeline before the LLM reads a single character.

**Tagline:** *"What the web shows you, Lateos reads safely."*

---

## The Problem with Other Tools

Popular MCP browser tools like Firecrawl, Playwright MCP, and ScrapeGraphAI pass untrusted web content directly to your LLM without sanitization. This creates a **critical security vulnerability**:

- **Prompt injection attacks** can manipulate AI behavior
- **Personal identifiable information (PII)** can leak into conversation logs
- **Malicious instructions** hidden in web pages can compromise your AI agent

Visus solves this by treating **every web page as untrusted input** and sanitizing it before your LLM sees it.

---

## How Visus Works

```
User provides URL → Playwright Fetch → Injection Sanitizer (43 patterns) →
PII Redactor → Clean Content → Claude via MCP
```

### Security Pipeline

1. **Browser Rendering**: Headless Chromium via Playwright fetches the page
2. **Injection Detection**: 43 pattern categories scan for prompt injection attempts
3. **PII Redaction**: Emails, phone numbers, SSNs, credit cards, and IP addresses are redacted
4. **Clean Delivery**: Only sanitized content reaches your LLM

**This pipeline cannot be bypassed.** Every tool invocation runs content through the full sanitizer.

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

Fetch and sanitize a web page.

### `visus_read`

Extract clean article content from a web page using Mozilla Readability (reader mode).

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

Search the web via DuckDuckGo and return sanitized results with prompt injection and PII removed. Use before `visus_fetch` or `visus_read` to safely discover and then read pages.

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

Extract structured data from a web page according to a schema.

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
- **Validated Patterns**: 43 injection patterns, 122/122 passing tests
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

**Phase 1** (Current): Open-source MCP tool with local sanitization

**Phase 2** (Planned):
- Lateos cloud integration for audit logging
- User session relay for authenticated pages
- Hosted tier with SLA guarantees

**Phase 3** (Future):
- Chrome extension for session relay
- Real-time threat dashboard
- Custom pattern libraries

---

## Security

For detailed threat model, pattern examples, and vulnerability reporting:

**[→ Read SECURITY.md](./SECURITY.md)**

Report vulnerabilities: **security@lateos.ai** or [GitHub Security](https://github.com/visus-mcp/visus-mcp/security)

---

## License

MIT License

Copyright (c) 2024 Lateos (Leo Chongolnee)

---

## Credits

Built by [Leo Chongolnee](https://github.com/leochong) (@leochong) as part of the Lateos platform.

Inspired by the MCP ecosystem and informed by CISSP/CEH security principles.

---

## FAQ

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
