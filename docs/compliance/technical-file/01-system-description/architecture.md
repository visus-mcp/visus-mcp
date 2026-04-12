# Visus-MCP Technical Architecture (Annex IV §1.2)

## High-Level Architecture
Visus-MCP is a modular, stateless pipeline implemented in TypeScript/Node.js. It interfaces via Model Context Protocol (MCP) stdio, processes content locally, and outputs sanitized data with proofs. No external dependencies beyond Playwright (local) and optional AWS Lambda renderer.

### Key Components
1. **MCP Interface:** Stdio server handles tool calls (e.g., `visus_fetch`).
2. **Renderer:** Playwright (Chromium) for JS execution; Fallback: Native fetch.
3. **Content Router:** MIME-type detection routes to handlers (HTML/PDF/JSON/SVG).
4. **Threat Pipeline:** IPI (19 cats) → Injection Sanitizer (45 patterns) → Worm Detector → PII Redactor.
5. **Proof & Logging:** Crypto proofs (SHA-256/HMAC) + Immutable Merkle Ledger.
6. **Output:** Sanitized content + metadata (threat_summary, merkle_root, proof).

**Stateless Design:** No persistent model weights/training data; Session state in Ledger only (append-only, verifiable).

### Data Flow Diagram
```mermaid
graph TD
  A[MCP Client<br/>e.g., Claude Desktop] --> B[visus-mcp Stdio Server<br/>index.ts]
  B --> C[Renderer: Playwright/Chromium<br/>playwright-renderer.ts]
  C --> D[Content-Type Router<br/>content-handlers/index.ts]
  D -->|HTML/JS| E[IPI Detector (19 cats)<br/>ThreatDetector.ts]
  D -->|PDF/JSON/SVG| F[Specialized Handlers<br/>pdf/json-handlers.ts]
  E --> G[Injection Sanitizer (45 patterns)<br/>sanitizer/index.ts]
  F --> G
  G --> H[Worm Detector (15 patterns)<br/>worm-detector.ts]
  H --> I[PII Redactor + Allowlist<br/>pii-redactor.ts]
  I --> J[Crypto Proof Builder<br/>proof-builder.ts]
  J --> K[Immutable Session Ledger<br/>Merkle Tree (SHA-256)<br/>ImmutableLedger.ts]
  K --> L[Output: Sanitized Content +<br/>visus_proof + threat_summary +<br/>merkle_root + inclusion_proof]
  L --> A

  style A fill:#f9f
  style L fill:#f9f
  style K fill:#ff9
```

**Data Flows Explained:**
- **Input:** MCP tool params (e.g., URL) → Stateless processing.
- **Processing:** All ops local; No cloud unless VISUS_RENDERER_URL set (Phase 2).
- **Output:** JSON with Result<T> (ok/value or error); Proofs embedded for verification.
- **Logging:** Stderr JSON (structured); Ledger to audit/ledger-YYYY-MM-DD.jsonl.

**Dependencies:** merkletreejs (Merkle), crypto (built-in hashes), playwright (rendering). Vulnerabilities: NVD-monitored via npm audit.

**Scalability:** Local: 1 req/sec; Hosted: 10k req/day (Lambda concurrency).

**Interface:** MCP tools (11 total); Outputs conform to schemas in src/types.ts.
