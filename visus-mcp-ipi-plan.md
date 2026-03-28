# visus-mcp: Indirect Prompt Injection Protection
## Project Plan + Claude Code Prompt

---

## Project Plan

### Context & Current State

visus-mcp v0.8.0 already sanitizes web content before it reaches the LLM context window. The existing pipeline strips obvious threats but treats detection as implicit — content either passes or is blocked, with no structured record of *what* was detected, *why*, or at *what confidence*. 

This project makes detection **explicit, typed, and auditable**. The goal is not to add a new feature — it's to surface and formalize the security intelligence that already exists in the pipeline.

---

### Threat Taxonomy (v1)

Eight attack classes, each with its own detector:

| Class | ID | Description |
|---|---|---|
| Instruction Override | `IPI-001` | "Ignore previous instructions", "New system prompt:", etc. |
| Role Hijacking | `IPI-002` | Adversarial persona assignment ("You are now DAN...") |
| Data Exfiltration | `IPI-003` | Attempts to extract context, keys, or history |
| Tool Abuse | `IPI-004` | Directs LLM to invoke tools destructively |
| Context Poisoning | `IPI-005` | Subtle misinformation designed to alter downstream reasoning |
| Encoded Payload | `IPI-006` | Base64, hex, unicode obfuscation embedding instructions |
| Steganographic | `IPI-007` | Zero-width chars, hidden HTML, markdown injection |
| Multi-vector | `IPI-008` | Injection split across content chunks or content types |

---

### Versioned Threat Report Schema

```typescript
interface ThreatAnnotation {
  id: string;              // e.g. "IPI-001"
  class: ThreatClass;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;      // 0.0–1.0
  offset: number;          // character offset in source content
  excerpt: string;         // redacted snippet for audit
  vector: ContentType;     // "html" | "pdf" | "json" | "svg" | "text"
  mitigated: boolean;
}

interface ThreatReport {
  schema_version: "2.0";
  tool_invocation_id: string;
  source_url: string;
  content_type: ContentType;
  scan_duration_ms: number;
  threat_count: number;
  aggregate_severity: Severity;
  annotations: ThreatAnnotation[];
  multi_vector_correlation?: MultiVectorCorrelation;
  hitl_escalated: boolean;
}
```

This replaces/extends the current TOON-encoded report. TOON v2 wraps this schema.

---

### Milestones

#### v0.9.0 — Threat Detection Engine
**Target: ~2 weeks**

- [ ] Define `ThreatClass`, `ThreatAnnotation`, `ThreatReport` TypeScript interfaces in `src/types/threats.ts`
- [ ] Build `ThreatDetector` class: runs all IPI-001–007 detectors against a content chunk
- [ ] Implement pattern library: regex + heuristic detectors per class
- [ ] Wire `ThreatDetector` into existing content-type handlers (HTML, PDF, JSON, SVG)
- [ ] Per-chunk annotation: each handler returns `{ sanitized: string, threats: ThreatAnnotation[] }`
- [ ] Unit tests: minimum 2 positive + 2 negative + 1 edge case per detector class (~56 new tests)
- [ ] Update CLAUDE.md Known Errors Registry with new detector edge cases

**Stop condition**: All existing 294 tests still pass. New tests ≥ 320 total, 0 failures.

---

#### v0.9.1 — Structured Threat Reports + TOON v2
**Target: ~1 week**

- [ ] Implement `ThreatReportBuilder`: aggregates per-chunk annotations into a `ThreatReport`
- [ ] Severity aggregation logic: `aggregate_severity` = max severity across all annotations
- [ ] Confidence scoring: weighted average with floor logic (CRITICAL always wins)
- [ ] TOON v2 encoder: wraps `ThreatReport` in existing TOON envelope with `schema_version: "2.0"`
- [ ] Update `visus_fetch`, `visus_fetch_structured`, `visus_read` tool responses to include `threat_report` field
- [ ] Update HITL escalation bridge: trigger on `aggregate_severity === "CRITICAL"` OR `threat_count > threshold`
- [ ] Integration tests: end-to-end fetch → detect → report → TOON encode

**Stop condition**: `visus_fetch` on a known-malicious URL returns a valid `ThreatReport` with ≥1 annotation.

---

#### v0.9.2 — Multi-vector Correlation (IPI-008)
**Target: ~1 week**

- [ ] Implement `SessionThreatAccumulator`: tracks annotations across multiple tool invocations in a session
- [ ] Cross-content-type correlation: detect injection patterns split across e.g. PDF + JSON from same domain
- [ ] Threat elevation logic: two MEDIUM threats from the same domain in one session → elevate to HIGH
- [ ] `MultiVectorCorrelation` object appended to `ThreatReport` when triggered
- [ ] Session TTL: accumulator state expires after configurable window (default: 30 min)
- [ ] Tests: multi-fetch scenarios with coordinated injection across content types

**Stop condition**: Split-vector test (PDF + JSON with coordinated injection) correctly detected and elevated.

---

#### v1.0.0 — Audit, Observability & Hardening
**Target: ~1 week**

- [ ] Structured audit log per invocation: append-only, NDJSON format, written to configurable path
- [ ] Adversarial test corpus: 20+ real-world injection samples (pulled from public red-team datasets)
- [ ] Benchmark suite: measure detector false positive rate against benign corpus (target: <2% FPR)
- [ ] HITL escalation hardening: deduplicate repeated escalations for same threat pattern
- [ ] README: "Security Architecture" section documenting threat taxonomy, schema, and report structure
- [ ] Total test count target: ≥ 370

**Stop condition**: Benchmark report generated. FPR <2%. All 370+ tests pass. README updated.

---

### Test Philosophy

Every new detector must have:
1. **True positive**: content that IS the attack → correctly flagged
2. **True negative**: benign content that resembles the pattern → NOT flagged
3. **Obfuscated variant**: the same attack, encoded or split → still flagged
4. **Edge case**: boundary condition (empty content, max-length, Unicode) → no crash

---

### What This Unlocks for Lateos

- visus-mcp becomes the only open-source MCP server that returns **structured, versioned security intelligence** per fetch — not just sanitized content
- The `ThreatReport` is a natural upsell surface: "Want audit logs, KMS-encrypted report storage, and cross-session correlation history? → Lateos managed tier"
- CVE-2026-25475 talking point sharpens: "OpenClaw leaked credentials. visus-mcp detected the exfiltration attempt and reported it as IPI-003 with CRITICAL severity before the token ever reached the model."

---
---

## Claude Code Prompt

Paste this into a fresh Claude Code session with your CLAUDE.md in scope.

---

```
You are working on visus-mcp (https://github.com/visus-mcp/visus-mcp), a security-focused MCP server that sanitizes web content before it reaches an LLM context window. The current version is v0.11.0 with 389/389 tests passing and Phase 1 content-type handlers (PDF, JSON, SVG, HTML) complete, plus IPI threat detection system.

## Objective

Implement the Indirect Prompt Injection (IPI) Protection system as described below. This is v0.9.0 scope only. Do NOT implement v0.9.1 or later milestones in this session.

---

## Pre-flight Checklist (Complete Before Writing Any Code)

1. Run `npm test` and confirm 389/389 passing. Record the result.
2. Read `src/types/` — understand the existing type structure.
3. Read `src/handlers/` — understand how content-type handlers currently return sanitized content.
4. Read `src/tools/` — understand how `visus_fetch`, `visus_fetch_structured`, and `visus_read` invoke handlers.
5. Read `CLAUDE.md` Known Errors Registry — check for any relevant prior issues.
6. Confirm TypeScript strict mode is enabled in `tsconfig.json`.

---

## Deliverables for v0.9.0

### 1. New file: `src/types/threats.ts`

Define the following TypeScript types with JSDoc comments:

```typescript
export type ThreatClass =
  | "IPI-001" // Instruction Override
  | "IPI-002" // Role Hijacking
  | "IPI-003" // Data Exfiltration
  | "IPI-004" // Tool Abuse
  | "IPI-005" // Context Poisoning
  | "IPI-006" // Encoded Payload
  | "IPI-007" // Steganographic
  | "IPI-008"; // Multi-vector (reserved for v0.9.2)

export type ThreatSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ContentType = "html" | "pdf" | "json" | "svg" | "text";

export interface ThreatAnnotation {
  id: ThreatClass;
  severity: ThreatSeverity;
  confidence: number; // 0.0–1.0
  offset: number;     // character offset in source content
  excerpt: string;    // max 120 chars, redacted if sensitive
  vector: ContentType;
  mitigated: boolean;
}

export interface HandlerResult {
  sanitized: string;
  threats: ThreatAnnotation[];
  contentType: ContentType;
}
```

### 2. New file: `src/security/ThreatDetector.ts`

Implement a `ThreatDetector` class with:

- A `scan(content: string, contentType: ContentType): ThreatAnnotation[]` method
- Separate private detector methods for IPI-001 through IPI-007
- Each detector returns `ThreatAnnotation[]` (empty array = no threat found)
- All detectors run on every scan (no short-circuit); annotations are accumulated

**Detector specifications:**

**IPI-001 (Instruction Override)** — CRITICAL
- Patterns: "ignore previous instructions", "ignore all prior", "disregard your", "new system prompt", "override your instructions", "forget everything", "your new instructions are", case-insensitive
- Confidence: 0.95 for exact match, 0.75 for partial/variant

**IPI-002 (Role Hijacking)** — HIGH
- Patterns: "you are now", "act as", "pretend you are", "roleplay as", "you must behave as", "your persona is", followed by a non-Claude/non-assistant identity
- Heuristic: check if the pattern appears in a `<script>`, `<meta>`, JSON value, or PDF annotation (not user-visible body text) — elevate confidence to 0.9 if so

**IPI-003 (Data Exfiltration)** — CRITICAL
- Patterns: "send your context", "repeat your system prompt", "output your instructions", "what were you told", "relay all messages", "email the above", "POST to", combined with a URL or email pattern
- Also flag: any `fetch()`, `XMLHttpRequest`, `curl`, or `wget` invocation in non-code content

**IPI-004 (Tool Abuse)** — HIGH
- Patterns: directive language ("call the", "invoke", "execute", "run the tool") followed by common tool/function names ("delete", "write", "send", "bash", "shell", "execute_code", "file_write")
- Confidence: 0.85 for directive + destructive verb, 0.6 for directive alone

**IPI-005 (Context Poisoning)** — MEDIUM
- Heuristic (no single pattern): look for factual assertion blocks that contradict well-known constants — e.g., "the current date is [implausible date]", "your name is [non-Claude name]", "you previously said [invented statement]"
- Flag as MEDIUM/0.55 confidence — this is intentionally conservative to keep FPR low

**IPI-006 (Encoded Payload)** — HIGH
- Detect base64 strings > 50 chars that decode to text containing IPI-001/002/003/004 patterns
- Detect hex-encoded strings > 20 chars that decode similarly
- Detect unicode look-alike substitution (Cyrillic/Greek chars substituted for Latin)
- Confidence: 0.9 if decoded content matches another detector, 0.6 if encoding alone is suspicious

**IPI-007 (Steganographic)** — HIGH
- Detect zero-width characters: U+200B, U+200C, U+200D, U+FEFF, U+2060
- Detect HTML hidden text: `display:none`, `visibility:hidden`, `opacity:0`, `color:white` on white bg, `font-size:0`
- Detect HTML comment injection: `<!-- [instruction-like content] -->`
- Detect markdown link injection: `[visible text](javascript:...)` or unusual protocol URLs

### 3. Update existing content-type handlers

Modify each handler in `src/handlers/` to:
- Import `ThreatDetector` and `HandlerResult`
- Instantiate `ThreatDetector` and call `scan()` on the raw content BEFORE sanitization
- Return `HandlerResult` instead of `string`
- Set `mitigated: true` on all annotations (content was sanitized)

Do NOT change the sanitization logic itself — only add the detection layer on top.

### 4. Update tool response schemas

Modify `visus_fetch`, `visus_fetch_structured`, and `visus_read` to:
- Accept `HandlerResult` from handlers (not raw `string`)
- Include a `threat_summary` field in the tool response:
  ```typescript
  threat_summary: {
    threat_count: number;
    highest_severity: ThreatSeverity | "NONE";
    classes_detected: ThreatClass[];
  }
  ```
- Pass `threats` array through to HITL bridge (existing logic unchanged — HITL already triggers on CRITICAL)

### 5. Tests

Create `src/security/__tests__/ThreatDetector.test.ts`.

For each detector (IPI-001 through IPI-007), write:
- 2 true positive tests (content that IS the attack)
- 2 true negative tests (benign content that resembles the pattern)
- 1 obfuscated variant (same attack, encoded or split)
- 1 edge case (empty string, max-length, Unicode boundary)

Minimum: 56 new tests. All must pass. All 294 existing tests must still pass.

---

## Stop Conditions (Mandatory)

STOP and report to the user before proceeding if:
1. Any existing test fails after your changes.
2. TypeScript compilation emits errors in strict mode.
3. A handler's sanitization output changes for any existing test fixture.
4. Detector FPR on the benign test fixtures exceeds 5% (checked by running true negative tests).
5. You are unsure whether a pattern belongs in IPI-005 vs IPI-001 — ask, do not guess.

---

## Coding Standards

- TypeScript strict mode throughout. No `any`.
- All new files: JSDoc on every exported symbol.
- Detector patterns: defined as `readonly` constants at module level, not inline in methods.
- No dependencies added without explicit approval. Use only what's already in `package.json`.
- Test file naming: `*.test.ts`, co-located with the module under `__tests__/`.
- After completing all changes, run `npm test` and report the final count: `X/Y tests passing`.

---

## Definition of Done

- [ ] `src/types/threats.ts` created with all types
- [ ] `src/security/ThreatDetector.ts` created with all 7 detectors
- [ ] All content-type handlers updated to return `HandlerResult`
- [ ] Tool responses include `threat_summary`
- [ ] 56+ new tests, 0 failures
- [ ] 294 original tests still passing (total ≥ 350)
- [ ] `npm run build` succeeds with 0 TypeScript errors
- [ ] CLAUDE.md Known Errors Registry updated with any edge cases discovered

Report final test count and any Known Errors Registry additions when done.
```
