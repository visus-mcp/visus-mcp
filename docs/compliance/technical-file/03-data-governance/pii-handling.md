# PII Handling & Oversight (Annex IV §1.5; GDPR Art. 25)

## PII Redaction Policy
Visus-MCP redacts PII before LLM ingestion to prevent exposure in conversation history.

### Detected Types & Redaction
| Type | Pattern | Redaction | Allowlist Rationale |
|------|---------|-----------|--------------------|
| EMAIL | RFC 5322 | [REDACTED:EMAIL] | Domain-scoped (e.g., health.gov allowed) |
| PHONE | E.164/US NANP | [REDACTED:PHONE] | None (critical: Do-Not-Call compliance) |
| SSN | XXX-XX-XXXX | [REDACTED:SSN] | None |
| CC | 16-digit | [REDACTED:CC] | None |
| IP | IPv4/IPv6 | [REDACTED:IP] | None |

**Implementation:** pii-redactor.ts (regex + context checks); 100% test cov. in pii-allowlist.test.ts.

### Human Oversight (Art. 15(c))
- **HITL Triggers:** CRITICAL threats >0.8 score (Hitl-gate.ts); Elicit confirmation.
- **Logs:** Human decisions in Ledger (human_review_flag: true, reviewer_id: UUID).
- **Oversight Logs:** /audit/oversight-YYYY-MM.jsonl; Query via visus_get_ledger_proof.

**By Design:** PII never reaches LLM; Oversight for edge cases only.
