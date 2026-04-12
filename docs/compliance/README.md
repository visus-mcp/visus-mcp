# Compliance Documentation Entry Point
## Visus-MCP Technical File Index (Annex IV)

**Version:** 1.0 | **EU AI Act Compliance:** Art. 11 & Annex IV | **Status:** W1 Complete

This folder contains the formal *Technical File* for Visus-MCP, structured per Annex IV requirements for high-risk AI systems. For General Purpose AI (GPAI), this provides best-practice transparency under Art. 52.

### Navigation to Annex IV Sections
- **[§1.1-1.2: System Description & Purpose](technical-file/01-system-description/intended-purpose.md)** – Intended use, architecture overview.
- **[§1.3: Risk Management](technical-file/02-risk-management/risk-register.md)** – Risk register (v1: Glassworm, Morris II).
- **[§1.4-1.5: Data Governance](technical-file/03-data-governance/training-data.md)** – Stateless design, PII handling.
- **[§1.6: Verification & Validation](technical-file/04-verification-validation/test-coverage.md)** – 570+ tests, Art. 15 cybersecurity.
- **[§1.7: Traceability & Monitoring](technical-file/05-monitoring-traceability/ledger-spec.md)** – Immutable Ledger, Art. 62 logs.

### Feature-to-Annex IV Mapping (100% Coverage)
| Feature | Annex IV Ref | Evidence |
|---------|--------------|----------|
| 19 IPI Detectors | §1.1(e), §1.3 | ThreatDetector.ts; 570+ tests |
| 45 Injection Patterns | §1.6 | sanitizer/patterns.ts; 43/43 pass |
| PII Redaction | §1.4; GDPR 25 | pii-redactor.ts |
| Stateless Processing | §1.2 | Data flow diagram |
| Immutable Ledger | §1.7; Art. 62 | ImmutableLedger.ts |
| Crypto Proofs | §1.6 (Art. 15) | proof-builder.ts; 100% verification |

**Gaps Addressed in Future Sprints:** Quantitative benchmarks (W2), human oversight logs (W3).

**Export:** Run `npm run export-compliance` (to be implemented in W4) for ZIP bundle.

Contact: leo@lateos.ai for reviews or audits.
