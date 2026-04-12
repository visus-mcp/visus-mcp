# Compliance Documentation Entry Point
## Visus-MCP Technical File Index (Annex IV)

**Version:** 1.0 | **EU AI Act Compliance:** Art. 11 & Annex IV | **Status:** Compliance Ready (W4 Complete)

This folder contains the formal *Technical File* for Visus-MCP, structured per Annex IV requirements for high-risk AI systems. For General Purpose AI (GPAI), this provides best-practice transparency under Art. 52.

### Table of Contents
- [§1.1: Intended Purpose](technical-file/01-system-description/intended-purpose.md)
- [§1.2: Architecture](technical-file/01-system-description/architecture.md) (incl. Data Flow Diagram)
- [§1.3: Risk Management](technical-file/02-risk-management/risk-register.md) & [Mitigations](technical-file/02-risk-management/mitigations.md)
- [§1.4: Training Data](technical-file/03-data-governance/training-data.md)
- [§1.5: Human Oversight & PII](technical-file/03-data-governance/pii-handling.md)
- [§1.6: Verification & Validation](technical-file/04-verification-validation/test-coverage.md) & [Cybersecurity](technical-file/04-verification-validation/cybersecurity.md)
- [§1.7: Traceability](technical-file/05-monitoring-traceability/ledger-spec.md) & [Audit Logs](technical-file/05-monitoring-traceability/audit-logs.md) & [Archival Policy](technical-file/05-monitoring-traceability/archival-policy.md)

### Feature-to-Annex IV Mapping (100% Coverage)
| Feature | Annex IV Ref | Evidence |
|---------|--------------|----------|
| 19 IPI Detectors | §1.1(e), §1.3 | ThreatDetector.ts; 570+ tests |
| 45 Injection Patterns | §1.6 | sanitizer/patterns.ts; 43/43 pass |
| PII Redaction | §1.4; GDPR 25 | pii-redactor.ts |
| Stateless Processing | §1.2 | Data flow diagram |
| Immutable Ledger | §1.7; Art. 62 | ImmutableLedger.ts |
| Crypto Proofs | §1.6 (Art. 15) | proof-builder.ts; 100% verification |

**Export & Artifacts:**
- `npm run export-compliance` → ZIP of Technical File (v1.0.zip).
- `npm run render-pdf artifacts/self-attestation.md report.pdf` → PDF stub.
- [Self-Attestation Checklist](artifacts/self-attestation.md)

Contact: leo@lateos.ai for reviews, audits, or ZIP exports.
