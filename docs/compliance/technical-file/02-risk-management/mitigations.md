# Mitigations Overview (Annex IV §1.3 Supplement)

## Feature Mitigations
- **IPI Detection (19 cats):** Pre-sanitization scan blocks escalation; Maps to OWASP LLM01, MITRE AML.T0012.
- **Injection Sanitizer (45 patterns):** Neutralizes direct attacks; Graceful degradation (no full blocks).
- **Worm Detector:** Post-sanitization check for replication; Integrates with Ledger for chain detection.

**Validation:** All mitigations covered in 570+ Jest tests; E2E pipeline in fetch-tool.test.ts.
