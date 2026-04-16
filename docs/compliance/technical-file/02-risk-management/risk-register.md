# Risk Register v1 (Annex IV §1.3)

## Risk Management Framework
Visus-MCP employs a risk-based approach aligned with EN ISO/IEC 42001 and NIST AI RMF. Risks are assessed using MITRE ATLAS + OWASP LLM Top 10, scored 1-5 (Likelihood x Impact).

## Identified Risks
| Risk ID | Description | Pre-Mitigation Severity | Residual Risk | Controls & Evidence |
|---------|-------------|--------------------------|---------------|---------------------|
| R001-GLASSWORM | Steganographic Unicode Variation Selectors hiding IPI payloads (IPI-007) | HIGH (4/5) | LOW (1/5) | Variation Selector stripping in sanitizer.ts; 100% coverage in glassworm.test.ts; Post-mitigation verification via crypto proofs. |
| R002-MORRIS-II | Self-replicating prompts in multi-turn sessions | MEDIUM (3/5) | LOW (1/5) | Worm detector (15 patterns) + visus_context_scan; HITL trigger >0.8 score; Immutable Ledger chaining prevents propagation. Tests: worm-detector.test.ts (100% pass). |
| R003-TRACEABILITY | Tampering/deletion of audit logs | CRITICAL (5/5) | NONE (0/5) | Merkle tree append-only (SHA-256 leaves); Inclusion proofs verifiable offline. Ledger v0.18.0 tests: 4/4 pass. |
| R004-IPI-CHAINING | Multi-turn priming (e.g., Page1 save, Page2 exploit) | HIGH (4/5) | LOW (2/5) | Stateful scan (visus_context_scan); Local hash cache (30min TTL). Session-ledger.test.ts covers 80% vectors (Unit 42 2026). |

| R010-BOOLEAN_BYPASS | CVE-2026-4399 Boolean Prompt Injection (logic gate restriction bypass) | HIGH (4/5) | LOW (1/5) | Boolean-gate detector (regex + safeEval); Pre-test antecedents; Tests: boolean-gate.test.ts (10 cases, 100% pass). |

## Assessment Methodology
- **Scoring:** Likelihood (1-5) x Impact (1-5); Residual post-controls.
- **Review Cycle:** Quarterly (Art. 61); Next: Q3 2026.
- **Threshold:** Residual >2 triggers update to Technical File.

**Overall Residual Risk:** LOW – All mitigations validated at 100% test pass rate. No unmitigated CRITICAL risks.

**Links to V&V:** test-coverage.md; All risks covered in 570+ Jest suites.
