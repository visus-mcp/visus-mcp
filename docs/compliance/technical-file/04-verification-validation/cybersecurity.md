# Cybersecurity Measures (Annex IV §1.6; Art. 15)

## Robustness Controls
- **Input Validation:** All URLs sanitized; No eval/exec (RULE 4).
- **Output Sanitization:** 45 patterns + 19 IPI + PII; Stateless (no cross-session leaks).
- **Crypto:** SHA-256/HMAC (built-in); Merkle for Ledger tamper-proofing.
- **Access:** Local-only; Admin tools (visus_export_ledger) key-protected (VISUS_ADMIN_KEY).

## Threat Model
- **Attack Vectors:** IPI chaining (mitigated: visus_context_scan); Log tampering (mitigated: Merkle proofs).
- **Incident Response:** Ledger exports for forensics; Stderr JSON for PMM.

**Compliance:** Aligns with EN ISO 27001 (info sec) + Art. 15(d) updates.
