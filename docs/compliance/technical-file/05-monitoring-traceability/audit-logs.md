# Audit Logs & Traceability (Annex IV §1.7 Supplement)

## Logging Mechanism
- **Stderr Output:** Structured JSON (no stdout pollution); e.g., `{"level":"warn","event":"critical_threat","patterns":["IPI-001"],"url":"..."}`.
- **Ledger Integration:** All events hashed; Query via visus_get_ledger_proof(request_id).
- **HITL Logs:** human_review_flag in events; Full chain via Merkle proofs.

**Retention & Access:** 12mo; Exports via exportLedger() → JSONL/ZIP.

**Audit Use Case:** For DPA query: "Prove event X occurred" → `getProof(X)` + `verifyProof()`.
