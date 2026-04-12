# Immutable Session Ledger Specification (Annex IV §1.7; Art. 62 Post-Market Monitoring)

## Overview
The Immutable Session Ledger is a tamper-evident, append-only audit trail for all Visus-MCP operations. It chains events via Merkle trees (SHA-256 leaves) to ensure traceability without storing raw content. This satisfies §1.7 (record of parameters) and Art. 62 (PMM system) for high-risk systems.

**Design Principles:**
- **Append-Only:** No deletions/mutations; Merkle roots detect tampering.
- **Privacy-First:** Hashes only (SHA-256); No raw inputs/outputs persisted.
- **Verifiability:** Inclusion proofs for any event; Offline verification via `verifyProof()`.
- **Retention:** 12 months (GDPR-compliant); Auto-purge configurable.

## Event Schema
Each LedgerEvent is JSON-serialized and hashed before tree insertion.

```typescript
interface LedgerEvent {
  request_id: string;                     // UUID v4
  session_id: string;                     // Session key (MCP conversation ID)
  timestamp: string;                      // ISO 8601 (ms precision)
  url?: string;                           // Source URL (if applicable)
  original_hash: string;                  // SHA-256(raw content)
  cleaned_hash: string;                   // SHA-256(sanitized output)
  sanitization_steps: string[];           // e.g., ['strip_nav', 'redact_pii']
  threats_detected: Array<{               // IPI/Threat details
    pattern_id: string;                   // e.g., 'IPI-001'
    severity: 'CRITICAL' | 'HIGH' | ...;
    snippet_hash: string;                 // SHA-256(excerpt)
  }>;
  pii_redacted_count: number;
  pii_types: string[];                    // e.g., ['EMAIL', 'PHONE']
  visus_proof: string;                    // HMAC from proof-builder.ts
  human_review_flag: boolean;
  human_reviewer_id?: string;             // UUID if HITL
  model_output_hash?: string;             // Optional: LLM response hash
  tool_name?: string;                     // e.g., 'visus_fetch'
  entities?: HashedEntity[];              // VSIL integration (session risks)
  risk_summary?: SessionRiskSummary;      // Aggregate score
  new_threats?: ThreatAnnotation[];       // Incremental threats
}
```

**Merkle Tree Structure:**
- **Leaves:** SHA-256(JSON.stringify(event))
- **Hash Algo:** SHA-256 (configurable: VISUS_MERKLE_ALGO)
- **Balance:** Sorted pairs (merkletreejs); MMR for append-only efficiency (future v0.20).
- **Session Scope:** Per-session_id tree; Daily root for global chaining.
- **Proofs:** Inclusion (siblings + path) for verification.

## Implementation Details
- **Storage:** JSONL files (`audit/ledger-YYYY-MM-DD.jsonl`); In-memory trees for active sessions.
- **Integration:** Called post-sanitization in tools/fetch.ts; Attaches merkle_root/proof to outputs.
- **Env Vars:**
  - VISUS_LEDGER_ENABLED=true (default: false)
  - VISUS_LEDGER_PATH=./audit
  - VISUS_MERKLE_ALGO=sha256
  - VISUS_RETENTION_MONTHS=12
- **Verification:** `verifyProof(proof: InclusionProof, event: LedgerEvent): boolean` – Reconstructs root.

## Conformity Mapping
- **§1.7:** Records all params (hashes traceable to inputs/outputs without exposure).
- **Art. 62(1):** PMM via append-only logs; Enables incident analysis.
- **Tests:** immutable-ledger.test.ts (addEvent, getProof, verifyProof, purge – 4/4 pass).

**Limitations:** In-memory for active sessions; Prod: Persist trees to DB (Phase 3).
