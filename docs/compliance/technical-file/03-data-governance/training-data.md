# Training Data & Data Governance (Annex IV §1.4)

## Overview
Visus-MCP is a rule-based (non-ML) system with **no training data** or model weights. It operates statelessly on inputs, using deterministic pattern matching for sanitization. This satisfies §1.4(a) (no datasets) and §1.4(b) (no preprocessing biases).

### Data Sources & Processing
- **Input Data:** Untrusted web content (HTML/JSON/etc.) via URLs/tools.
- **Processing:** Stateless pipeline; No storage beyond session Ledger (hashes only, 12mo retention).
- **Output Data:** Sanitized text + metadata/proofs; No raw content persisted.
- **Volumes:** Per-request; No aggregate training sets.

### Quality Assurance
- **Data Minimization (GDPR Art. 5):** Only process requested fields; Truncate >512KB.
- **Bias Absence:** Rule-based; No ML decisions.
- **Quality Metrics:** 100% repeatability (tests); Token reduction 70% avg. (tokenMetrics.ts).

**Governance:** Internal audits quarterly; No external data flows unless Ledger export (user-initiated).
