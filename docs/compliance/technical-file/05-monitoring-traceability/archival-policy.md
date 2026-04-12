# Archival & Retention Policy (Annex IV §1.7; GDPR Art. 5)

## Policy Overview
Visus-MCP implements a GDPR-compliant retention policy for traceability logs, ensuring data minimization while meeting Art. 62 PMM requirements.

### Retention Schedule
- **Ledger Events:** 12 months active; Auto-purge via purgeOldLedgers() (monthly cron).
- **Verification Outputs:** 24 months (visus_verify logs); Stored as /artifacts/verifications/YYYY-MM.jsonl.
- **Audit Exports:** User-initiated; Retained until manual deletion (no auto-purge).
- **Rationale:** Balances Art. 5(1)(e) (storage limitation) with Art. 62(1) (historical incidents).

### Archival Process
1. **Export:** Run `npm run export-compliance -- --session <id>` → JSONL with proofs.
2. **Storage:** /docs/compliance/artifacts/; Encrypted if VISUS_ARCHIVE_ENCRYPT=true (KMS future).
3. **Deletion:** purgeOldLedgers() removes files < retention_months; Logs purge events to stderr.
4. **Access Controls:** Local-only; Admin exports require VISUS_ADMIN_KEY.

### Compliance Mapping
- **GDPR Art. 25:** By design (privacy in hashing).
- **Art. 61(3):** Logs enable DPA submissions; Merkle for integrity.

**Implementation:** ImmutableLedger.ts#purgeOldLedgers(); Config: VISUS_RETENTION_MONTHS=12.
