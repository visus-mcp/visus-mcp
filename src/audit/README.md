# Visus-MCP Audit Logging System

## Overview

Every Visus-MCP tool call produces a structured audit record written to DynamoDB with a 90-day TTL. Records are designed for EU AI Act and GDPR compliance.

## Architecture

```
MCP Tool Call
     │
     ▼
audited_sanitize()           ← audit/middleware.ts
     │
     ├─► Sanitization Pipeline (43 patterns)
     │        │
     │        └─► SanitizationProof (proof_hash, hashes, counts)
     │
     ├─► DataFlowRecord (bytes, domain hash, lawful basis)
     ├─► RedactionRecord[] (category, pattern_id, length — not content)
     │
     ▼
AuditLogRecord.write()       ← audit/logger.ts
     │
     ▼
DynamoDB (90-day TTL)
     │
     └─► visus_report tool   ← CSV / JSON / GDPR Art. 30 export
```

## Regulatory Mapping

| Component | EU AI Act | GDPR |
|-----------|-----------|------|
| SanitizationProof (proof_hash) | Art. 9 Risk Management | Art. 32(1)(d) Regular Testing |
| RedactionRecord (what + why) | Art. 9 Risk Management | Art. 5(1)(c) Data Minimisation |
| DataFlowRecord (lawful basis) | Art. 10 Data Governance | Art. 30 Records of Processing |
| 90-day TTL | Code of Practice §4 | Art. 5(1)(e) Storage Limitation |
| visus_report export | Art. 13 Transparency | Art. 30 Records of Processing |
| No raw content in logs | Art. 15 Robustness | Art. 25 Data Protection by Design |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VISUS_AUDIT_TABLE` | `visus-audit-log` | DynamoDB table name |
| `AUDIT_TABLE_NAME` | (fallback) | Alternative table name variable |
| `VISUS_AUDIT_ENABLED` | `true` | Disable for testing |
| `AUDIT_FAIL_CLOSED` | `false` | Raise on write failure |
| `AWS_REGION` | `us-east-1` | DynamoDB region |

## Generating Compliance Reports

### Via MCP (Claude Desktop or API)

```typescript
// Summary JSON (aggregated statistics)
visus_report({ report_type: "summary_json", days_back: 30 })

// CSV export (row per request)
visus_report({ report_type: "csv", days_back: 90 })

// GDPR Art. 30 Records of Processing template
visus_report({ report_type: "gdpr_art30" })
```

### Directly (for DPA submission)

```typescript
import { ComplianceReportExporter } from './src/audit/report.js';

const exporter = new ComplianceReportExporter();
const endDate = new Date();
const startDate = new Date();
startDate.setDate(startDate.getDate() - 30);

const csvReport = await exporter.generateCSV({ startDate, endDate });
console.log(csvReport);
```

## Privacy Design

The audit log is designed to be safe for external disclosure:

- **No raw content stored** — only SHA-256 hashes of input/output
- **No URLs stored** — only SHA-256 hash of domain (first 16 chars)
- **No PII stored** — only the *category* and *length* of redacted PII, never the PII itself
- **Proof hash is verifiable** — SHA-256(request_id + sorted_pattern_ids + timestamp)
- **90-day TTL** — automatic deletion satisfies GDPR Art. 5(1)(e) storage limitation

## Usage in MCP Tools

To add audit logging to a tool:

```typescript
import { audited_sanitize } from '../audit/middleware.js';

// In your tool handler:
const { content, proof_hash, injections_blocked } = await audited_sanitize({
  request_id: generateRequestId(),
  url: inputUrl,
  raw_content: fetchedContent,
  tool_name: 'visus_fetch',
  tool_version: '1.0.0'
});

// Return audit proof in response
return {
  content,
  audit_proof: proof_hash,
  injections_blocked
};
```

## DynamoDB Table Schema

**Table Name:** `visus-audit-${environment}`

**Primary Key:**
- Partition key: `user_id` (STRING) — for Lambda mode
- Sort key: `timestamp` (STRING) — ISO 8601

**Global Secondary Index:**
- Index name: `request_id-index`
- Partition key: `request_id` (STRING)
- Projection: ALL

**TTL Attribute:** `ttl` (NUMBER) — Unix epoch, 90 days from creation

**Encryption:** KMS customer-managed key

## Compliance Attestations

When asked by auditors or data protection authorities:

1. **Is raw web content retained?** No. Only SHA-256 hashes are stored.
2. **How long are records kept?** 90 days, then automatically deleted via DynamoDB TTL.
3. **What lawful basis applies?** Art. 6(1)(f) GDPR — Legitimate interests of the data subject in being protected from prompt injection attacks.
4. **Are all requests audited?** Yes, when `VISUS_AUDIT_ENABLED=true` (default).
5. **Can you demonstrate sanitization occurred?** Yes, via the `proof_hash` field, which is SHA-256(request_id + sorted_pattern_ids + timestamp).

## EU AI Act Code of Practice Alignment

The audit system satisfies:

- **Measure 2.5 (Adversarial Robustness):** Logs document that sanitization pipeline executed and which patterns were triggered.
- **Measure 4.1 (Incident Disclosure):** Export capability allows conformity assessment bodies to review security incidents.
- **Measure 1.2 (Capability Transparency):** Audit records provide machine-readable transparency artifacts.

## Troubleshooting

### Audit writes failing

1. Check AWS credentials: `aws sts get-caller-identity`
2. Verify table exists: `aws dynamodb describe-table --table-name visus-audit-log`
3. Check IAM permissions: Lambda execution role must have `dynamodb:PutItem`
4. Review CloudWatch Logs for `audit_logging_failed` events

### No audit records appearing

1. Check `VISUS_AUDIT_ENABLED` is not set to `false`
2. Verify `AUDIT_TABLE_NAME` or `VISUS_AUDIT_TABLE` is set correctly
3. Check TTL hasn't deleted recent records (90-day retention)

### Report queries returning no data

1. Verify date range includes audit records
2. Check `tool_filter` isn't excluding all records
3. Scan table directly: `aws dynamodb scan --table-name visus-audit-log --max-items 5`

## Future Enhancements

- [ ] PDF export for compliance artifacts (`visus_report` with `report_type: 'pdf'`)
- [ ] Real-time compliance dashboard
- [ ] Automated GDPR Art. 30 record generation with deployer details
- [ ] Integration with SIEM systems via CloudWatch Events
- [ ] GraphQL API for audit log queries
