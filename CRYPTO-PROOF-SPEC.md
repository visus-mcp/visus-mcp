# Visus-MCP Cryptographic Proof Specification

Version: 1.0.0
Status: Normative
Regulatory basis: EU AI Act Art. 9, 11, 13, 15 | GDPR Art. 5(2), 32

---

## Purpose

This document specifies the cryptographic proof scheme used by Visus-MCP to
provide verifiable, tamper-evident evidence that its prompt injection
sanitization pipeline executed before any web content was forwarded to a
large language model.

Any third party — regulator, DPA, conformity assessment body, or security
researcher — can independently verify any Visus-MCP proof record using only
this specification and standard SHA-256 / HMAC-SHA-256 implementations.

---

## Proof Fields

Every Visus-MCP tool response includes a `visus_proof` object with these fields:

| Field | Type | Description |
|---|---|---|
| `request_id` | hex string (32 chars) | Unique identifier for this tool call |
| `proof_hash` | hex string (64 chars) | SHA-256 commitment over all proof fields |
| `chain_hash` | hex string (64 chars) | Links this proof to previous proof |
| `injection_detected` | boolean | Whether any injection pattern fired |
| `patterns_evaluated` | integer | Total patterns checked |
| `patterns_triggered` | integer | Patterns that fired |
| `redactions` | integer | Number of redactions applied |
| `sanitization_applied` | boolean | Whether content was modified |
| `timestamp_utc` | ISO 8601 string | When sanitization completed |
| `pipeline_version` | semver string | Sanitization library version |
| `schema_version` | semver string | Proof schema version |

The `proof_signature` (HMAC) is stored in the audit log but **not** returned
in tool responses. It is disclosed only to authorised auditors.

---

## Proof Hash Computation

The `proof_hash` is computed as:

```
proof_hash = SHA-256(canonical_string)

canonical_string = join([
    request_id,
    input_hash,
    output_hash,
    sorted(triggered_pattern_ids).join(","),
    str(patterns_evaluated),
    timestamp_utc,
    pipeline_version,
], separator="\x00|\x00")
```

Where:

- `input_hash  = SHA-256(raw_content_utf8)`   — hash of content BEFORE sanitization
- `output_hash = SHA-256(sanitized_content_utf8)` — hash of content AFTER sanitization
- `triggered_pattern_ids` = sorted lexicographically before joining
- All string encoding is UTF-8
- The field separator `\x00|\x00` (null-pipe-null) prevents field boundary ambiguity

---

## Proof Signature Computation

```
proof_signature = HMAC-SHA-256(proof_hash, VISUS_HMAC_SECRET)
```

The signature is disclosed to authorised auditors under NDA. It proves the
proof was issued by a pipeline instance holding the secret key, not forged
by an external observer.

---

## Chain Hash Computation

```
chain_hash = SHA-256(previous_proof_hash + "\x00|\x00" + current_proof_hash)
```

- First record: `previous_proof_hash = "GENESIS"`
- The chain allows auditors to detect gaps (deleted records) or reordering.

---

## Verification Procedure

### Hash-only verification (no signing key required)

1. Obtain `request_id`, `timestamp_utc`, `pipeline_version`, `patterns_evaluated`, `patterns_triggered` from the `visus_proof` object
2. Obtain `input_hash` and `output_hash` from the audit log record
3. Obtain `triggered_pattern_ids` (list) from the audit log record
4. Recompute `canonical_string` using the formula above
5. Compute `SHA-256(canonical_string)`
6. Compare against `proof_hash` — must match byte-for-byte

### Full cryptographic verification (requires signing key)

1. Perform hash-only verification first
2. Compute `HMAC-SHA-256(recomputed_proof_hash, VISUS_HMAC_SECRET)`
3. Compare against `proof_signature` from audit log — must match byte-for-byte

### Using the `visus_verify` MCP tool

```json
{
  "tool": "visus_verify",
  "input": {
    "proof": { "<paste the visus_proof object here>" },
    "signingKey": "<VISUS_HMAC_SECRET — omit for hash-only>"
  }
}
```

### Using the CLI verifier

```bash
# TypeScript
echo '{"proof": {...}, "signingKey": "..."}' | \
  node dist/crypto/verifier.js

# Exit code 0 = valid, 1 = invalid, 2 = parse error
```

---

## Regulatory Mapping

| Proof Component | EU AI Act | GDPR |
|---|---|---|
| `input_hash` + `output_hash` | Art. 15 Robustness — proves pipeline ran | Art. 32 Security — cryptographic evidence |
| `proof_hash` | Art. 9 Risk Management — tamper-evident record | Art. 5(2) Accountability — verifiable |
| `proof_signature` (audit-only) | Art. 11 Technical Documentation | Art. 32(1)(d) Regular testing evidence |
| `chain_hash` | Art. 9 Risk Management — deletion detection | Art. 5(2) Accountability |
| `visus_verify` tool | Art. 13 Transparency — callable verification | Art. 30 Records — machine-readable |
| `patterns_evaluated` / `patterns_triggered` | Art. 9(4) Risk Management documentation | Art. 32 — evidence of controls |

### Presumption of Conformity Path

Deployers can reference this specification as part of the technical
documentation required under EU AI Act Annex IV. The `visus_verify` tool
constitutes the "testing, validation and verification procedures" required
by Annex IV §2(f).

---

## Security Properties

| Property | Mechanism | Guarantee |
|---|---|---|
| **Tamper evidence** | SHA-256 over all fields | Any field change invalidates proof_hash |
| **Authenticity** | HMAC-SHA-256 with secret key | Proves pipeline issued the proof |
| **Non-repudiation** | Audit log + chain_hash | Deletion of records is detectable |
| **Privacy preservation** | Hashes only, no raw content | Verification without data exposure |
| **Timing safety** | `timingSafeEqual` / `hmac.compare_digest` | No timing oracle on verification |
| **Ordering proof** | Chain hash | Record sequence is tamper-evident |

---

## Reference Implementation Test Vectors

Use these to verify your implementation is correct:

### Input:
```
request_id         = "test-request-id-0000"
input_hash         = SHA-256("raw content")
                   = "a6e5d15bf571ca7a23fd704caad6c4c071210ba8d38ea0296dc58c3ce0a0e514"
output_hash        = SHA-256("clean content")
                   = "573b1d8589d0623b86749785dae7a299483d140d551299578f0fcb30bdcece28"
triggered_pattern_ids = ["PI-001", "PI-007"]  (sort → ["PI-001","PI-007"])
patterns_evaluated = 43
timestamp_utc      = "2026-03-26T00:00:00.000Z"
pipeline_version   = "1.0.0"

canonical_string = "test-request-id-0000\x00|\x00a6e5d15bf571ca7a23fd704caad6c4c071210ba8d38ea0296dc58c3ce0a0e514\x00|\x00573b1d8589d0623b86749785dae7a299483d140d551299578f0fcb30bdcece28\x00|\x00PI-001,PI-007\x00|\x0043\x00|\x002026-03-26T00:00:00.000Z\x00|\x001.0.0"
```

### Expected Output:
```
proof_hash = "9cda5595b2f9865e1f1f50ac366a79daa488bd85db02551c20c3de22a65c902d"

signing_key = "test-signing-key-for-spec-vectors-only-000000"
proof_signature = "0d7a6102117ed1c6d5ceb8dcc132000f96ddf3d1c4a97bf18328063dded959b5"
```

### Verification:

Recompute the `proof_hash` from the inputs above. It must match exactly. Then compute the HMAC signature using the test signing key. It must also match exactly.

If either hash does not match, your implementation is incorrect. Common causes:
- Field ordering wrong in canonical string
- Separator string incorrect (must be `\x00|\x00`)
- Pattern IDs not sorted lexicographically
- Encoding not UTF-8
- Extra whitespace or newlines in canonical string

---

## Compliance Checklist

For deployers preparing for conformity assessment under EU AI Act:

- [ ] `VISUS_HMAC_SECRET` configured in production (minimum 32 bytes)
- [ ] Audit logging enabled (`VISUS_AUDIT_ENABLED=true`)
- [ ] Audit records retained for 90 days minimum
- [ ] `visus_verify` tool accessible to auditors
- [ ] Test vectors verified against your deployment
- [ ] Chain tip persisted across server restarts (if applicable)
- [ ] HMAC key rotation procedure documented
- [ ] Incident response plan for key compromise
- [ ] Data sharing agreement covers proof signature disclosure to DPAs
- [ ] Technical documentation references this specification

---

## Changelog

| Version | Date | Changes |
|---|---|---|
| 1.0.0 | 2026-03-28 | Initial release — comprehensive cryptographic proof system |

---

## Contact

For questions about this specification or security disclosures:

- Email: security@lateos.ai
- GitHub: https://github.com/visus-mcp/visus-mcp/security

---

**End of Specification**
