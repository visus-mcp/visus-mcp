# Visus project conventions

## Non-negotiable rules
- No secrets in code, env vars, logs, or git. Secrets Manager only.
- No * in IAM resource ARNs. Explicit ARNs always.
- All infrastructure in IaC (CDK v2). No console changes.
- content_hash computed and verified on every event before DynamoDB write.
- Structured JSON logging on all Lambdas. No stack traces in API responses.
- No test skipping. All tests must pass.
- No Claude/Anthropic outputs used as training data or model outputs.

## Schema versioning
- Event schema: shared/schemas/event.schema.json (v1)
- Finding schema: shared/schemas/finding.schema.json (v1, Sprint 2)
- Breaking changes require version bump and schema adapter. See REC-08 in project plan.

## Canonical JSON
- All hashing uses shared/canonical-json.ts — never inline JSON.stringify
- Canonical JSON: alphabetically sorted keys, no whitespace, UTF-8

## Test floors (minimum, not target)
- Sprint 0: ≥40 unit tests
- Sprint 1: ≥100 unit tests total (60 new)
- Integration tests run against staging, never against production

## Naming conventions
- Lambda functions: visus-{name} (e.g. visus-proof-signer)
- DynamoDB tables: visus-{name} (e.g. visus-events)
- Secrets Manager paths: visus/{scope}/{name} (e.g. visus/audit/signing-keypair)
- Environment: VISUS_ENV=staging | production

## Language & Runtime
- TypeScript for all Lambda functions and IaC (CDK v2)
- Runtime: Node.js 20.x
- Use Python 3.12 only if a specific library has no TypeScript equivalent

## Repository
- https://github.com/visus-mcp/visus-mcp

## Ed25519 Keypair Verification
The proof-signer Lambda signs payloads using the Ed25519 private key stored in Secrets Manager.
To verify a signature:
```bash
# Extract public key from Secrets Manager
aws secretsmanager get-secret-value \
  --secret-id visus/audit/signing-keypair \
  --region us-east-1 \
  --query SecretString --output text > /tmp/priv.pem

openssl pkey -in /tmp/priv.pem -pubout -out /tmp/pub.pem

# Verify a signature
openssl pkeyutl -verify \
  -pubin -inkey /tmp/pub.pem \
  -rawin -in payload.bin \
  -sigfile signature.bin

# Clean up
shred -u /tmp/priv.pem /tmp/pub.pem
```

## Known Errors Registry

| Error | Root Cause | Fix | Date Confirmed |
|-------|-----------|-----|----------------|
| `ERR_MODULE_NOT_FOUND: @modelcontextprotocol/sdk` in Lambda | `index.js` (MCP stdio server) included in Lambda bundle via `package.json` `"main"` field; SDK not bundled | Add `@modelcontextprotocol/sdk` to `externalModules` in `infrastructure/stack.ts` | 2026-03-24 |
| CVE-2026-32622: SQLBot RCE via stored terms | Injected SQL in DB descriptions leads to LLM-executed RCE | Implement db-guard middleware | 2026-04-15 |
