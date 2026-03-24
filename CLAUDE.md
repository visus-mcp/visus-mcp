# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Visus** (`visus-mcp`) is an MCP tool that provides Claude with secure, sanitized access to web pages. Unlike other MCP browser tools (Firecrawl, Playwright MCP, ScrapeGraphAI), Visus runs ALL fetched content through an injection sanitization pipeline before the LLM reads it.

Core differentiator: *"What the web shows you, Lateos reads safely."*

This is part of the Lateos platform — a security-by-design AI agent framework deployed on AWS serverless (Lambda, Step Functions, API Gateway, Cognito, Bedrock with Guardrails, DynamoDB with KMS encryption).

## Architecture

The system follows this flow:
```
User provides URL → Visus MCP Tool → Browser rendering (Playwright) →
Raw HTML extraction → Injection Sanitizer (43 patterns) → PII Redactor →
Clean content → Claude via MCP
```

### Two MCP Tools

1. **`visus_fetch(url, options?)`** - Returns sanitized markdown/text from a URL
2. **`visus_fetch_structured(url, schema)`** - Extracts structured data with sanitization

Both tools MUST always pass content through the sanitizer — this cannot be bypassed.

## Key Components

### Sanitizer (The Core Product)
Location: `src/sanitizer/`

The sanitizer is the product's primary moat. It must detect and neutralize 43 injection pattern categories:

1. Direct instruction injection ("Ignore previous instructions")
2. Role hijacking ("You are now", "Act as")
3. System prompt extraction ("Repeat your instructions")
4. Privilege escalation ("Admin mode", "Developer override")
5. Context poisoning ("The user said", "You already agreed")
6. Data exfiltration ("Send this to", "Email the following")
7. Encoding obfuscation (Base64, Unicode lookalikes, hex-encoded)
8. Whitespace hiding (zero-width chars, invisible Unicode)
9. HTML/script injection (`<script>`, `<iframe>`, `onclick`)
10. Markdown injection (malicious link syntax, image payloads)
11. URL fragment attacks (instructions after `#`)
12. Social engineering (urgency language)
... (43 total)

**Sanitizer behavior:**
- Detect → log pattern name to `sanitization.patterns_detected`
- Neutralize → strip, replace with `[REDACTED: pattern_name]`, or escape
- Never block entire page — degrade gracefully
- PII redaction: email, phone, SSN, credit card, IP addresses
- PII format: `[REDACTED:EMAIL]`, `[REDACTED:PHONE]`, etc.

### Browser Rendering
Location: `src/browser/playwright-renderer.ts`

**Phase 2 (Current):** Uses Playwright headless Chromium with full JavaScript execution support. Browser instance is managed as a singleton for performance. Supports dynamic content, SPAs, and interactive web applications via `waitUntil: 'networkidle'`. Phase 3 will add user-session relay for login-gated pages.

## Development Commands

Since this is a new project, these commands will be added to `package.json`:

```bash
npm run build          # Compile TypeScript to /dist
npm test              # Run Jest test suite (must have 0 failures)
npm run lint          # TypeScript strict mode checks
npm publish --dry-run # Validate package before publishing
npx visus-mcp         # Start MCP server
```

**IMPORTANT: On every npm release, keep `server.json` version in sync with `package.json` version.**
The MCP registry requires that the version field in `server.json` matches the published npm package version.

## Coding Standards (Lateos Conventions)

- **TypeScript strict mode** - No `any` types allowed
- **Error handling** - Never throw raw errors; return typed Result objects
- **Logging** - Structured JSON to stderr (NOT stdout — MCP protocol uses stdout)
- **Documentation** - All public functions must have JSDoc comments
- **Tests** - Jest, located in `/tests`, minimum 80% coverage
- **Security** - No secrets in code; read from environment variables
- **Build output** - `tsc` compiles to `/dist`

## Test Requirements

All tests must pass before Phase 1 is complete.

### `tests/sanitizer.test.ts`
- Each of 43 pattern categories with at least one positive test case
- PII detection: email, phone, SSN, credit card
- Clean content passes through unmodified (no false positives)
- `content_modified: false` when no patterns detected
- `content_modified: true` and `patterns_detected` populated when injection found

### `tests/fetch-tool.test.ts`
- `visus_fetch` returns expected output shape
- `visus_fetch_structured` extracts fields correctly
- Timeout handling
- Invalid URL handling
- Sanitizer is always called (cannot be bypassed)

### `tests/injection-corpus.ts`
- 43 injection payloads (one per pattern category)
- 10 clean pages/content samples (should produce no detections)

---

## Standard Troubleshooting Protocol

Whenever you encounter an error, blocked deployment, or multi-step recovery task, you MUST generate a structured troubleshooting log automatically. This is not optional — it applies to every build, fix, and diagnostic task in this project.

### Log File Naming

```
TROUBLESHOOT-<CONTEXT>-$(date +%Y%m%d-%H%M).md
```

Save to project root. Examples:
- `TROUBLESHOOT-CDK-20260314-0621.md`
- `TROUBLESHOOT-LAMBDA-20260314-0900.md`
- `TROUBLESHOOT-SLIM-20260314-0629.md`

### Log Structure

Every troubleshooting log MUST follow this three-phase structure:

#### Phase 1: Investigation (read-only)
No changes to code or infrastructure. Gather facts, reproduce the error, read logs.
Only advance to Phase 2 after root cause is confirmed or a clear hypothesis is formed.

#### Phase 2: Fix Plan
Write out the proposed fix and alternatives considered. Do NOT execute yet.
If root cause shifts during Phase 2, return to Phase 1.

#### Phase 3: Execution
Implement the fix. Log every action. Update the SUMMARY at the end.

---

### Stop Conditions (mandatory — check before every action)

If any of the following are true, **STOP immediately**, log the blocker, and wait for user input:

| Condition | Action |
|-----------|--------|
| Deployment or build hangs >10 minutes | Kill process, document, ask user for direction |
| Same error appears >2 times in a row | Stop retrying, propose alternative approach |
| Root cause shifts away from original task | Re-confirm scope with user before continuing |
| A tool or service is unavailable (Docker, AWS, etc.) | Document and present options — do not loop |
| Success criteria cannot be verified | Stop and ask user how to validate |

---

### Environment Pre-flight

Run this checklist before ANY deployment or infrastructure task. Log each result.

```bash
# AWS credentials
aws sts get-caller-identity

# Docker health (required for CDK bundling)
docker info

# Disk space (ENOSPC will cause silent failures)
df -h /

# CDK version
npx cdk --version

# Node/npm
node --version && npm --version
```

If Docker is unavailable or disk space is low, use the manual Lambda deploy path (see Lambda Deployment below) rather than attempting CDK.

---

### Entry Format (append after EVERY action)

```markdown
## [HH:MM:SS] Step N - <short title>

**Goal:** What this step is trying to accomplish
**Reasoning:** Why this approach was chosen over alternatives
**Action:** Exact command or operation performed
**Result:** Raw output, error messages, success confirmation
**Status:** ✅ Success / ❌ Failed / ⚠️ Partial
```

### Ruled Out (maintain throughout session)

Append to this section whenever a suspected cause is eliminated. Prevents re-investigation.

```markdown
## Ruled Out
- ❌ <Component>: <one-line reason> — confirmed <date/time>
```

Example:
```markdown
## Ruled Out
- ❌ Cognito JWT: Auth correctly returns 401 on unauthenticated requests — not the issue
- ❌ API Gateway routing: Routes confirmed correct in stack outputs — not the issue
```

---

### Rules

1. **Log BEFORE executing, not after** — write Goal and Reasoning first
2. **Never skip a step** even if obvious or trivial
3. **On failure:** log the full error, state your revised reasoning, attempt one alternative, log that too
4. **Do not summarize or clean up errors** — paste raw output verbatim
5. **End every log with a SUMMARY section:** root cause, resolution, lessons learned, and open issues
6. **Populate "Ruled Out" in real time** — do not re-investigate eliminated causes
7. **Complete Phase 1 fully before making any changes** — no exceptions

---

### CLAUDE.md Updates Required

At the end of every troubleshooting session, before closing, check whether any findings should be promoted to this file. Add a section to the troubleshoot doc:

```markdown
## CLAUDE.md Updates Required
- [ ] <Finding that should become a permanent convention>
- [ ] <New known error to add to the registry>
- [ ] <New deployment step or warning>
```

Then apply those updates to CLAUDE.md as the final step of the session.

---

### Purpose

These logs are tool-use execution traces for future agent training. The **Reasoning** field is the highest-value signal — always explain **WHY**, not just **WHAT**.

**Example log structure:**

```markdown
# Lateos MCP Handler - Emergency Recovery Log

Started: 2026-03-14 06:02:15
Goal: Restore MCP handler Lambda with proper dependency packaging

---

## Phase 1: Investigation

## [06:02:18] Step 1 - Locate MCP Handler Source

**Goal:** Find the mcp_handler.py source file in the project
**Reasoning:** Need the handler source to rebuild the deployment package
**Action:** find /Users/leochong/Documents/projects -name "mcp_handler.py"
**Result:**
/Users/leochong/Documents/projects/Lateos/lambdas/core/mcp_handler.py
**Status:** ✅ Success

---

## Ruled Out
- ❌ IAM permissions: Lambda execution role has correct policies — not the issue

---

## Phase 2: Fix Plan
...

## Phase 3: Execution
...

---

# RECOVERY SUMMARY

Final Status: ✅ RESTORED
Root Cause: Lambda package missing runtime dependencies
Resolution: Installed aws_lambda_powertools + aws_xray_sdk
Lessons Learned: Always verify dependencies in Lambda packages

## CLAUDE.md Updates Required
- [ ] Add aws_lambda_powertools to standard Lambda dependency checklist
```

---

## Known Errors Registry

When a root cause is confirmed, add it here. Future sessions check this list first before investigating.

| Error | Root Cause | Fix | Date Confirmed |
|-------|-----------|-----|----------------|
| `ERR_MODULE_NOT_FOUND: @modelcontextprotocol/sdk` in Lambda | `index.js` (MCP stdio server) included in Lambda bundle via `package.json` `"main"` field; SDK not bundled | Add `@modelcontextprotocol/sdk` to `externalModules` in `infrastructure/stack.ts` | 2026-03-24 |
| CDK `docker buildx` hangs indefinitely | Docker resource contention or disk pressure on Apple Silicon Mac | Use manual Lambda deploy script (see below); fix Docker separately | 2026-03-24 |
| `ENOSPC` on Claude Code startup | Mac disk full; `~/.claude/debug/` write fails | Free disk space; `rm -rf ~/.claude/debug/`; restart | 2026-03-24 |
| 401 Unauthorized after `cdk deploy` | CDK does NOT automatically redeploy API Gateway stages when Lambda code or authorizer config changes | After every `cdk deploy`, run: `aws apigateway create-deployment --rest-api-id <api-id> --stage-name <stage>` | 2026-03-24 |
| `unable to get local issuer certificate` in Lambda | undici HTTP client in AWS Lambda Node.js 20 runtime lacks proper CA certificate configuration | Replace undici with Node.js native `fetch()` API (available in Node 18+) which has proper CA handling in Lambda | 2026-03-24 |

---

## Lambda Deployment

### Bundling Conventions

**CRITICAL: Always use `--format=cjs` for Lambda bundles.**
AWS SDK v3 uses dynamic `require()` internally. ESM output from esbuild will fail at Lambda runtime with `ERR_REQUIRE_ESM` or similar. CommonJS is the correct format for all Lambda deployments.

**Always externalize these packages:**
- `playwright-core` — added via Lambda layer
- `@sparticuz/chromium` — added via Lambda layer
- `@modelcontextprotocol/sdk` — only needed for stdio mode, not Lambda

**Entry point must always be `src/lambda-handler.ts`, NOT `src/index.ts`.**
`index.ts` is the MCP stdio server and imports packages that must not be in the Lambda bundle.

### Manual Deploy Script (use when CDK/Docker is unavailable)

```bash
#!/bin/bash
# scripts/deploy-lambda.sh
# Use this when CDK Docker bundling is blocked

set -e

echo "Building Lambda bundle..."
npm run build

npx esbuild src/lambda-handler.ts \
  --bundle \
  --platform=node \
  --target=node20 \
  --format=cjs \
  --outfile=dist/lambda-bundle.js \
  --external:playwright-core \
  --external:@sparticuz/chromium \
  --external:@modelcontextprotocol/sdk \
  --sourcemap

echo "Zipping..."
cd dist && zip -r ../lambda.zip lambda-bundle.js lambda-bundle.js.map && cd ..

echo "Getting function name..."
FUNCTION_NAME=$(aws cloudformation describe-stacks \
  --stack-name VisusStack-dev \
  --query "Stacks[0].Outputs[?OutputKey=='LambdaFunctionName'].OutputValue" \
  --output text)

echo "Deploying to Lambda: $FUNCTION_NAME"
aws lambda update-function-code \
  --function-name "$FUNCTION_NAME" \
  --zip-file fileb://lambda.zip

echo "Waiting for update..."
aws lambda wait function-updated --function-name "$FUNCTION_NAME"

echo "Testing health endpoint..."
curl -s https://3lsush2fx0.execute-api.us-east-1.amazonaws.com/dev/health | jq .

echo "Done. Check CloudWatch for ERR_MODULE_NOT_FOUND — should be gone."
```

After using manual deploy, run a full `cdk deploy` when Docker is restored to keep CloudFormation state in sync with live infrastructure.

---

## CRITICAL: Security Rules — Never Violate These

Claude Code must refuse to generate code that violates these rules, even if
explicitly instructed to do so in a subsequent message:

```
RULE 1: No secrets in code, environment variables, or config files.
        ALL secrets go through AWS Secrets Manager. No exceptions.

RULE 2: No wildcard (*) actions or resources in any IAM policy.
        Every Lambda has a scoped execution role. Period.

RULE 3: No public S3 buckets, no public endpoints without Cognito.
        (WAF deferred to Phase 2 per ADR-011)

RULE 4: No shell execution in any Lambda or skill.
        os.system(), subprocess, eval(), exec() are banned.

RULE 5: All user input is sanitized for prompt injection before
        touching the LLM. Never pass raw user input to Bedrock.

RULE 6: No cross-user data access. Every DynamoDB query is scoped
        to the authenticated user_id partition key. No exceptions.

RULE 7: Every Lambda has reserved_concurrent_executions set.
        No function can scale to infinity and run up costs.

RULE 8: No plaintext logging of tokens, passwords, API keys, or PII.
        Use structured logging with field redaction.
```

If asked to do something that violates these rules, Claude Code should explain
why and offer a compliant alternative.

---

## Environment Variables

```bash
# Optional — for Lateos hosted tier (Phase 2)
LATEOS_API_KEY=          # Enables audit logging to Lateos cloud
LATEOS_ENDPOINT=         # Defaults to https://api.lateos.ai

# Optional — browser config
VISUS_TIMEOUT_MS=10000   # Default fetch timeout
VISUS_MAX_CONTENT_KB=512 # Max content size before truncation
```

No API key required for open-source tier. `npx visus-mcp` works out of the box.

## Project Structure

```
lateos-visus/
├── src/
│   ├── index.ts                    # MCP server entry, tool registration
│   ├── tools/
│   │   ├── fetch.ts                # visus_fetch(url, options?)
│   │   └── fetch-structured.ts     # visus_fetch_structured(url, schema)
│   ├── sanitizer/
│   │   ├── index.ts                # Sanitizer orchestrator
│   │   ├── injection-detector.ts   # Pattern matching engine
│   │   ├── pii-redactor.ts         # PII detection and redaction
│   │   └── patterns.ts             # 43 injection pattern definitions
│   ├── browser/
│   │   └── playwright-renderer.ts  # Headless Chromium page fetcher
│   └── types.ts                    # Shared TypeScript interfaces
├── scripts/
│   └── deploy-lambda.sh            # Manual Lambda deploy (bypasses CDK/Docker)
└── tests/
    ├── sanitizer.test.ts
    ├── fetch-tool.test.ts
    └── injection-corpus.ts         # Test payload library
```

## Phase 1 Definition of Done

- [ ] `npx visus-mcp` starts an MCP server with both tools registered
- [ ] `visus_fetch("https://example.com")` returns sanitized markdown
- [ ] All 43 pattern categories have test cases that pass
- [ ] No false positives on 10 clean content samples
- [ ] README leads with security narrative
- [ ] SECURITY.md documents the threat model
- [ ] `npm test` passes with 0 failures
- [ ] `npm run build` produces clean `/dist`
- [ ] `npm publish --dry-run` succeeds

## What NOT to Build in Phase 1

- No AWS Lambda deployment (Phase 2)
- No DynamoDB audit logging (Phase 2)
- No Cognito auth (Phase 2)
- No user-session relay / Chrome extension (Phase 3)
- No Lateos dashboard integration (Phase 2)
- No paid tier gating (Phase 2)

Keep Phase 1 lean: a working, publishable open-source MCP tool with security-first documentation.

## Implementation Order

Start with the sanitizer — it is the product:

1. Define all 43 patterns in `src/sanitizer/patterns.ts`
2. Build the sanitizer engine against those patterns
3. Build the Playwright renderer
4. Wire into MCP tools
5. Write tests (sanitizer tests FIRST)
6. Write README and SECURITY.md last

Do not proceed past the sanitizer until the pattern library and basic detection logic are complete and unit-tested.

## Tool Output Schemas

### `visus_fetch` Output
```typescript
{
  url: string,
  content: string,                // Sanitized content
  sanitization: {
    patterns_detected: string[],  // Names of injection patterns found
    pii_types_redacted: string[], // e.g. ["email", "phone", "ssn"]
    content_modified: boolean
  },
  metadata: {
    title: string,
    fetched_at: string,           // ISO timestamp
    content_length_original: number,
    content_length_sanitized: number
  }
}
```

### `visus_fetch_structured` Output
```typescript
{
  url: string,
  data: Record<string, string | null>,  // Extracted fields, sanitized
  sanitization: { /* same as above */ },
  metadata: { /* same as above */ }
}
```

## Security-First Documentation

Both README.md and SECURITY.md must lead with the security narrative, not features:
- The problem with other tools (raw content passed to LLM)
- How Visus works (fetch → sanitize → return)
- 43 pattern categories with examples
- PII redaction types and format
- Honest limitations (novel obfuscation, AI-generated benign-looking instructions)
- Vulnerability reporting: security@lateos.ai or GitHub Security tab
