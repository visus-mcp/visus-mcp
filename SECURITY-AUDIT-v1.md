# Visus MCP — Security Audit v1

**Status:** ✅ **COMPLETED** — Auth Smoke Tests (2026-03-22)
**Scope:** Authentication enforcement and Lambda handler security
**Version:** v0.3.1 (security hardening release)

---

## Executive Summary

**Audit Completed:** 2026-03-22
**Tests Executed:** 146 passing (24 auth-specific tests)
**Findings:** 2 (1 HIGH, 1 LOW)
**Resolution:** ✅ Both findings resolved in v0.3.1
**Security Posture:** SECURE (after remediation)

---

## Audit Scope — Authentication Enforcement

### Objectives
1. Verify authentication is enforced at both infrastructure and application layers
2. Identify gaps where direct Lambda invocation could bypass API Gateway auth
3. Validate CORS enforcement and origin validation
4. Ensure health check endpoints follow REST conventions
5. Confirm no sensitive data exposure in unauthenticated paths

### Methodology
- **Approach:** Comprehensive smoke testing with mock API Gateway events
- **Test Categories:** 8 (health endpoints, auth validation, CORS, method enforcement, input validation, unknown endpoints, security audit)
- **Test Count:** 24 auth-specific tests (22 original + 2 added in v0.3.1)
- **Environment:** Jest with mocked AWS Lambda context
- **Documentation:** `TROUBLESHOOT-AUTH-20260322-2019.md`

---

## Findings and Resolutions

### 🔴 FINDING 1: No Application-Level Auth Enforcement (HIGH)

**Status:** ✅ **RESOLVED in v0.3.1**
**Location:** `src/lambda-handler.ts:190-209` (post-fix)
**Severity:** HIGH
**Discovered:** 2026-03-22

**Original Issue:**
- Lambda handler trusted API Gateway's Cognito authorizer without validation
- Fell back to `user_id = 'anonymous'` if authorizer context was missing (line 132, v0.3.0)
- Direct Lambda invocation (AWS SDK, console, cross-account) bypassed all authentication
- Audit logs showed "anonymous" making attribution impossible

**Risk:**
- Unauthenticated requests possible via direct Lambda invocation
- Resource policy or IAM-based invocations would process without auth
- Security gap violated defense-in-depth principle

**Resolution (v0.3.1):**
```typescript
// SECURITY FIX (FINDING 1): Application-level authentication enforcement
// Extract user ID from Cognito authorizer
const userId = event.requestContext.authorizer?.claims?.sub;

// Require authentication for all protected endpoints (not already handled above)
if (!userId) {
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: 'auth_required',
    request_id: requestId,
    path: event.path,
    reason: 'Missing Cognito authorizer context - Lambda must be invoked via API Gateway',
  }));

  return {
    statusCode: 401,
    headers: corsHeaders,
    body: JSON.stringify({
      error: 'Unauthorized: Authentication required. This Lambda must be invoked via API Gateway with Cognito authorizer.',
    }),
  };
}
```

**Verification:**
- ✅ Tests confirm 401 returned for missing auth context
- ✅ `auth_required` event logged for security monitoring
- ✅ No anonymous audit logs possible
- ✅ Health check endpoint explicitly excluded

**Impact:** Defense-in-depth implemented. Direct Lambda invocation now rejected.

---

### 🟡 FINDING 2: Health Endpoint Requires POST (LOW)

**Status:** ✅ **RESOLVED in v0.3.1**
**Location:** `src/lambda-handler.ts:152-165` (post-fix)
**Severity:** LOW
**Discovered:** 2026-03-22

**Original Issue:**
- Health check endpoint required POST method (non-standard)
- Method validation occurred before path routing (lines 156-162, v0.3.0)
- Standard monitoring tools (AWS Health Checks, CloudWatch Synthetics) expect GET
- API Gateway health check configuration could fail with default settings

**Impact:**
- Operational tooling compatibility issues
- Non-standard REST convention
- Not a security vulnerability, but affects observability

**Resolution (v0.3.1):**
```typescript
// Health check endpoint (no auth required, allows GET and POST)
// SECURITY FIX (FINDING 2): Moved before POST-only validation to support standard GET health checks
if (event.path === '/health' || event.path === '/dev/health' || event.path === '/prod/health') {
  return {
    statusCode: 200,
    headers: corsHeaders,
    body: JSON.stringify({
      status: 'healthy',
      service: 'visus-mcp',
      version: '0.3.1',
      timestamp: new Date().toISOString(),
    }),
  };
}

// Only allow POST requests for protected endpoints
if (event.httpMethod !== 'POST') {
  return {
    statusCode: 405,
    headers: corsHeaders,
    body: JSON.stringify({ error: 'Method not allowed. Use POST.' }),
  };
}
```

**Changes:**
- Health check moved before POST-only validation
- Supports both GET and POST methods
- CORS updated to allow `GET, POST, OPTIONS`

**Verification:**
- ✅ GET /health returns 200 without auth
- ✅ POST /health returns 200 without auth
- ✅ CORS headers include GET method
- ✅ Standard monitoring tools compatible

**Impact:** Standard REST conventions restored. Operational tooling compatibility ensured.

---

## Security Posture Assessment

### Before v0.3.1
**Overall:** ADEQUATE WITH GAPS
**Critical Issue:** Application-level auth missing (HIGH severity)
**Compliance:** 93.75% (7.5/8 CLAUDE.md security rules)

### After v0.3.1
**Overall:** ✅ **SECURE**
**Critical Issues:** NONE
**Compliance:** 100% (8/8 CLAUDE.md security rules)

---

## Confirmed Secure (No Changes Required)

✅ **CORS Enforcement** - Origin validation working correctly, malicious origins rejected
✅ **User ID Extraction** - Cognito claims properly extracted when present
✅ **Input Validation** - Malformed requests (missing url, schema, invalid JSON) rejected
✅ **Method Enforcement** - Non-POST requests blocked for protected endpoints
✅ **Audit Logging** - Fire-and-forget DynamoDB logging operational
✅ **Health Check Bypass** - Intentionally unauthenticated, returns only non-sensitive metadata
✅ **Unknown Endpoints** - Returns 404 with clear error message

---

## Infrastructure Layer (Not Tested - Requires Live Deployment)

⚠️ **API Gateway Cognito Authorizer** - Requires live Cognito User Pool
⚠️ **API Key Enforcement** - Requires live API Gateway deployment
⚠️ **Usage Plan Rate Limiting** - Requires traffic simulation
⚠️ **Lambda Resource Policy** - Requires IAM integration testing
⚠️ **Cross-Account Invocation** - Requires multi-account test environment

**Recommendation:** Create integration test suite for deployed infrastructure validation.

---

## Test Results

**Total Tests:** 146 passing (100%)
**Test Suites:** 4 passing
**Execution Time:** ~3.9s
**Zero Regressions:** All existing tests continue to pass

**Test Breakdown:**
1. Sanitizer tests: 43 passing
2. Fetch tool tests: 50+ passing
3. PII allowlist tests: 26 passing
4. **Auth smoke tests: 24 passing** (4 health endpoint, 3 protected without auth, 3 protected with auth, 3 CORS, 3 method enforcement, 3 input validation, 1 unknown endpoint, 4 security audit resolutions)

---

## Compliance with CLAUDE.md Security Rules

| Rule | Status | Verification |
|------|--------|-------------|
| RULE 1: No secrets in code | ✅ PASS | No hardcoded secrets found |
| RULE 2: No wildcard IAM | ✅ PASS | All policies scoped in stack.ts |
| RULE 3: No public endpoints without Cognito | ✅ PASS | /health is public (intentional), /fetch and /fetch-structured require auth |
| RULE 4: No shell execution | ✅ PASS | No os.system/subprocess/eval/exec |
| RULE 5: Sanitize user input | ✅ PASS | All content passes through sanitizer |
| RULE 6: No cross-user data access | ✅ PASS | DynamoDB writes scoped to user_id |
| RULE 7: Reserved concurrent executions | ✅ PASS | Set to 10 (dev) / 100 (prod) |
| RULE 8: No plaintext PII logging | ✅ PASS | Structured logging, no secrets |

**Overall Compliance:** 100% (8/8 rules)

---

## Recommendations for Future Audits

### Phase 2 (Next Audit - Post-Deployment)
1. **Integration Testing:** Deploy to dev account and verify:
   - API Gateway Cognito authorizer blocks unauthenticated requests
   - Direct Lambda invocation properly restricted via resource policy
   - Rate limiting triggers at configured thresholds
   - Cross-account invocation properly denied

2. **Penetration Testing:** Red team engagement to test:
   - JWT manipulation attempts
   - Token replay attacks
   - CORS bypass attempts
   - DynamoDB injection via audit log fields

3. **Sanitizer Deep Dive:** Comprehensive bypass testing:
   - 50+ crafted payloads across all 43 pattern categories
   - Novel obfuscation techniques
   - False positive rate measurement

### Phase 3 (After User-Session Relay)
- Chrome extension security review
- Cookie/session token handling
- Login-gated page access controls

---

## Bug Bounty Program (Planned)

| Severity | Reward |
|---|---|
| Critical (sanitizer bypass, auth bypass) | $500–$2,000 |
| High (PII leakage, rate limit bypass) | $200–$500 |
| Medium (false positive causing data loss) | $50–$200 |
| Low (documentation issues, minor bypasses) | Recognition + HALL_OF_FAME.md |

*Bounty program activates after v0.4.0 deployment.*

---

## Documentation References

- **Troubleshooting Log:** `TROUBLESHOOT-AUTH-20260322-2019.md`
- **Test Suite:** `tests/auth-smoke.test.ts`
- **Fixed Code:** `src/lambda-handler.ts` (v0.3.1)
- **Project Status:** `STATUS.md` (updated 2026-03-22 20:23 JST)

---

*Audit Conducted By:* Claude Code (Anthropic)
*Audit Date:* 2026-03-22
*Remediation Date:* 2026-03-22
*Version:* v0.3.1
*Contact:* security@lateos.ai
*Repository:* https://github.com/visus-mcp/visus-mcp
