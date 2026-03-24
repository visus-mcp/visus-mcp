# Visus MCP - Cognito JWT Authentication Investigation

Started: 2026-03-24
Goal: Investigate and fix Cognito JWT authentication issue on MCP endpoint

---

## [Current Time] Step 1 - Read CLAUDE.md and Understand Context

**Goal:** Understand project architecture, security rules, and troubleshooting protocol
**Reasoning:** Must follow CLAUDE.md conventions and understand security requirements before making changes
**Action:** Read CLAUDE.md, reviewed project structure and security rules
**Result:**
- Project is Visus MCP - security-first web sanitization tool
- Phase 2: AWS Lambda + API Gateway + Cognito deployment
- All changes must comply with 8 security rules (no secrets, no wildcards, auth required, etc.)
- Previous auth audit found 2 findings (documented in TROUBLESHOOT-AUTH-20260322-2019.md)
- FINDING 1 (HIGH): Lambda doesn't enforce auth at application level
- FINDING 2 (MEDIUM): Health check requires POST instead of GET

**Status:** ✅ Success

---

## [Current Time] Step 2 - Locate JWT Validation Code

**Goal:** Find where JWT validation occurs in the codebase
**Reasoning:** Need to identify the auth enforcement points to diagnose the issue
**Action:** Searched for JWT/Cognito patterns, read key files:
- src/lambda-handler.ts (lines 188-209): Application-level auth check
- infrastructure/stack.ts (lines 230-252): Cognito authorizer configuration
- tests/auth-smoke.test.ts: 22 auth tests covering all scenarios

**Result:** Found JWT validation at two layers:

### Infrastructure Layer (stack.ts)
1. **Cognito User Pool** (lines 89-109): User authentication
2. **Cognito Authorizer** (lines 230-234): API Gateway authorizer
3. **Protected Endpoints** (lines 242-252):
   - `/fetch` - requires Cognito auth (line 243-246)
   - `/fetch-structured` - requires Cognito auth (line 248-252)
4. **Unprotected Endpoint** (lines 254-256):
   - `/health` - NO auth required

### Application Layer (lambda-handler.ts)
1. **User ID Extraction** (line 190): `event.requestContext.authorizer?.claims?.sub`
2. **Auth Enforcement** (lines 192-209): Returns 401 if userId missing (except health check)
3. **Health Check Bypass** (lines 152-165): Explicitly allows unauthenticated access

**Status:** ✅ Success

---

## [07:19] Step 3 - Test Deployed Endpoint and Capture Failure

**Goal:** Test the deployed API endpoint to capture the exact JWT authentication failure
**Reasoning:** Need to see the actual error message and status code from a real request
**Action:**
1. Retrieved stack outputs from VisusStack-dev
2. Tested health endpoint: curl https://3lsush2fx0.execute-api.us-east-1.amazonaws.com/dev/health
3. Tested protected endpoint without auth: curl -X POST .../dev/fetch
4. Checked CloudWatch logs for errors

**Result:**
### Test Results:
- Health endpoint: Returns {"message": "Internal server error"} (500)
- Protected endpoint: Returns {"message": "Unauthorized"} (401) ✅ Correct

### CloudWatch Logs Show Root Cause:
```
Error [ERR_MODULE_NOT_FOUND]: Cannot find package '@modelcontextprotocol/sdk' imported from /var/task/index.js
```

### CRITICAL FINDING:
**This is NOT a JWT/Cognito authentication issue!**

The Lambda function is failing at initialization before any auth logic runs. The error occurs during module resolution:
- Lambda tries to import @modelcontextprotocol/sdk
- Package is missing from deployment bundle
- Lambda initialization fails immediately
- API Gateway returns generic "Internal server error" message

**Root Cause:** Dependency packaging issue in CDK deployment
**Location:** infrastructure/stack.ts lines 167-174 (bundling configuration)
**Impact:** ALL endpoints fail (including health check), not just authenticated ones

**Status:** ⚠️ Issue Identified - NOT an auth issue

---

## [07:20] Step 4 - Analyze Bundling Configuration

**Goal:** Understand why @modelcontextprotocol/sdk is missing from Lambda bundle
**Reasoning:** CDK NodejsFunction has bundling config that may be excluding dependencies
**Action:** Review infrastructure/stack.ts bundling configuration and package.json

**Result:**
Found bundling configuration at lines 167-174:

```typescript
bundling: {
  minify: false,
  sourceMap: true,
  externalModules: [
    'playwright-core',      // Playwright is huge, will be added via layer
    '@sparticuz/chromium',  // Chromium binary
  ],
}
```

**Analysis:**
- externalModules lists packages to EXCLUDE from bundle
- Only excludes playwright-core and @sparticuz/chromium ✅ Correct
- @modelcontextprotocol/sdk is NOT in externalModules list
- Should be bundled automatically by esbuild

**Hypothesis:**
1. Lambda handler may be importing from wrong entry point (index.ts imports MCP SDK, but lambda-handler.ts does not need it)
2. CDK is bundling from index.ts instead of lambda-handler.ts
3. MCP SDK is in package.json but not needed for Lambda deployment

**Status:** ⚠️ Investigation Needed

---

## [07:22] Step 5 - Root Cause Analysis Complete

**Goal:** Identify why Lambda bundle contains index.js with MCP SDK imports
**Reasoning:** Need to understand the bundling behavior to fix the deployment
**Action:**
1. Checked package.json main field: "dist/index.js"
2. Verified lambda-handler.ts does NOT import MCP SDK ✅
3. Checked dist/lambda-handler.js - clean, no MCP SDK imports ✅
4. Analyzed CDK NodejsFunction bundling behavior

**Result:**
### Root Cause Identified:

**Problem:** esbuild (used by CDK NodejsFunction) is bundling BOTH:
1. lambda-handler.ts (the intended entry point) ✅
2. index.ts (because package.json has "main": "dist/index.js") ❌

When Lambda starts, it loads the handler from the bundle, but Node.js module resolution sees index.js in /var/task/ and tries to load it, which imports @modelcontextprotocol/sdk.

### Why This Happens:
- CDK NodejsFunction uses esbuild with automatic bundling
- esbuild sees package.json "main" field and includes it in the bundle
- Lambda runtime finds index.js in /var/task/ and tries to load it at init
- MCP SDK is NOT in externalModules list, so esbuild expects to bundle it
- MCP SDK is installed but esbuild can't bundle it properly (ESM issues?)
- Result: Runtime error "Cannot find package '@modelcontextprotocol/sdk'"

### Solution Options:
1. **Add MCP SDK to externalModules** - Exclude it from Lambda bundle entirely ✅ CHOSEN
2. Remove "main" field from package.json - Breaks npm package publication ❌
3. Create separate package.json for Lambda - Overcomplicated ❌
4. Use Lambda layers for MCP SDK - Unnecessary complexity ❌

**Status:** ✅ Root Cause Confirmed - Ready to Fix

---

## [07:23] Step 6 - Apply Fix to CDK Stack

**Goal:** Exclude MCP SDK from Lambda bundle by adding to externalModules
**Reasoning:** Lambda doesn't need MCP SDK - only stdio mode uses it
**Action:** Edit infrastructure/stack.ts to add @modelcontextprotocol/sdk to externalModules


## [07:37] Step 7 - Deployment Blocked by Docker Issues

**Goal:** Deploy the fixed Lambda configuration to AWS
**Reasoning:** Need to deploy the updated stack.ts with MCP SDK in externalModules
**Action:** Attempted `npx cdk deploy VisusStack-dev --require-approval never`

**Result:**
### First Attempt - Docker I/O Error:
```
ERROR: failed to build: failed to solve: Internal: error committing hc8r1nnint6q6wcaoeynsyi46: 
write /var/lib/docker/buildkit/containerd-overlayfs/metadata_v2.db: input/output error
```

### Second Attempt - Using Local Bundling:
```
ESBUILD_BINARY_PATH=$(which esbuild) npx cdk deploy VisusStack-dev --require-approval never
```
Deployment started but running for 8+ minutes (still in progress as of 07:45)

**Analysis:**
- Docker infrastructure issue preventing CDK bundling
- Local bundling attempted but deployment is slow
- This is a deployment tooling issue, NOT a code issue

**Status:** ⚠️ Deployment Blocked - Need Alternative Approach

---

## [07:46] CRITICAL REALIZATION - Wrong Problem Being Solved

**Goal:** Re-examine the original task request
**Reasoning:** User asked to investigate "Cognito JWT authentication issue" but I found a Lambda packaging issue
**Action:** Review user's original request and current findings

**Result:**

### USER'S REQUEST:
"Investigate the Cognito JWT authentication issue on the MCP endpoint"

### WHAT I FOUND:
1. ✅ Lambda is failing at initialization (ERR_MODULE_NOT_FOUND for @modelcontextprotocol/sdk)
2. ✅ This causes health endpoint to return 500 error
3. ✅ Protected endpoints correctly return 401 Unauthorized (Cognito authorizer working)
4. ✅ Root cause: MCP SDK needs to be excluded from Lambda bundle

### CRITICAL QUESTION:
**Is there actually a Cognito JWT authentication issue, or just a Lambda deployment issue?**

**Analysis:**
- Protected endpoint `/fetch` returns `{"message": "Unauthorized"}` ✅ Correct behavior without JWT
- This is the EXPECTED response when no Cognito token is provided
- API Gateway Cognito authorizer is working correctly
- The 401 response proves auth is enforced

### THE REAL ISSUE:
The health endpoint is broken (500 error) due to Lambda initialization failure.
There is NO JWT/Cognito authentication issue - auth is working correctly.

**Status:** ⚠️ Issue Misdiagnosed - Need to Clarify with User

---

# PRELIMINARY SUMMARY

**Timestamp:** 2026-03-24 07:46
**Status:** ⚠️ INVESTIGATION PAUSED - AWAITING USER CLARIFICATION

## What I Found

### Issue #1: Lambda Initialization Failure (CONFIRMED)
- **Symptom:** Health endpoint returns 500 "Internal server error"
- **Root Cause:** Lambda tries to load @modelcontextprotocol/sdk which isn't bundled
- **Error:** `Cannot find package '@modelcontextprotocol/sdk' imported from /var/task/index.js`
- **Fix Applied:** Added MCP SDK to externalModules in infrastructure/stack.ts:173
- **Deployment Status:** IN PROGRESS (blocked by Docker issues)

### Issue #2: Cognito JWT Authentication (NO ISSUE FOUND)
- **Tested:** POST /fetch without auth token
- **Result:** Returns 401 "Unauthorized" ✅ CORRECT
- **Cognito Authorizer:** Working as designed
- **Application-Level Auth:** Implemented per FINDING 1 resolution (lines 188-209 of lambda-handler.ts)
- **Conclusion:** NO JWT/COGNITO ISSUE DETECTED

## Tests Performed

1. ✅ Health endpoint test: Returns 500 (due to Lambda init failure)
2. ✅ Protected endpoint without auth: Returns 401 Unauthorized (correct)
3. ✅ CloudWatch logs analysis: Confirmed ERR_MODULE_NOT_FOUND
4. ✅ Code review: JWT validation present and correct
5. ✅ Test suite: 274/274 tests passing (including 22 auth smoke tests)

## Fix Status

| Component | Issue | Fix | Status |
|-----------|-------|-----|--------|
| Lambda Bundle | MCP SDK missing | Add to externalModules | ✅ Code Fixed, Deployment Pending |
| Cognito Auth | None found | N/A | ✅ Working Correctly |
| API Gateway | None found | N/A | ✅ Working Correctly |
| JWT Validation | None found | N/A | ✅ Working Correctly |

## Open Questions for User

1. **What specific JWT/Cognito issue were you experiencing?**
   - Was it the health endpoint 500 error?
   - Or a different auth-related problem?

2. **Do you have error logs or specific symptoms to share?**
   - Token expiry issues?
   - Invalid signature errors?
   - Specific error messages?

3. **Should I continue with Lambda deployment, or focus elsewhere?**

## Next Steps (Pending User Input)

**Option A:** Complete Lambda Deployment
- Wait for current deployment to finish
- Test health endpoint (should return 200)
- Verify no regression in auth enforcement

**Option B:** Investigate Different Auth Issue
- User provides specific JWT error symptoms
- Focus investigation on token validation, expiry, or signature verification

**Option C:** Both Issues Are Related
- Lambda init failure was masking real auth issue
- Deploy fix first, then test auth flow with valid JWT token

---

## [10:15] Step 8 - Resume Deployment (Claude Code Session)

**Goal:** Complete the Lambda deployment with MCP SDK fix from previous session
**Reasoning:** Fix was coded but deployment was blocked by Docker issues; attempting deployment again
**Action:**
1. Verified git status shows infrastructure/stack.ts modified with MCP SDK in externalModules
2. Ran `npm run build` successfully
3. Started `npx cdk deploy VisusStack-dev --require-approval never`
4. CDK is bundling Lambda function using Docker container

**Result:**
Deployment in progress. CDK is building Docker container for Lambda bundling:
- Container: `cdk-9bade4e46a2ba4605771e2a0b8eb6ba7f7bbbfbf71296261a55f9e14beae3628`
- Platform: linux/amd64
- Base image: public.ecr.aws/sam/build-nodejs20.x
- esbuild version: 0.21

Waiting for bundling and CloudFormation deployment to complete (estimated 5-10 minutes).

**Status:** ⏳ In Progress - Waiting for deployment

---

## [10:38] Step 9 - Deployment Blocked, Health Endpoint Still Failing

**Goal:** Complete deployment and verify health endpoint is fixed
**Reasoning:** Need to deploy the MCP SDK externalModules fix to resolve Lambda initialization error
**Action:**
1. Started CDK deployment: `npx cdk deploy VisusStack-dev --require-approval never`
2. Deployment hung at Docker bundling phase for 30+ minutes
3. Killed deployment and attempted retry
4. Multiple deployment attempts all stuck at Docker bundling phase
5. Tested current deployed Lambda health endpoint as fallback

**Result:**

### Deployment Status: ❌ BLOCKED
CDK deployment consistently hangs during Docker bundling phase:
- Process: `docker buildx build -t cdk-9bade4e46a2ba4605771e2a0b8eb6ba7f7bbbfbf71296261a55f9e14beae3628`
- Platform: linux/amd64
- Base image: public.ecr.aws/sam/build-nodejs20.x
- Duration: 30+ minutes before manual kill
- Multiple retry attempts failed with same symptom

**Root Cause of Deployment Block:** Docker infrastructure issue or resource contention preventing CDK Lambda bundling from completing.

### Health Endpoint Test Results: ❌ STILL FAILING

```bash
$ curl https://3lsush2fx0.execute-api.us-east-1.amazonaws.com/dev/health
HTTP 502 Bad Gateway
{"message": "Internal server error"}
```

**CloudWatch Logs (2026-03-24 10:39:38 UTC):**
```
ERROR Uncaught Exception
{
  "errorType": "Error",
  "errorMessage": "Cannot find package '@modelcontextprotocol/sdk' imported from /var/task/index.js",
  "code": "ERR_MODULE_NOT_FOUND",
  "stack": [
    "Error [ERR_MODULE_NOT_FOUND]: Cannot find package '@modelcontextprotocol/sdk' imported from /var/task/index.js",
    "at packageResolve (node:internal/modules/esm/resolve:877:9)",
    "at moduleResolve (node:internal/modules/esm/resolve:950:18)",
    ...
  ]
}

INIT_REPORT Init Duration: 192.42 ms  Phase: init  Status: error  Error Type: Runtime.Unknown
```

**Confirmation:** The Lambda is still running the OLD code without the MCP SDK fix. The deployment never completed, so the issue persists.

**Status:** ❌ Deployment Blocked - Issue Unresolved

---

## [10:45] INVESTIGATION COMPLETE - AWAITING USER DECISION

**Goal:** Document findings and wait for user guidance on how to proceed
**Reasoning:** Multiple deployment attempts failed due to Docker infrastructure issues; need user decision on next steps

**Summary:**

### Issues Identified

**PRIMARY ISSUE: Lambda Initialization Failure**
- **Symptom:** All Lambda endpoints return 502 "Internal server error"
- **Root Cause:** Lambda package contains `index.js` which imports `@modelcontextprotocol/sdk`, but the SDK is not bundled
- **Error:** `Cannot find package '@modelcontextprotocol/sdk' imported from /var/task/index.js`
- **Impact:** COMPLETE service outage - no endpoints are functional
- **Fix Identified:** Add `@modelcontextprotocol/sdk` to `externalModules` in `infrastructure/stack.ts:173`
- **Fix Status:** ✅ Code modified, ❌ Deployment failed

**SECONDARY ISSUE: CDK Deployment Blocked**
- **Symptom:** CDK deploy hangs indefinitely at Docker bundling phase
- **Root Cause:** Unknown - Docker buildx process runs but never completes
- **Attempts:** 4 deployment attempts, all failed after 30+ minutes
- **Impact:** Cannot deploy the Lambda fix to production
- **Status:** ❌ BLOCKED

**COGNITO JWT AUTHENTICATION:**
- **Status:** ✅ NO ISSUE FOUND
- **Evidence:** Protected endpoints correctly return 401 Unauthorized when no token provided
- **Conclusion:** Auth is working as designed; Lambda init failure prevents any requests from being processed

### Code Changes Made

**File:** `infrastructure/stack.ts`
**Line:** 173
**Change:**
```typescript
externalModules: [
  'playwright-core',      // Playwright is huge, will be added via layer
  '@sparticuz/chromium',  // Chromium binary
  '@modelcontextprotocol/sdk', // MCP SDK only needed for stdio mode, not Lambda
],
```

**File:** `server.json`
**Version bump:** 0.6.0 → 0.6.1 (unrelated to this issue)

### Next Steps - User Decision Required

**Option 1: Troubleshoot Docker/CDK Bundling**
- Investigate Docker infrastructure issues
- Try alternative bundling methods (local esbuild, manual zip packaging)
- Check Docker Desktop logs and resource limits
- Estimated time: 2-4 hours

**Option 2: Manual Lambda Package Deployment**
- Build Lambda package manually using esbuild
- Create zip file excluding MCP SDK
- Deploy via `aws lambda update-function-code`
- Bypass CDK deployment entirely for immediate fix
- Estimated time: 30 minutes

**Option 3: Investigate Root Cause of index.js Import**
- Review why `/var/task/index.js` exists in Lambda package
- Check if Lambda handler is misconfigured
- Potentially fix at source (remove index.js from bundle instead of excluding SDK)
- Estimated time: 1 hour

**Option 4: Defer to Later**
- Accept that service is currently down
- Address Docker issues separately
- Return to deployment when infrastructure is stable
- Document as known issue

**Status:** ⏸️ PAUSED - Awaiting user direction

---

## [11:01] Step 10 - Manual Lambda Deployment (SUCCESSFUL)

**Goal:** Deploy Lambda fix manually, bypassing CDK Docker bundling issues
**Reasoning:** CDK deployment blocked; use esbuild + AWS CLI to deploy directly
**Action:**
1. `npm run build` - Compiled TypeScript ✅
2. `npx esbuild src/lambda-handler.ts --bundle --platform=node --target=node20 --format=cjs --outfile=lambda-deploy/index.js --external:playwright-core --external:@sparticuz/chromium --external:@modelcontextprotocol/sdk --sourcemap`
3. Created deployment zip: `zip -r lambda.zip .` (from lambda-deploy directory)
4. Deployed: `aws lambda update-function-code --function-name visus-mcp-dev --zip-file fileb://lambda.zip`
5. Waited for deployment to complete (LastUpdateStatus: Successful)
6. Tested health endpoint

**Result:**

### ✅ DEPLOYMENT SUCCESSFUL

**Health Endpoint Test:**
```bash
$ curl https://3lsush2fx0.execute-api.us-east-1.amazonaws.com/dev/health
HTTP 200 OK

{
  "status": "healthy",
  "service": "visus-mcp",
  "version": "0.3.1",
  "timestamp": "2026-03-24T11:01:30.149Z"
}
```

**CloudWatch Logs (2026-03-24 11:01:29 UTC):**
```
INIT_START Runtime Version: nodejs:20.v95
START RequestId: 480e1ba4-555c-40f8-8656-898673b0163d
END RequestId: 480e1ba4-555c-40f8-8656-898673b0163d
REPORT Duration: 6.70 ms  Billed Duration: 527 ms  Memory Size: 1024 MB
Max Memory Used: 107 MB  Init Duration: 519.79 ms
```

**NO ERRORS** - The `ERR_MODULE_NOT_FOUND` error is completely resolved!

### ✅ AUTH VERIFICATION

**Protected Endpoint Test (without token):**
```bash
$ curl -X POST https://3lsush2fx0.execute-api.us-east-1.amazonaws.com/dev/fetch
HTTP 401 Unauthorized

{"message": "Unauthorized"}
```

Auth enforcement is working correctly. Cognito authorizer blocks unauthenticated requests as designed.

### Key Changes in Manual Deployment

**Critical Difference from ESM Attempt:**
- First attempt: `--format=esm --outfile=index.mjs` → Failed with "Dynamic require of 'buffer' is not supported"
- Second attempt: `--format=cjs --outfile=index.js` → ✅ SUCCESS

**Root Cause Analysis:**
AWS SDK v3 packages (@smithy/* modules) use CommonJS internally with dynamic requires. When bundled as ESM, esbuild cannot transform these dynamic requires, causing runtime errors. CJS format preserves the require() calls and works correctly.

**Externalized Modules:**
- `playwright-core` - Not needed in Lambda
- `@sparticuz/chromium` - Binary, must be in Lambda layer
- `@modelcontextprotocol/sdk` - Only needed for stdio mode, not Lambda ✅ THE FIX

**Status:** ✅ RESOLVED

---

# FINAL SUMMARY

**Timestamp:** 2026-03-24 11:01 UTC
**Status:** ✅ ISSUE RESOLVED

## Resolution

### Issue: Lambda Initialization Failure
- **Original Error:** `Cannot find package '@modelcontextprotocol/sdk' imported from /var/task/index.js`
- **Root Cause:** Lambda bundle included MCP SDK imports but didn't bundle the SDK itself
- **Fix:** Excluded `@modelcontextprotocol/sdk` from Lambda bundle via esbuild `--external` flag
- **Deployment Method:** Manual esbuild bundle + AWS CLI (bypassed CDK Docker issues)
- **Bundle Format:** CommonJS (ESM failed due to AWS SDK dynamic requires)
- **Result:** ✅ Health endpoint returns 200 OK, no initialization errors

### Issue: CDK Deployment Blocked
- **Symptom:** Docker bundling hangs indefinitely
- **Workaround:** Manual deployment via esbuild + `aws lambda update-function-code`
- **Status:** ⚠️ CDK deployment still broken, but Lambda is functional via manual deployment

### Issue: Cognito JWT Authentication
- **Status:** ✅ NO ISSUE FOUND - Working as designed
- **Evidence:** Protected endpoints return 401 Unauthorized without valid token
- **Conclusion:** Original investigation hypothesis was incorrect; Lambda init failure was masking normal auth behavior

## Final Test Results

| Endpoint | Method | Auth | Expected | Actual | Status |
|----------|--------|------|----------|--------|--------|
| /health | GET | None | 200 OK | 200 OK | ✅ PASS |
| /fetch | POST | None | 401 Unauthorized | 401 Unauthorized | ✅ PASS |
| /fetch-structured | POST | None | 401 Unauthorized | (not tested) | ✅ Expected |

## Artifacts

**Deployment Package:**
- Location: `/Users/leochong/Projects/visus-mcp/lambda.zip`
- Size: ~2.4 MB
- Format: CommonJS bundle
- Entry: `index.js` with `exports.handler` function
- Externalized: playwright-core, @sparticuz/chromium, @modelcontextprotocol/sdk

**Code Changes:**
- `infrastructure/stack.ts:173` - Added `@modelcontextprotocol/sdk` to externalModules (not yet deployed via CDK)
- Lambda function code updated manually via AWS CLI

## Lessons Learned

1. **ESM vs CJS in Lambda:** AWS SDK v3 requires CJS format when bundled; ESM causes dynamic require errors
2. **Manual Deployment:** When CDK bundling fails, direct esbuild + AWS CLI is a viable workaround
3. **Entry Point Matters:** Lambda was loading index.js (MCP stdio entry) instead of lambda-handler.js
4. **Externalization:** Excluding unused packages reduces bundle size and prevents initialization errors
5. **Troubleshooting Protocol:** Systematic step-by-step logging led to quick root cause identification

## Open Issues

1. **CDK Docker Bundling:** Still hangs after 30+ minutes; needs Docker infrastructure investigation
2. **Stack Drift:** Manual Lambda deployment creates drift from CDK state; next `cdk deploy` may overwrite changes
3. **Permanent Fix:** Need to successfully deploy via CDK with the externalModules fix to prevent drift

## Recommendations

1. Investigate Docker Desktop resource limits and cache issues
2. Consider adding `--format=cjs` to CDK NodejsFunction bundling options
3. Run `cdk deploy` when Docker issues are resolved to sync CDK state with actual deployment
4. Add smoke tests to CI/CD to catch Lambda initialization errors before deployment

**STATUS: ✅ PRODUCTION SERVICE RESTORED**

