# Lateos Visus Lambda - ES Module Dependency Resolution

Started: 2026-03-22 19:45:00
Goal: Deploy VisusStack-dev with working Lambda handler that includes all dependencies

---

## [19:45:05] Step 1 - Initial Deployment Attempt

**Goal:** Deploy VisusStack-dev with security controls enabled
**Reasoning:** Stack has never been deployed before (CDK diff showed all resources as new), need to create infrastructure
**Action:** `npx cdk deploy VisusStack-dev --require-approval never`
**Result:**
- Deployment successful
- All 39 resources created
- API endpoint: https://3lsush2fx0.execute-api.us-east-1.amazonaws.com/dev/
- Auth enforcement test: 401 ✅ (Cognito working)
- Health check test: 500 ❌ (Internal server error)
**Status:** ⚠️ Partial - Auth works, Lambda fails

---

## [19:46:10] Step 2 - Check Lambda Logs for Error

**Goal:** Identify why Lambda is failing
**Reasoning:** CloudWatch logs will show the initialization error
**Action:** `aws logs tail /aws/lambda/visus-mcp-dev --since 5m`
**Result:**
```
ERROR: Cannot use import statement outside a module
Runtime.UserCodeSyntaxError: SyntaxError: Cannot use import statement outside a module
```
**Status:** ✅ Success - Root cause identified: ES module syntax not recognized

---

## [19:47:20] Step 3 - Copy package.json to dist/

**Goal:** Enable ES module support in Lambda runtime
**Reasoning:** Lambda needs package.json with "type": "module" to parse import statements
**Action:** `cp package.json dist/package.json`
**Result:** package.json copied successfully
**Status:** ✅ Success

---

## [19:48:30] Step 4 - Redeploy with package.json

**Goal:** Fix ES module syntax error
**Reasoning:** With package.json in dist/, Node.js should recognize .js files as ES modules
**Action:** `npx cdk deploy VisusStack-dev --require-approval never`
**Result:**
- Deployment successful (Lambda code updated)
- Health check still returns 500
- New error in logs:
```
ERROR: Cannot find package '@modelcontextprotocol/sdk' imported from /var/task/index.js
ERR_MODULE_NOT_FOUND
```
**Status:** ⚠️ Partial - ES module syntax works now, but dependencies missing

---

## [19:49:45] Step 5 - Analyze Dependency Problem

**Goal:** Understand why node_modules are missing
**Reasoning:** Lambda deployment only includes dist/ folder, not node_modules/
**Action:** Review stack.ts configuration
**Result:**
```typescript
code: lambda.Code.fromAsset('dist')
```
- Only dist/ is packaged
- node_modules/ is NOT included
- ES modules require dependencies to be available at runtime
**Status:** ✅ Success - Problem identified

---

## [19:51:00] Step 6 - Attempt Full Project Deployment (FAILED)

**Goal:** Include node_modules by deploying entire project
**Reasoning:** Change fromAsset('dist') to fromAsset('.') with exclusions
**Action:** Modified stack.ts:
```typescript
code: lambda.Code.fromAsset('.', {
  exclude: ['cdk.out', 'infrastructure', 'tests', 'src', ...]
})
handler: 'dist/index.handler'
```
**Result:**
```
Failed to publish asset: timeout after 10000ms
```
- Asset is too large (includes all of node_modules/ ~200MB+)
- S3 upload times out
**Status:** ❌ Failed - Approach not viable

---

## [19:52:15] Step 7 - Revert to dist/ Deployment

**Goal:** Return to original configuration while finding solution
**Reasoning:** Need to package dependencies INTO dist/ folder instead
**Action:** Reverted stack.ts to:
```typescript
code: lambda.Code.fromAsset('dist')
handler: 'index.handler'
```
**Status:** ✅ Success - Reverted

---

## [19:53:30] Step 8 - Copy Production Dependencies to dist/node_modules

**Goal:** Bundle only required production dependencies into dist/
**Reasoning:** Lambda needs @aws-sdk, @modelcontextprotocol/sdk, cheerio, undici
**Action:**
```bash
mkdir -p dist/node_modules
cp -R node_modules/@aws-sdk dist/node_modules/
cp -R node_modules/@smithy dist/node_modules/
# Attempted: cd dist && npm install --production
```
**Result:** User interrupted - waiting for alternative approach
**Status:** ⏸️ Paused - Awaiting troubleshooting guidance from CLAUDE.md

---

## NEXT STEPS (Pending)

**Option A: Use esbuild bundler**
- Install esbuild as dev dependency
- Bundle all code + dependencies into single file
- Update CDK to use bundled output
- PRO: Single file, no dependency resolution issues
- CON: Larger bundle size

**Option B: Create deployment package script**
- npm script that copies dist/ + production node_modules/
- Prune dev dependencies before copy
- Deploy packaged folder
- PRO: Standard approach for Lambda
- CON: Manual packaging step

**Option C: Use AWS CDK NodejsFunction construct**
- Switch from lambda.Function to lambda-nodejs.NodejsFunction
- Automatic esbuild bundling
- Handles dependencies automatically
- PRO: Built-in CDK solution
- CON: Requires refactoring stack.ts

---

---

## [19:54:45] Step 9 - Switch to NodejsFunction with esbuild

**Goal:** Use CDK's built-in bundling solution
**Reasoning:** NodejsFunction automatically bundles TypeScript + dependencies using esbuild
**Action:** Modified stack.ts:
```typescript
import * as lambdaNodejs from 'aws-cdk-lib/aws-lambda-nodejs';

const visusFn = new lambdaNodejs.NodejsFunction(this, 'VisusFunction', {
  entry: 'src/lambda-handler.ts',
  handler: 'handler',
  bundling: {
    minify: false,
    sourceMap: true,
    externalModules: ['playwright-core', '@sparticuz/chromium'],
  },
  ...
});
```
**Result:** Stack configuration updated
**Status:** ✅ Success - Now deploying

---

**Current Status:** Deploying with NodejsFunction bundler
**Solution Implemented:** Option C (NodejsFunction)
**Expected Outcome:** All dependencies bundled automatically, ES modules resolved
