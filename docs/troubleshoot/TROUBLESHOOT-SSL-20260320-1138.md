# Visus MCP SSL Certificate Verification - Troubleshooting Log

Started: 2026-03-20 11:38
Goal: Fix SSL certificate verification for fetch() operations without disabling security

---

## [11:38:00] Step 1 - Identify Root Cause of SSL Failure

**Goal:** Determine why SSL certificate verification is failing with both native fetch and undici
**Reasoning:** Need to understand if this is a system-level certificate issue or Node.js configuration problem
**Action:** Test SSL with multiple tools to isolate the issue
**Result:**
```bash
curl --version: Uses SecureTransport (macOS native) and LibreSSL - works fine
openssl version: OpenSSL 3.6.1 - works fine
openssl s_client -connect example.com:443: Verify return code: 0 (ok)
node -e "fetch('https://example.com')": ERROR: fetch failed
```
**Status:** ✅ Success - System SSL works, Node.js SSL fails

---

## [11:39:00] Step 2 - Check Node.js Certificate Configuration

**Goal:** Determine if Node.js can access system certificates
**Reasoning:** nvm-installed Node.js on macOS often can't find system certificate store
**Action:** Check NODE_EXTRA_CA_CERTS and system certificate count
**Result:**
```bash
NODE_EXTRA_CA_CERTS: not set
System root certificates: 156 certificates in /System/Library/Keychains/SystemRootCertificates.keychain
Node.js location: /Users/leochong/.nvm/versions/node/v22.20.0/bin/node
```
**Root Cause Found:** Node.js installed via nvm cannot access macOS system certificate store
**Status:** ✅ Success - Issue identified

---

## [11:40:00] Step 3 - Export macOS Root Certificates

**Goal:** Create a PEM file containing all macOS system root certificates
**Reasoning:** Node.js can use a custom CA bundle via NODE_EXTRA_CA_CERTS environment variable
**Action:** security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain > system-ca-bundle.pem
**Result:**
```
Created: system-ca-bundle.pem (3,879 lines, 156 certificates)
Verified: 156 certificates exported successfully
```
**Status:** ✅ Success - CA bundle created

---

## [11:41:00] Step 4 - Test Node.js with CA Bundle

**Goal:** Verify that Node.js can use the exported certificate bundle
**Reasoning:** Need to confirm the fix works before updating configuration
**Action:** NODE_EXTRA_CA_CERTS="$(pwd)/system-ca-bundle.pem" node -e "fetch('https://example.com')"
**Result:**
```
SUCCESS: Fetched 528 bytes
```
**Status:** ✅ Success - SSL verification working with CA bundle

---

## [11:42:00] Step 5 - Update Claude Desktop Configuration

**Goal:** Configure visus-mcp to use the CA bundle for all requests
**Reasoning:** Replace insecure NODE_TLS_REJECT_UNAUTHORIZED=0 with proper certificate validation
**Action:** Update claude_desktop_config.json
**Result:**
```json
{
  "env": {
    "NODE_EXTRA_CA_CERTS": "/Users/leochong/Projects/visus-mcp/system-ca-bundle.pem"
  }
}
```
**Status:** ✅ Success - Configuration updated with proper SSL verification

---

## [11:43:00] Step 6 - Add CA Bundle to .gitignore

**Goal:** Prevent system-specific certificate bundle from being committed
**Reasoning:** CA bundle is system-specific and should be regenerated per-machine
**Action:** echo "system-ca-bundle.pem" >> .gitignore
**Result:** Added to .gitignore
**Status:** ✅ Success

---

# RESOLUTION SUMMARY

**Final Status:** ✅ RESOLVED

## Root Cause

nvm-installed Node.js on macOS cannot access the system certificate store located in `/System/Library/Keychains/SystemRootCertificates.keychain`. This caused all HTTPS requests via native fetch() and undici to fail with "fetch failed" or "unable to get local issuer certificate" errors.

## Resolution

1. **Exported macOS system root certificates** to a PEM file:
   ```bash
   security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain > system-ca-bundle.pem
   ```

2. **Configured Node.js to use the CA bundle** via `NODE_EXTRA_CA_CERTS` environment variable in Claude Desktop config:
   ```json
   "env": {
     "NODE_EXTRA_CA_CERTS": "/Users/leochong/Projects/visus-mcp/system-ca-bundle.pem"
   }
   ```

3. **Added system-ca-bundle.pem to .gitignore** to prevent committing system-specific files

## Verification

✅ SSL certificate verification: ENABLED
✅ HTTPS requests: WORKING
✅ Security: MAINTAINED (no certificate validation bypass)
✅ Test: `fetch('https://example.com')` returns 528 bytes successfully

## Alternative Solutions Considered

❌ **NODE_TLS_REJECT_UNAUTHORIZED=0**: Rejected - disables all certificate validation (security risk)
❌ **Using HTTP instead of HTTPS**: Rejected - defeats the security purpose of Visus
✅ **NODE_EXTRA_CA_CERTS with system certificates**: Selected - maintains security while fixing the issue

## Setup Instructions for Other Developers

On macOS with nvm-installed Node.js:

```bash
# 1. Export macOS system certificates
security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain > system-ca-bundle.pem

# 2. Add to Claude Desktop config
{
  "env": {
    "NODE_EXTRA_CA_CERTS": "/path/to/visus-mcp/system-ca-bundle.pem"
  }
}

# 3. Add to .gitignore
echo "system-ca-bundle.pem" >> .gitignore
```

## Lessons Learned

1. **nvm + macOS + SSL = certificate issues** - Always check certificate access when using nvm
2. **Never disable SSL verification** - Even for "quick testing", find the proper fix
3. **System certificates are accessible** - macOS provides all root certificates via security command
4. **NODE_EXTRA_CA_CERTS is the proper solution** - Documented Node.js feature for custom CA bundles
5. **Test with undici AND native fetch** - Both can have different certificate handling behaviors

## Files Modified

- `.gitignore` - Added system-ca-bundle.pem
- `claude_desktop_config.json` - Changed NODE_TLS_REJECT_UNAUTHORIZED=0 to NODE_EXTRA_CA_CERTS

## Files Created

- `system-ca-bundle.pem` - macOS system root certificates (156 certs, not committed to git)

---

**Resolution Completed:** 2026-03-20 11:43
**Total Time:** 5 minutes
**Final Verdict:** ✅ SSL certificate verification working properly with full security maintained
