# Visus MCP — Product Roadmap

## v0.1.0 ✅ PUBLISHED (2026-03-21)
- 43 injection pattern categories
- PII redaction (email, phone, SSN, credit card, IP)
- undici fetch() renderer (static + server-rendered pages)
- visus_fetch + visus_fetch_structured tools
- 95/95 tests passing
- Published to npm
- Claude Desktop smoke tested (4/4 passing)

## v0.2.0 ✅ PUBLISHED + DEPLOYED (2026-03-22)
- Playwright headless Chromium (JavaScript-rendered pages, SPAs)
- AWS Lambda renderer (x86_64, Amazon Linux, Node.js 20)
- API Gateway (REST API)
- Cognito User Pool with OAuth 2.0 (email authentication)
- DynamoDB audit logging table (KMS-encrypted, PITR in prod)
- IAM roles with scoped permissions
- CloudWatch structured logging (30-day retention)
- Dual-mode runtime (stdio MCP + Lambda unified codebase)
- BYOC support (user-supplied Lambda endpoint via VISUS_RENDERER_URL)
- Lateos managed endpoint live:
  https://wyomy29zd7.execute-api.us-east-1.amazonaws.com
- 95/95 tests passing (no regressions)
- Lambda smoke tests: 3/3 passing
  - example.com (static): 1.0s warm
  - github.com (SPA): 6.2s warm
  - medlineplus.gov (clinical): 3.0s warm

## v0.3.0 — PLANNED
Focus: managed tier activation — make the deployed
infrastructure useful to end users

- Activate Cognito authentication on managed endpoint
  (currently deployed but open — no auth enforced)
- Free tier rate limiting (requests/day per user)
- API key management for managed tier users
- CloudWatch metrics dashboard (usage visibility)
- WAF rules on API Gateway (bot protection)
- CORS restricted to authenticated origins
- npm publish v0.3.0

## v0.4.0 — PLANNED
Focus: paid tier + enterprise

- Stripe billing integration
- Usage dashboard for managed tier users
- Paid tier gating (rate limit increase)
- BYOC enterprise tier (dedicated Lambda, SLA documentation)
- Lateos platform integration
- Multi-region consideration (me-central-1 for MENA healthcare)

## Phase 3 — USER SESSION RELAY (future)
Focus: login-gated content (LinkedIn, X, EHR portals)

- Chrome extension / in-app browser layer
- User-authenticated session relay
- Content passes through Visus sanitizer before reaching Claude
- Zero Lateos infrastructure in the auth path (user's own session)
- Tagline: "What the web shows you, Lateos reads safely"
- This is the feature that unlocks LinkedIn, X, and clinical portals

## Architecture Decisions (permanent record)

| Decision | Rationale |
|---|---|
| Sanitizer always runs locally | PHI never touches Lateos infrastructure |
| x86_64 Lambda only | ARM64 incompatible with Playwright |
| us-east-1 for managed endpoint | Best Lambda cold start globally |
| me-central-1 reserved | Future Lateos backend (MENA healthcare) |
| Open endpoint until v0.3.0 | Minimize adoption friction at launch |
| Cognito deployed in v0.2.0 | Available, not yet enforced |
| DynamoDB deployed in v0.2.0 | Available, not yet activated for audit |
| undici fallback retained | Graceful degradation if Lambda unavailable |

## Known Limitations (Phase 2)

| Limitation | Resolution |
|---|---|
| Login-gated pages (LinkedIn, X) | Phase 3 user-session relay |
| Lambda cold start 4-5s | Provisioned concurrency (v0.3.0) |
| No rate limiting on managed endpoint | v0.3.0 |
| DynamoDB audit log not yet active | v0.3.0 activation |
| Cognito auth deployed but not enforced | v0.3.0 activation |
