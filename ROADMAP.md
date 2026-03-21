# Visus MCP — Product Roadmap

## v0.1.0 ✅ PUBLISHED
- 43 injection pattern categories
- PII redaction (email, phone, SSN, CC, IP)
- undici fetch() renderer
- visus_fetch + visus_fetch_structured tools
- 95/95 tests passing
- Published to npm

## v0.2.0 — IN PROGRESS
- Lambda browser renderer (Playwright, Amazon Linux x86_64)
- BYOC support (user-supplied Lambda endpoint)
- Lateos managed endpoint (open, no auth — rate limiting deferred)
- CDK deployment template for self-hosted users
- Three-tier renderer fallback: Lambda → fetch()

## v0.3.0 — PLANNED
- API key authentication for managed endpoint
- Cognito user pool for multi-user support
- DynamoDB audit logging (HIPAA compliance trail)
- Rate limiting on managed tier (free vs paid)
- CloudWatch metrics dashboard

## v0.4.0 — PLANNED
- Paid tier billing (Stripe integration)
- Usage dashboard for managed tier users
- BYOC enterprise tier (dedicated Lambda, SLA)
- Lateos platform integration

## Deferred / Under Consideration
- Playwright local rendering (blocked by macOS ARM64 compatibility)
- Chrome extension / user-session relay (Phase 3 Visus feature)
- WAF protection on managed endpoint (post-v0.3.0)
- Pattern library expansion based on bypass reports

## Architecture Decisions
- Sanitizer ALWAYS runs locally — PHI never touches Lateos infrastructure
- Managed tier open (no auth) until v0.3.0 — minimize adoption friction
- BYOC uses same CDK template as Lateos managed deployment
- x86_64 Lambda required for Playwright (ARM64 incompatible)
