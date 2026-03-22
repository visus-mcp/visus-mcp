# Visus MCP — Product Roadmap

## ✅ v0.1.0 — PUBLISHED (2026-03-21)
- 43 injection pattern categories
- PII redaction (email, phone, SSN, credit card, IP)
- undici fetch() renderer (static + server-rendered pages)
- visus_fetch + visus_fetch_structured tools
- 95/95 tests passing
- Published to npm
- Claude Desktop smoke tested (4/4 passing)

## ✅ v0.2.0 — PUBLISHED + DEPLOYED (2026-03-22)
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

## ✅ v0.3.0 — PUBLISHED (2026-03-22)
- Domain-scoped PII allowlist for health authority phone numbers
- Security hardening: scrubbed sensitive infrastructure details from STATUS.md
- Test suite expanded to 121/121 tests passing
- npm publish v0.3.0

---

## 🔒 v0.3.x — Managed Tier Security Hardening (IN PROGRESS)
Target: this week

- [ ] Enforce Cognito auth on managed endpoint (currently deployed, not enforced)
- [ ] Activate DynamoDB audit logging (table exists, no writes yet)
- [ ] Restrict CORS from * to claude.ai + localhost
- [ ] Add API Gateway usage plan: 1,000 req/day, 10 rps per API key
- [ ] Add TTL (90-day) to audit records
- [ ] Smoke test: unauthenticated request returns 401
- [ ] Update STATUS.md after deploy

---

## 📣 Phase 0 — Visibility & Distribution (2 weeks, zero-cost)
*Do these before any new features. Adoption stays at zero without them.*

### MCP Registry Submission (Day 1)
- [ ] Submit visus-mcp to https://github.com/modelcontextprotocol/servers
- [ ] Follow submission format exactly (name, description, install command, tools list)
- [ ] This is free permanent distribution — do not skip

### GitHub Polish
- [ ] CI/CD badge (GitHub Actions: build + test passing)
- [ ] Auto-release workflow on git tag push
- [ ] CONTRIBUTING.md — focus on allowlist PRs (how to submit trusted domains)
- [ ] Issue templates: Bug report, Feature request, Allowlist submission
- [ ] Update README test count and fix all known stale content

### Injection Arena — Public Demo Site
- [ ] GitHub Pages site (React, no backend required)
- [ ] User pastes a URL → sees raw content vs Visus-sanitized side-by-side
- [ ] Highlighted blocked patterns (color-coded by category)
- [ ] Redacted PII shown with [REDACTED:TYPE] markers
- [ ] 5 pre-loaded famous attack examples:
  - Hidden DAN prompt via CSS display:none
  - Base64-encoded jailbreak in meta tag
  - Role hijacking via invisible Unicode
  - System prompt extraction in page footer
  - Whitespace steganography in prose
- [ ] "Try in Claude Desktop" one-click config snippet
- [ ] Links to GitHub + npm

### Benchmark Report
- [ ] Test corpus: 50 real-world attack pages (mix of known CVEs + synthetic)
- [ ] Measure: Visus vs raw fetch vs Firecrawl — bypass rate, PII leakage, token count
- [ ] Publish as BENCHMARK.md in repo + LinkedIn post
- [ ] Target: 0% bypass rate for Visus on known patterns

### LinkedIn Launch Sequence (6 posts, 1 per week)
See LINKEDIN-STRATEGY.md for full post drafts.
- [ ] Post 1: OpenClaw CVE story — the credential leak nobody fixed
- [ ] Post 2: What prompt injection actually looks like (show the Injection Arena)
- [ ] Post 3: Why "engineered not vibe-coded" — the 43-pattern story
- [ ] Post 4: Healthcare angle — why PHI + AI agents is a compliance disaster waiting to happen
- [ ] Post 5: Benchmark results drop
- [ ] Post 6: Community call — allowlist PRs, contributors, roadmap

---

## v0.4.0 — Content Distillation + Managed Tier Activation
Target: 4–6 weeks

### Content Distillation (new feature)
Reduce token consumption by stripping irrelevant content before it reaches Claude.
Pipeline position: runs AFTER sanitization, never before.

- [ ] New module: src/sanitizer/content-distiller.ts
- [ ] Input: sanitized HTML/text + distill_level param (0–3)
- [ ] Level 0: off (default, current behavior)
- [ ] Level 1 (safe): remove nav/footer boilerplate, cookie banners, excessive whitespace
- [ ] Level 2 (moderate): also remove decorative emoji, social share blocks, ad artifacts
- [ ] Level 3 (aggressive): extract main content block only (Reader Mode equivalent)
- [ ] Expose as optional param in visus_fetch and visus_fetch_structured tool inputs
- [ ] Add bytes_distilled field to sanitization metadata output
- [ ] Test corpus: 20 pages across content types (news, docs, medical, ecommerce)
- [ ] Feature flag: default off, user opts in per-request
- [ ] Note: emoji that carry semantic meaning (ratings ⭐, warnings ⚠️) must be preserved

### Managed Tier Activation
- [ ] Stripe billing integration (free tier: 1,000 req/day; paid: unlimited)
- [ ] Usage dashboard (Next.js, reads from DynamoDB audit log)
- [ ] Blocked attacks heatmap, PII redaction count, token savings report
- [ ] API key management UI (issue, revoke, view usage)
- [ ] Provisioned concurrency on Lambda (eliminate 4s cold starts)
- [ ] WAF rules on API Gateway (bot protection, geo-blocking)
- [ ] CloudWatch metrics dashboard
- [ ] CORS restricted to authenticated origins only
- [ ] npm publish v0.4.0

### Community Allowlist Program
- [ ] Extend PII allowlist beyond health authorities to finance, legal, government
- [ ] GitHub PR template for allowlist submissions
- [ ] Manual review process documented in CONTRIBUTING.md
- [ ] Allowlist becomes community data moat (only Visus has verified trusted-domain DB)

---

## v0.5.0 — Cryptographic Audit Proofs
Target: 3 months

The enterprise differentiator. Proves in compliance audits that content was
sanitized before reaching the LLM.

- [ ] SHA-256 hash of original HTML included in every response
- [ ] SHA-256 hash of sanitized content included in every response
- [ ] Diff summary (patterns removed, bytes stripped, PII types redacted)
- [ ] Signed proof bundle: {original_hash, sanitized_hash, diff, visus_version, timestamp}
- [ ] Proof stored in DynamoDB audit log, retrievable by request_id
- [ ] New API endpoint: GET /proof/{request_id} → returns signed proof bundle
- [ ] Verification CLI: visus verify {request_id} → pass/fail
- [ ] Compliance report export (PDF) for SOC2/HIPAA audit packages
- [ ] Add proof_bundle field to sanitization metadata output

---

## Phase 3 — Chrome Extension Session Relay
Target: 4 months
*The killer feature. Unlocks LinkedIn, banking portals, EHR systems.*

- [ ] Chrome extension: captures rendered DOM from user's authenticated browser tab
- [ ] Content piped through local Visus sanitizer before reaching Claude
- [ ] Zero Lateos infrastructure in the authentication path (user's own session)
- [ ] Sanitizer runs locally regardless of which renderer is used (existing guarantee)
- [ ] Structured extraction schema for LinkedIn profiles, job postings
- [ ] Structured extraction schema for EHR patient portal views
- [ ] Demo: "Ask Claude to summarize this LinkedIn profile" with Visus
- [ ] Documentation: "Your credentials never leave your machine"
- [ ] Ship Chrome extension to Web Store under Lateos publisher account

---

## Phase 4 — ML Hybrid Detector (Managed Tier Only)
Target: 6 months
*Rule-based 43 patterns + embedding similarity for zero-day detection.*

- [ ] Train lightweight classifier on public injection datasets + synthetic attacks
- [ ] Bounty-driven attack corpus (community-submitted, manually verified)
- [ ] Deploy as sidecar to managed Lambda — NOT bundled in npm package
- [ ] Zero impact on open-source install size
- [ ] Managed tier users get ML detection automatically, no config change
- [ ] Report: ML detector catches X% of novel attacks that pattern matching misses
- [ ] Compounding moat: attack corpus grows with every bounty submission

---

## Phase 5 — Enterprise & Revenue
Target: 9 months

- [ ] SOC2 Type I audit (existing KMS + audit logs + proofs make this achievable)
- [ ] HIPAA BAA available for healthcare customers
- [ ] Custom policy engine: YAML rules per domain
- [ ] Multi-region deployment (add me-central-1 for MENA healthcare — existing plan)
- [ ] Dedicated Lambda instances for enterprise tier
- [ ] "Visus Shield" API for non-MCP agents (REST API, no MCP required)
- [ ] Lateos platform integration (full dashboard, team management)

---

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
| Content distiller runs after sanitizer | Prevents distiller from obscuring injection patterns |
| ML detector managed-tier only | Keeps npm package lightweight (<170MB Playwright already) |
| Cryptographic proofs stored 90 days | Matches audit log TTL, sufficient for compliance windows |
| Chrome extension local sanitizer path | Maintains PHI-never-touches-Lateos guarantee |

## Known Limitations

| Limitation | Resolution |
|---|---|
| Login-gated pages (LinkedIn, X) | Phase 3 user-session relay |
| Lambda cold start 4-5s | Provisioned concurrency (v0.3.0) |
| No rate limiting on managed endpoint | v0.3.0 |
| DynamoDB audit log not yet active | v0.3.0 activation |
| Cognito auth deployed but not enforced | v0.3.0 activation |
