# Visus Enterprise

**visus-mcp is MIT open source.** The core fetch, sanitization, injection detection, and PII redaction are fully functional and free forever. You never lose security by not paying.

## What the Enterprise Tier Adds

Visus Enterprise is a managed cloud service that wraps the MIT open-source tooling with operational features that matter for regulated deployments:

- **Aggregated Compliance Reports** — Quarterly PDF bundles with HMAC-signed attestations, ready for DPA and notified body submission
- **Immutable Audit Storage** — Long-term retention of proof hashes with configurable retention policies (GDPR Art. 12 / 30 compliant)
- **Enterprise Key Signing** — CA-anchored attestation signing (HSM-backed) for cryptographic proof verification
- **SIEM Forwarding** — Real-time threat detection events to Splunk, Sentinel, Datadog, or ELK
- **SLA-Backed Renderer** — Dedicated Playwright renderer instances with uptime guarantee
- **Priority Support** — Direct engineering support with SLA

## How It Works

```
Local MIT tool → generates proof hashes locally
              → optionally pushes proof hashes to api.lateos.ai
              → Enterprise cloud aggregates, signs, stores
              → user pulls auditor-ready PDFs
```

The `VISUS_ENTERPRISE_ENDPOINT` environment variable switches the tool into enterprise mode. Unset = everything runs locally, no data leaves your machine, no enterprise features. Set = selected metadata (proof hashes, threat counts, not raw content) is forwarded to the enterprise endpoint for aggregation.

**Raw page content never reaches Lateos infrastructure** in either mode. The sanitization pipeline always runs locally. Enterprise mode forwards only proof metadata (hashes, pattern names, timestamps) — no PII, no page text, no URLs beyond what you explicitly fetch.

## Pricing Model

| Tier | Price | Best For |
|---|---|---|
| Open Source | Free (MIT) | Individuals, small teams, non-production |
| Enterprise | Per-seat subscription | Regulated industries, production deployments |
| Managed Hosted | Usage-based pricing | Teams that want zero ops overhead |

Enterprise licensing is via annual subscription with per-seat pricing. Contact leo@lateos.ai for current pricing.

## Data Flow & Privacy

| | Open Source | Enterprise |
|---|---|---|
| Content fetched | Local only | Local only |
| Proof hashes | Local only | Forwarded to enterprise endpoint |
| Raw content | Never transmitted | Never transmitted |
| Threat patterns | Never transmitted | Anonymized counts only |
| Audit retention | Machine-local (ledger JSONL) | Cloud-stored (configurable retention) |

## Getting Started

```bash
# Open source (free, no setup):
npx visus-mcp

# Enterprise:
export VISUS_ENTERPRISE_ENDPOINT=https://api.lateos.ai
export VISUS_ENTERPRISE_LICENSE=your-license-key
npx visus-mcp
```

---

**visus-mcp is and remains MIT open source.** The enterprise tier is an optional cloud service, not a code gate. Every feature in the MIT repository is yours to use, modify, and redistribute.
