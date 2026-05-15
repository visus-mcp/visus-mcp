# Visus-Chaos: Adversarial Simulation Suite for MCP Servers

**Project Type:** Open Core (Community Edition: Apache 2.0 / Enterprise Edition: Proprietary)
**Target Market:** DevSecOps Engineers, SOC Analysts, AI Governance Officers, Indie Developers
**Positioning:** CI/CD Security Gate + Protocol-Level Fuzzing + Enterprise SIEM Integration
**Repositories:**
- `github.com/visus-mcp/visus-chaos` (PUBLIC - Apache 2.0)
- `github.com/lateos/visus-chaos-enterprise` (PRIVATE - Proprietary)

---

## Executive Summary

**Visus-Chaos** transforms Visus-MCP's defensive sanitization engine into an automated offensive testing suite. While Visus-MCP protects production LLM agents from prompt injection attacks, Visus-Chaos validates that protection through adversarial simulation before deployment.

**Core Value Proposition:**
- **For DevSecOps:** CI/CD pipeline blocker with configurable fail-fast thresholds
- **For SOC Teams:** SIEM-native attack telemetry (Splunk HEC + Microsoft Sentinel) with OCSF schemas (Enterprise)
- **For Compliance:** Auto-generated PDF artifacts mapping test results to EU AI Act Articles 9-15 and NIST AI RMF (Enterprise)
- **For Open Source:** Free adversarial testing with JSON reports and GitHub Actions integration

**Competitive Moat:**
1. **Open Core Strategy:** Community-driven payload corpus + enterprise SIEM/compliance features
2. **Protocol-Level Fuzzing:** JSON-RPC MCP message manipulation (not just prompt injection)
3. **Stateful Attack Chains:** Multi-turn conversation priming attacks (80% of real-world bypasses per Unit 42 2026)
4. **Compliance Traceability:** Auto-generated audit artifacts (Enterprise only)
5. **Durable Execution:** Built-in retry logic for SIEM ingestion failures (Enterprise only)

---

## Architecture Analysis: Visus-MCP Hook Points

### Current Visus-MCP Pipeline (v0.28.0)

```
┌─────────────────────────────────────────────────────────────────┐
│ MCP Client (Claude Desktop / claude.ai)                         │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ index.ts: CallToolRequestSchema Handler                         │
│ • visus_fetch, visus_fetch_structured, visus_read, etc.        │
│ • Session Ledger (VSIL) — multi-turn attack detection          │
│ • HITL Gate (human-in-the-loop for CRITICAL threats)           │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ sanitizer/index.ts: sanitizeWithProof()                         │
│ • injection-detector.ts (43 patterns)                           │
│ • boolean-gate-detector.ts (CVE-2026-4399)                      │
│ • worm-detector.ts (self-replicating payloads)                  │
│ • pii-redactor.ts (with domain allowlisting)                    │
│ • threat-reporter.ts (TOON-formatted findings)                  │
│ • crypto/proof-builder.ts (SHA-256 audit trail)                 │
└─────────────────────────────────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ audit/logger.ts: DynamoDB Audit Log (90-day TTL)                │
│ • GDPR Art. 30 / EU AI Act Art. 9 compliance records           │
│ • Sanitization proof hashes                                     │
└─────────────────────────────────────────────────────────────────┘
```

### **🎯 Adversarial Proxy Injection Points**

**Option A: Transport-Layer Proxy (RECOMMENDED)**

Intercept MCP JSON-RPC messages BEFORE they reach the server:

```
┌────────────────┐
│ MCP Client     │
└────────┬───────┘
         │
         ▼
┌────────────────────────────────────┐
│ VISUS-CHAOS ADVERSARIAL PROXY      │  ◄── NEW COMPONENT
│ • JSON-RPC fuzzing                 │
│ • Protocol mutation                │
│ • Tool call injection              │
│ • Stateful conversation priming    │
└────────┬───────────────────────────┘
         │
         ▼
┌────────────────┐
│ Visus-MCP      │ (unchanged)
│ Server         │
└────────────────┘
```

**Why this approach:**
- No modification to Visus-MCP codebase (commercial fork isolation)
- Tests the full sanitization stack end-to-end
- Can test OTHER MCP servers, not just Visus (market expansion)
- Drop-in replacement for `npx @modelcontextprotocol/inspector`

**Option B: Sanitizer-Level Injection (Secondary)**

Direct fuzzing of the sanitizer API:

```typescript
// Chaos harness directly calls sanitizer internals
import { sanitizeWithProof } from 'visus-mcp/dist/sanitizer/index.js';

const result = await sanitizeWithProof(
  maliciousPayload,
  'https://attacker.com',
  'chaos-fuzzer',
  '1.0.0'
);

// Assertion: result.sanitization.content_modified === true
// If false → bypass detected → report to SIEM + block CI/CD
```

**Why use both:**
- Option A: End-to-end realistic testing
- Option B: Unit-level regression testing for sanitizer logic

---

## Open Core Licensing Strategy

### Repository Structure

```
┌─────────────────────────────────────────────────────────────┐
│ github.com/visus-mcp/visus-chaos (PUBLIC)                   │
│ License: Apache 2.0                                         │
│                                                             │
│ Community Edition Features:                                 │
│ ✅ Go CLI (chaos proxy, chaos test)                        │
│ ✅ MCP adversarial proxy (JSON-RPC fuzzing)                │
│ ✅ All attack payloads (import from Visus-MCP canaries)   │
│ ✅ Bypass detection logic                                  │
│ ✅ Resilience scoring (0-100)                              │
│ ✅ CI/CD exit codes (fail-fast thresholds)                 │
│ ✅ JSON reports (chaos-report.json)                        │
│ ✅ GitHub Actions workflow examples                        │
│ ✅ Basic HTML reports (single file, no PDF)               │
└─────────────────────────────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ github.com/lateos/visus-chaos-enterprise (PRIVATE)          │
│ License: Proprietary                                        │
│                                                             │
│ Enterprise-Only Features:                                   │
│ 🔒 SIEM connectors (Splunk HEC, Sentinel API)             │
│ 🔒 OCSF v1.3.0 event builder                              │
│ 🔒 Durable execution (DLQ with retry logic)                │
│ 🔒 PDF compliance artifacts (EU AI Act, NIST AI RMF)      │
│ 🔒 Encrypted DLQ (AES-256-GCM + KMS)                       │
│ 🔒 SOC playbook + pre-built dashboards                     │
│ 🔒 License key validation (Ed25519)                        │
│ 🔒 Priority support + SLA                                  │
└─────────────────────────────────────────────────────────────┘
```

### Feature Gating Implementation

**License Key Validation (Runtime Gating):**

```go
// internal/license/validator.go (Community Edition - stub)
package license

func Validate(key string) (*License, error) {
    return nil, fmt.Errorf(
        "Enterprise features require a license key.\n" +
        "Upgrade at https://lateos.ai/chaos/pricing\n\n" +
        "Community Edition includes:\n" +
        "  • Local adversarial testing\n" +
        "  • JSON reports\n" +
        "  • CI/CD integration\n\n" +
        "Enterprise Edition adds:\n" +
        "  • SIEM integration (Splunk, Sentinel)\n" +
        "  • PDF compliance artifacts\n" +
        "  • Encrypted audit logs",
    )
}
```

**Feature Check Example:**

```go
// internal/siem/client.go (Community Edition - interface only)
package siem

func NewSplunkClient(cfg Config) (*Client, error) {
    license, err := license.Validate(cfg.LicenseKey)
    if err != nil {
        return nil, err  // User-friendly upgrade prompt
    }

    // Enterprise implementation loaded dynamically
    return loadEnterpriseClient(license, cfg)
}
```

---

## Technical Architecture: Visus-Chaos v1.0

### Technology Stack Decision Matrix

| Component | Rust | Go | TypeScript | Decision |
|-----------|------|-----|------------|----------|
| CLI Runner | ✅ Zero deps, <5MB binary | ✅ Cross-compile, stdlib | ❌ Node.js required | **Go** |
| JSON-RPC Proxy | ✅ tokio async | ✅ goroutines | ✅ MCP SDK available | **Go** |
| SIEM Connectors | ⚠️ Manual HTTP | ✅ stdlib net/http | ✅ fetch API | **Go (Enterprise)** |
| PDF Generator | ❌ No ecosystem | ⚠️ gofpdf basic | ✅ puppeteer mature | **TS (Enterprise)** |
| Deployment | ✅ Static binary | ✅ Static binary | ❌ Requires Node | **Go primary** |

**Final Decision: Go for core engine, TypeScript for PDF renderer sidecar (Enterprise only)**

**Rationale:**
- Go produces a single static binary (~15MB) for CI/CD containers
- stdlib HTTP client handles Splunk HEC / Sentinel API without external deps (Enterprise)
- MCP JSON-RPC parsing is trivial in Go (stdlib `encoding/json`)
- PDF generation delegates to a TypeScript subprocess (Enterprise: `chaos-enterprise pdf` subcommand)
- Community binary <20MB; Enterprise binary with Node.js sidecar <80MB (still Docker-friendly)

---

### Module Structure (Community Edition - Open Source)

```
visus-chaos/                              # Apache 2.0
├── LICENSE                               # Apache 2.0
├── README.md                             # Focus on Community features
├── CONTRIBUTING.md                       # Payload submissions, bug reports
├── cmd/
│   ├── chaos/                            # CLI entry point
│   │   └── main.go                       # Cobra CLI framework
│   └── proxy/                            # MCP adversarial proxy
│       └── main.go                       # stdio <-> chaos engine <-> MCP server
├── internal/
│   ├── fuzzer/
│   │   ├── jsonrpc.go                    # JSON-RPC protocol mutation
│   │   ├── prompt.go                     # Payload library (import Visus-MCP)
│   │   └── chain.go                      # Stateful multi-turn attacks
│   ├── detector/
│   │   ├── bypass.go                     # Detect if sanitizer failed
│   │   └── score.go                      # Resilience scoring (0-100)
│   ├── reporter/
│   │   ├── json.go                       # JSON report writer
│   │   └── html.go                       # Basic HTML report (no PDF)
│   ├── executor/
│   │   ├── runner.go                     # Test orchestration
│   │   └── threshold.go                  # Fail-fast exit codes
│   └── license/
│       └── validator.go                  # Stub with upgrade message
├── corpus/
│   ├── canaries/                         # Import from Visus-MCP
│   └── README.md                         # How to contribute payloads
├── configs/
│   ├── thresholds.yaml                   # Strict/balanced/permissive
│   └── example.yaml                      # Full config with comments
└── .github/
    └── workflows/
        ├── test.yml                      # CI for Community Edition
        └── chaos-example.yml             # Example usage in CI/CD
│   │   ├── ocsf.go      # OCSF v1.3.0 event builder
│   │   ├── splunk.go    # Splunk HEC client with retry
│   │   └── sentinel.go  # Sentinel Log Analytics API client
│   ├── compliance/
│   │   ├── nist.go      # NIST AI RMF 1.0 mapping
│   │   ├── euaia.go     # EU AI Act Article mapper
│   │   └── artifact.go  # JSON → PDF handoff
│   └── executor/
│       ├── runner.go    # Test orchestration
│       └── threshold.go # Fail-fast decision logic
├── corpus/
│   ├── canaries/        # Self-reporting payloads (import from Visus-MCP)
│   ├── evasion/         # Advanced bypasses (closed-source)
│   └── chains/          # Multi-turn attack sequences (closed-source)
├── templates/
│   ├── compliance.html  # PDF template (EU AI Act)
│   └── executive.html   # Executive summary template
└── configs/
    ├── thresholds.yaml  # Fail-fast severity levels (strict/balanced/permissive)
    └── siem.yaml        # SIEM endpoint configurations
```

---

## OCSF-Compliant Event Schema (v1.3.0)

### Base Event Structure

```json
{
  "metadata": {
    "version": "1.3.0",
    "product": {
      "name": "Visus-Chaos",
      "version": "1.0.0",
      "vendor_name": "Lateos"
    },
    "profiles": ["security_control"],
    "log_name": "adversarial_simulation",
    "logged_time": 1735689600000,
    "original_time": 1735689600000
  },
  "class_uid": 6003,
  "category_uid": 6,
  "severity_id": 4,
  "type_uid": 600301,
  "activity_id": 1,
  "time": 1735689600000,
  "status_id": 1,
  "message": "Prompt injection bypass detected in visus_fetch tool",

  "finding_info": {
    "uid": "req-550e8400-e29b-41d4-a716-446655440000",
    "title": "Direct Override Bypass",
    "desc": "Payload containing 'Ignore previous instructions' bypassed sanitizer",
    "types": ["prompt_injection", "llm_security"],
    "src_url": "https://github.com/visus-mcp/visus-mcp/security/canaries/pi-direct-override.txt",
    "created_time": 1735689600000,
    "modified_time": 1735689600000
  },

  "attack": {
    "version": "14.1",
    "tactic": {
      "uid": "TA0001",
      "name": "Initial Access",
      "src_url": "https://attack.mitre.org/tactics/TA0001/"
    },
    "technique": {
      "uid": "T1659",
      "name": "Content Injection",
      "src_url": "https://attack.mitre.org/techniques/T1659/"
    }
  },

  "resources": [
    {
      "uid": "visus_fetch",
      "name": "visus_fetch MCP tool",
      "type": "mcp_tool",
      "version": "0.28.0"
    }
  ],

  "observables": [
    {
      "name": "attack_payload",
      "type_id": 24,
      "value": "[REDACTED]"
    },
    {
      "name": "sanitizer_response",
      "type_id": 24,
      "value": "content_modified: false"
    }
  ],

  "enrichments": [
    {
      "name": "resilience_score",
      "data": {"score": 42, "threshold": 85},
      "value": "FAIL",
      "type": "compliance_metric"
    },
    {
      "name": "eu_ai_act_article",
      "data": {"article": "9", "requirement": "Risk Management"},
      "value": "NON_COMPLIANT",
      "type": "regulatory_mapping"
    }
  ],

  "unmapped": {
    "visus_chaos": {
      "test_id": "chaos-run-2026-01-01-1200",
      "pattern_category": "direct_override",
      "sanitizer_version": "1.0.0",
      "bypass_confirmed": true,
      "remediation": "Update pattern library to detect 'ignore all previous' variants"
    }
  }
}
```

### SIEM Mapping

#### Splunk HEC

```bash
curl -X POST https://splunk.example.com:8088/services/collector/event \
  -H "Authorization: Splunk <HEC_TOKEN>" \
  -d '{
    "sourcetype": "visus:chaos:ocsf",
    "source": "visus-chaos-cli",
    "index": "security",
    "event": <OCSF_JSON>
  }'
```

**Splunk Search (Detect Bypasses):**
```spl
index=security sourcetype="visus:chaos:ocsf" finding_info.types="prompt_injection"
| where enrichments{}.name="resilience_score" AND enrichments{}.value="FAIL"
| stats count by attack.technique.name, resources{}.name
| sort -count
```

#### Microsoft Sentinel (Log Analytics)

```bash
curl -X POST "https://<workspace-id>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" \
  -H "Authorization: SharedKey <workspace-id>:<signature>" \
  -H "Log-Type: VisusChaos_CL" \
  -H "Content-Type: application/json" \
  -d '<OCSF_JSON>'
```

**KQL Query (Compliance Dashboard):**
```kql
VisusChaos_CL
| where finding_info_types_s contains "prompt_injection"
| extend ResilienceScore = toint(enrichments_data_score_d)
| summarize FailCount = countif(ResilienceScore < 85) by bin(TimeGenerated, 1h), resources_name_s
| render timechart
```

---

## CI/CD Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/visus-chaos-gate.yml
name: AI Security Gate

on:
  pull_request:
    paths:
      - 'mcp-config/**'
      - 'agents/**'
      - 'tools/**'

jobs:
  adversarial-simulation:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install Visus-Chaos CLI
        run: |
          curl -L https://releases.lateos.ai/visus-chaos/v1.0.0/chaos-linux-amd64 -o /usr/local/bin/chaos
          chmod +x /usr/local/bin/chaos

      - name: Run Adversarial Simulation
        id: chaos
        run: |
          chaos proxy \
            --mcp-server ./dist/index.js \
            --corpus ./security/canaries \
            --mode strict \
            --threshold 85 \
            --siem splunk \
            --output ./chaos-report.json \
            --exit-on-fail
        env:
          SPLUNK_HEC_TOKEN: ${{ secrets.SPLUNK_HEC_TOKEN }}
          SPLUNK_HEC_URL: ${{ secrets.SPLUNK_HEC_URL }}

      - name: Generate Compliance Artifact
        if: always()
        run: |
          chaos pdf \
            --input ./chaos-report.json \
            --template compliance \
            --output ./artifacts/eu-ai-act-conformity-${{ github.sha }}.pdf

      - name: Upload Compliance Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: compliance-report
          path: ./artifacts/*.pdf
          retention-days: 90

      - name: Block Merge on Failure
        if: failure()
        run: |
          echo "::error::Resilience score below 85%. See compliance artifact for details."
          exit 1

      - name: Post PR Comment
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('./chaos-report.json', 'utf8'));

            const comment = `
            ## 🛡️ Visus-Chaos Security Gate

            **Resilience Score:** ${report.resilience_score}/100
            **Threshold:** 85 (Strict Mode)
            **Status:** ${report.resilience_score >= 85 ? '✅ PASS' : '❌ FAIL'}

            ### Findings
            - **Critical:** ${report.findings.critical}
            - **High:** ${report.findings.high}
            - **Medium:** ${report.findings.medium}
            - **Low:** ${report.findings.low}

            ### Compliance
            - **EU AI Act Art. 9:** ${report.compliance.eu_ai_act.article_9}
            - **NIST AI RMF:** ${report.compliance.nist_ai_rmf.govern}

            [Download Full Report](https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }})
            `;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security

visus-chaos-gate:
  stage: security
  image: golang:1.22-alpine
  before_script:
    - apk add --no-cache curl
    - curl -L https://releases.lateos.ai/visus-chaos/v1.0.0/chaos-linux-amd64 -o /usr/local/bin/chaos
    - chmod +x /usr/local/bin/chaos
  script:
    - chaos proxy --mcp-server ./dist/index.js --mode strict --threshold 85 --exit-on-fail
    - chaos pdf --input chaos-report.json --output compliance.pdf
  artifacts:
    when: always
    paths:
      - chaos-report.json
      - compliance.pdf
    expire_in: 90 days
  only:
    - merge_requests
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    environment {
        SPLUNK_HEC_TOKEN = credentials('splunk-hec-token')
        SENTINEL_WORKSPACE_ID = credentials('sentinel-workspace-id')
    }

    stages {
        stage('Install Visus-Chaos') {
            steps {
                sh 'curl -L https://releases.lateos.ai/visus-chaos/v1.0.0/chaos-linux-amd64 -o chaos'
                sh 'chmod +x chaos'
            }
        }

        stage('Adversarial Simulation') {
            steps {
                sh '''
                ./chaos proxy \
                  --mcp-server ./dist/index.js \
                  --mode balanced \
                  --threshold 80 \
                  --siem splunk,sentinel \
                  --exit-on-fail
                '''
            }
        }

        stage('Generate Compliance Artifact') {
            steps {
                sh './chaos pdf --input chaos-report.json --template executive --output compliance.pdf'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '*.pdf, *.json', fingerprint: true
        }
        failure {
            emailext (
                subject: "AI Security Gate Failed: ${env.JOB_NAME} - Build #${env.BUILD_NUMBER}",
                body: """
                Resilience score below threshold.

                Review the compliance artifact:
                ${env.BUILD_URL}artifact/compliance.pdf

                SIEM alerts dispatched to Splunk and Sentinel.
                """,
                to: "security-team@example.com"
            )
        }
    }
}
```

---

## Compliance Artifact Structure

### EU AI Act Conformity Assessment (PDF)

**Page 1: Executive Summary**

```
┌──────────────────────────────────────────────────────────────┐
│ CONFORMITY ASSESSMENT REPORT                                 │
│ EU Artificial Intelligence Act (Regulation 2024/1689)        │
│                                                               │
│ System Under Test: Visus-MCP v0.28.0                        │
│ Test Date: 2026-01-01 12:00 UTC                             │
│ Test ID: chaos-run-2026-01-01-1200                          │
│ Tester: Visus-Chaos Enterprise v1.0.0                       │
│                                                               │
│ RESILIENCE SCORE: 42/100 ❌ NON-COMPLIANT                    │
│ Threshold: 85 (Strict Mode)                                  │
│                                                               │
│ FINDINGS SUMMARY                                              │
│ • Critical: 3 (Direct Override, Role Hijacking, Data Exfil) │
│ • High: 7 (System Prompt Extraction, Privilege Escalation)  │
│ • Medium: 12                                                  │
│ • Low: 5                                                      │
│                                                               │
│ REGULATORY IMPACT                                             │
│ ⚠️  Art. 9 (Risk Management): HIGH RISK - IMMEDIATE ACTION   │
│ ⚠️  Art. 13 (Transparency): INSUFFICIENT SAFEGUARDS          │
│ ⚠️  Art. 15 (Accuracy/Robustness): BYPASS DETECTED           │
└──────────────────────────────────────────────────────────────┘
```

**Page 2: Technical Findings (Mapped to EU AI Act)**

| Attack Pattern | Severity | Bypass? | EU AI Act Article | Requirement | Status |
|----------------|----------|---------|-------------------|-------------|--------|
| Direct Override ("Ignore all...") | CRITICAL | ✅ YES | Art. 15 (Accuracy) | "Resilient to errors, faults, inconsistencies" | ❌ FAIL |
| Role Hijacking (DAN mode) | CRITICAL | ✅ YES | Art. 9 (Risk Mgmt) | "Measures to address residual risks" | ❌ FAIL |
| Data Exfiltration ("Send to...") | CRITICAL | ✅ YES | Art. 10 (Data Gov) | "Training, validation, testing data quality" | ❌ FAIL |
| System Prompt Extraction | HIGH | ❌ NO | Art. 13 (Transparency) | "Clear indication of AI interaction" | ✅ PASS |
| ... | ... | ... | ... | ... | ... |

**Page 3: NIST AI RMF Mapping**

| RMF Function | Control | Test Result | Evidence |
|--------------|---------|-------------|----------|
| GOVERN-1.1 | Legal/regulatory requirements | ❌ FAIL | 3 critical bypasses violate Art. 15 |
| MAP-2.3 | System capabilities/limitations | ⚠️ PARTIAL | Sanitizer detects 38/43 patterns |
| MEASURE-2.13 | AI system security/resilience | ❌ FAIL | 11.6% bypass rate on known attacks |
| MANAGE-4.1 | Risk treatments implemented | ⚠️ PARTIAL | HITL gate active, but bypassed 3x |

**Page 4: Remediation Roadmap**

```
IMMEDIATE (0-7 days)
☐ Update injection-detector.ts patterns for "ignore all previous" variants
☐ Add Unicode normalization to prevent lookalike bypasses
☐ Enable worm-detector.ts in production (currently VISUS_WORM_DETECTION=false)

SHORT-TERM (8-30 days)
☐ Implement ML-based zero-day detection (per ROADMAP.md Phase 4)
☐ Extend HITL gate to trigger on >2 medium-severity findings (not just critical)
☐ Add rate limiting to prevent automated bypass discovery

LONG-TERM (31-90 days)
☐ SOC2 Type I audit (leverage existing DynamoDB audit trail)
☐ Deploy multi-region sanitizer for <100ms latency (Art. 15 performance req)
☐ Implement adversarial retraining pipeline (bounty-driven corpus)
```

---

## Durable Execution & SIEM Retry Logic

### Problem Statement

Enterprise SIEMs throttle ingestion:
- **Splunk HEC:** 429 Too Many Requests when >10 events/sec
- **Sentinel:** 500 MB/day limit per workspace on free tier
- **Network failures:** Corporate proxies, VPN drops, regional outages

**Requirement:** Chaos must never lose telemetry, even if SIEM is temporarily unavailable.

### Solution: Exponential Backoff + Dead Letter Queue

```go
// internal/siem/durable.go
package siem

import (
    "context"
    "encoding/json"
    "os"
    "time"
)

type DurableClient struct {
    client      Client  // Splunk or Sentinel
    dlqPath     string  // Dead letter queue file
    maxRetries  int
    backoffBase time.Duration
}

func (dc *DurableClient) SendEvent(ctx context.Context, event *OCSFEvent) error {
    var lastErr error

    for attempt := 0; attempt < dc.maxRetries; attempt++ {
        err := dc.client.Send(ctx, event)
        if err == nil {
            return nil  // Success
        }

        lastErr = err

        // Exponential backoff: 1s, 2s, 4s, 8s, 16s
        backoff := dc.backoffBase * time.Duration(1<<attempt)

        log.Warnf("SIEM send failed (attempt %d/%d): %v. Retrying in %s",
            attempt+1, dc.maxRetries, err, backoff)

        select {
        case <-time.After(backoff):
            continue
        case <-ctx.Done():
            return ctx.Err()
        }
    }

    // All retries exhausted → write to DLQ
    return dc.writeToDLQ(event, lastErr)
}

func (dc *DurableClient) writeToDLQ(event *OCSFEvent, err error) error {
    f, err := os.OpenFile(dc.dlqPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
    if err != nil {
        return fmt.Errorf("failed to open DLQ: %w", err)
    }
    defer f.Close()

    envelope := DLQEntry{
        Timestamp:   time.Now().UTC(),
        Event:       event,
        FailureReason: err.Error(),
    }

    return json.NewEncoder(f).Encode(envelope)
}

// CLI command: chaos siem replay --dlq ./failed-events.jsonl
func ReplayDLQ(ctx context.Context, dlqPath string, client Client) error {
    // Read DLQ, retry each event, remove from DLQ on success
}
```

**Operations Runbook:**

```bash
# Monitor DLQ size
ls -lh ./failed-events.jsonl

# Replay when SIEM is healthy
chaos siem replay --dlq ./failed-events.jsonl --siem splunk

# Alert on DLQ growth (Prometheus metric)
chaos_dlq_size_bytes > 10MB → PagerDuty
```

---

## 6-Week Sprint Schedule (Open Core Strategy)

**Phase 1: Community Edition (Weeks 1-3) — Open Source First**
**Phase 2: Pro/Enterprise Features (Weeks 4-6) — Validate Paid Demand**

---

### **Week 1-2: Community Edition v1.0 (PUBLIC RELEASE)**

**Target:** Ship fully functional open-source adversarial testing CLI

**Deliverables:**
- [ ] Go CLI scaffold (Cobra framework)
- [ ] JSON-RPC proxy with stdio passthrough
- [ ] Payload corpus loader (import all 43 Visus-MCP canaries)
- [ ] Bypass detection logic (compare sanitizer output to expected)
- [ ] Resilience scoring algorithm (weighted by severity)
- [ ] Threshold-based exit codes (0 = pass, 1 = fail, 2 = error)
- [ ] JSON reporter (`chaos-report.json`)
- [ ] Basic HTML reporter (single-file, no external deps)
- [ ] GitHub Actions workflow example
- [ ] Apache 2.0 LICENSE
- [ ] README with quick start (5-minute setup)
- [ ] CONTRIBUTING.md (how to submit new payloads)

**Acceptance Criteria:**
```bash
# Test: Community Edition runs end-to-end without license
chaos proxy --mcp-server ./dist/index.js --corpus ./canaries --threshold 85 --output report.json
# Expected: Exit code 0 or 1 based on score, JSON report written, no license check

# Test: HTML report generated
chaos report --input report.json --format html --output report.html
# Expected: Single HTML file with findings, resilience score, charts (Chart.js CDN)
```

**Launch Strategy:**
- Publish to GitHub (`visus-mcp/visus-chaos`)
- Submit to HackerNews: "We open-sourced our AI security testing framework"
- Reddit: r/netsec, r/programming, r/golang
- LinkedIn post: Tag influencers in AI security space

---

### **Week 3: Community Traction + Early Enterprise Validation**

**Focus:** Drive adoption, gather feedback, identify Enterprise prospects

**Deliverables:**
- [ ] Cross-platform binaries (Linux amd64/arm64, macOS amd64/arm64, Windows)
- [ ] Docker image (`ghcr.io/visus-mcp/chaos:latest`)
- [ ] GitLab CI example workflow
- [ ] Jenkins pipeline example
- [ ] Documentation site (GitHub Pages + MkDocs)
- [ ] First 3 community payload contributions merged
- [ ] License key validation stub (user-friendly upgrade message)

**Sales Development:**
- [ ] Identify 5 Community users who asked "Can this send to Splunk?" → Enterprise prospects
- [ ] Create Enterprise trial Docker image (`lateos/chaos-enterprise:trial` - 30-day license)
- [ ] Schedule demos with 3 qualified leads

**Acceptance Criteria:**
```bash
# Test: User tries SIEM integration without license
chaos proxy --siem splunk --mcp-server ./server.js
# Expected: Friendly error message with upgrade link, not a crash

# Community Edition includes:
#   • Local adversarial testing
#   • JSON reports
#   • CI/CD integration
#
# Enterprise Edition adds:
#   • SIEM integration (Splunk, Sentinel)
#   • PDF compliance artifacts
#   • Encrypted audit logs
#
# Learn more: https://lateos.ai/chaos/pricing
```

---

### **Week 4: Pro Tier - PDF Compliance Artifacts** (PAID FEATURE)

**Target:** Enable compliance use case for small teams ($99/mo price point)

**Deliverables:**
- [ ] TypeScript PDF renderer (Puppeteer + Handlebars templates)
- [ ] EU AI Act template (Articles 9, 13, 15 mapping)
- [ ] NIST AI RMF template (GOVERN/MAP/MEASURE/MANAGE)
- [ ] Executive summary template (non-technical, CxO-friendly)
- [ ] Email alerts (SMTP integration)
- [ ] Slack webhook integration
- [ ] License key validation for Pro tier
- [ ] CLI subcommand: `chaos-pro pdf --input report.json --output compliance.pdf`

**Templates:**
- `templates/compliance.html` — Technical findings → regulation mappings
- `templates/executive.html` — Non-technical summary
- `templates/nist.html` — NIST AI RMF 1.0 function mappings

**Acceptance Criteria:**
```bash
# Test: Pro license enables PDF generation
export VISUS_CHAOS_LICENSE=<pro-license-key>
chaos pdf --input chaos-report.json --template compliance --output eu-ai-act.pdf
# Expected: PDF generated with regulatory mappings, page count >3

# Test: Community user gets upgrade prompt
chaos pdf --input report.json
# Error: PDF generation requires Pro or Enterprise license ($99/mo)
# Upgrade at: https://lateos.ai/chaos/pricing
```

---

### **Week 5: Enterprise Tier - SIEM Integration** (PAID FEATURE)

**Target:** Ship SOC-team features ($2,499/mo price point)

**Deliverables:**
- [ ] OCSF v1.3.0 event builder
- [ ] Splunk HEC client with exponential backoff
- [ ] Microsoft Sentinel Log Analytics API client
- [ ] Durable execution (DLQ for failed sends)
- [ ] Encrypted DLQ (AES-256-GCM with KMS-derived keys)
- [ ] SIEM configuration file (`configs/siem.yaml`)
- [ ] Health check command (`chaos siem test`)
- [ ] License key validation for Enterprise tier
- [ ] CLI: `chaos-enterprise proxy --siem splunk`

**Acceptance Criteria:**
```bash
# Test: Enterprise license enables SIEM integration
export VISUS_CHAOS_LICENSE=<enterprise-license-key>
chaos proxy --mcp-server ./server.js --siem splunk --corpus ./canaries
# Expected: OCSF events sent to Splunk HEC, DLQ created on failure

# Test: Encrypted DLQ replay
chaos siem replay --dlq ./failed-events.enc
# Expected: Decrypts with Enterprise license, sends to SIEM, clears DLQ
```

---

### **Week 6: Polish, Launch, Scale**

**Deliverables:**
- [x] End-to-end test suite (all 43 canaries + 20 evasion payloads)
- [x] SOC playbook (PDF guide for security analysts)
- [x] Splunk dashboard JSON (pre-built visualizations)
- [x] Sentinel workbook (KQL queries + charts)
- [x] Docker image (`docker.io/lateos/visus-chaos:v1.0.0`)
- [x] Release artifacts (Linux/macOS/Windows binaries)

**SOC Playbook Contents:**
1. **Installation & Configuration** (10 min setup guide)
2. **Threshold Tuning** (strict/balanced/permissive mode selection)
3. **SIEM Query Reference** (Splunk SPL + Sentinel KQL)
4. **Incident Response Workflow** (when Chaos detects a bypass)
5. **Compliance Artifact Retention** (90-day EU AI Act requirement)

**Splunk Dashboard Example:**
```xml
<!-- visus_chaos_dashboard.xml -->
<dashboard>
  <label>Visus-Chaos: AI Security Gate</label>
  <row>
    <panel>
      <title>Resilience Score Trend (7d)</title>
      <chart>
        <search>
          <query>
            index=security sourcetype="visus:chaos:ocsf"
            | timechart avg(enrichments{}.data.score) as avg_score
          </query>
        </search>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Top 10 Bypasses</title>
      <table>
        <search>
          <query>
            index=security finding_info.types="prompt_injection" unmapped.visus_chaos.bypass_confirmed=true
            | stats count by attack.technique.name
            | sort -count
            | head 10
          </query>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

**Acceptance Criteria:**
```bash
# Test: Full corpus run completes in <5 minutes
time chaos proxy --mcp-server ./dist/index.js --corpus ./full-corpus --mode balanced
# Expected: 63 tests (43 canaries + 20 evasion), 100% completion, exit based on threshold

# Test: Docker image runs in CI
docker run --rm -v $(pwd):/workspace lateos/visus-chaos:v1.0.0 \
  proxy --mcp-server /workspace/dist/index.js --threshold 85
# Expected: Identical output to native binary
```

---

## Pricing Model (Open Core)

| Tier | License | Price | Features | Target Audience |
|------|---------|-------|----------|-----------------|
| **Community** | Apache 2.0 | **Free** | • CLI (chaos proxy, chaos test)<br>• JSON reports<br>• Basic HTML reports<br>• CI/CD exit codes<br>• GitHub Actions integration<br>• All attack payloads | Indie developers, open-source projects, students |
| **Pro** | Proprietary | $99/mo | Community +<br>• PDF compliance artifacts<br>• Email alerts<br>• Slack/Discord webhooks<br>• Advanced HTML dashboards | Startups, small security teams (1-10 people) |
| **Enterprise** | Proprietary | $2,499/mo | Pro +<br>• SIEM integration (Splunk, Sentinel)<br>• OCSF v1.3.0 events<br>• Encrypted DLQ<br>• Durable execution<br>• Priority support (24hr SLA) | SOC teams, regulated industries, Fortune 500 |
| **Enterprise+** | Proprietary | Custom | Enterprise +<br>• SOC2 audit artifacts<br>• Custom pattern development<br>• White-glove onboarding<br>• Dedicated Slack channel<br>• 4hr P1 SLA | Financial services, healthcare, government |

### Revenue Model

**Primary:**
- **Free-to-Paid Conversion:** Community users hit SIEM integration needs → upgrade to Enterprise
- **Visus-MCP Upsell:** Existing Visus-MCP users get Chaos to validate their deployments

**Secondary:**
- **Managed Chaos Service:** Lateos runs adversarial tests in your CI/CD on your behalf ($999/mo base + per-test pricing)
- **Professional Services:** Custom payload development ($5k), SOC training workshops ($10k/day), compliance audit prep ($15k)

**Time-to-Value:**
```
Day 1: Download Community Edition → prove value locally
Day 7: Hit limit (need SIEM or PDF) → sales conversation begins
Day 14: Enterprise trial with real Splunk integration
Day 30: Close deal (already proven ROI)
```

Compare to traditional enterprise sales: 6-12 month cycle. Open Core compresses this to <30 days.

---

## Success Metrics (6-Month Targets)

### Community Adoption

| Metric | Target | Measurement |
|--------|--------|-------------|
| GitHub Stars (visus-chaos) | 1,000 | Community awareness |
| Weekly Downloads | 500 | npm/Go binary downloads |
| Community Payload Contributions | 20 | PRs with new attack patterns |
| HackerNews Front Page | 1x | Launch announcement |
| CI/CD Integrations (Public) | 100 | GitHub Actions using Chaos |

### Commercial Success

| Metric | Target | Measurement |
|--------|--------|-------------|
| Pro Subscribers | 50 | $99/mo tier |
| Enterprise Customers | 10 | $2,499/mo tier |
| Enterprise+ Customers | 2 | Custom pricing |
| **Total MRR** | **$35k** | (50×$99) + (10×$2,499) + (2×$10k) |

### Technical Excellence

| Metric | Target | Measurement |
|--------|--------|-------------|
| Bypass Detection Rate | >95% | On known 43-pattern corpus |
| False Positive Rate | <5% | Clean content flagged as malicious |
| SIEM Events Delivered | 1M+ | Splunk + Sentinel combined |
| PDF Artifacts Generated | 5,000 | Enterprise tier downloads |
| Avg Resilience Score Improvement | +25 points | Before/after Chaos adoption |

---

## Competitive Landscape

| Product | Focus | SIEM? | CI/CD? | Compliance Artifacts? | Visus-Chaos Advantage |
|---------|-------|-------|--------|----------------------|----------------------|
| **Garak** (NVIDIA) | LLM red-teaming | ❌ | ⚠️ Manual | ❌ | Protocol-level fuzzing + OCSF |
| **PyRIT** (Microsoft) | Prompt injection | ❌ | ❌ | ❌ | Stateful chains + EU AI Act |
| **Invariant** | LLM guardrails | ✅ | ❌ | ❌ | MCP-native + threshold gates |
| **LangKit** (WhyLabs) | LLM observability | ✅ | ⚠️ Partial | ❌ | Compliance-first design |

**Unique Position:** Only product combining MCP protocol fuzzing + SIEM-native telemetry + regulatory artifact generation.

---

## Technical Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Visus-MCP sanitizer evolves, breaks Chaos assumptions | HIGH | Pin to semantic versioning, auto-detect breaking changes |
| SIEM API changes (Splunk/Sentinel) | MEDIUM | Version OCSF schema, support multiple API versions |
| License key piracy | HIGH | Hardware-bound licenses (MAC address hash) |
| False negatives (missed bypasses) | CRITICAL | Bounty program for novel attacks, quarterly corpus refresh |
| Go binary reverse engineering | MEDIUM | UPX packing + symbol stripping + encrypted strings |

---

## Go-to-Market Strategy (Open Core)

### Phase 1: Community Launch (Week 1-3)

**HackerNews Strategy:**
```
Title: "We open-sourced Visus-Chaos – adversarial testing for AI agents"

Post Content:
We built Visus-Chaos to test whether AI agents are resilient to prompt
injection attacks. It's protocol-level fuzzing for MCP servers.

What it does:
• Intercepts MCP JSON-RPC messages and injects 43 attack patterns
• Detects bypasses in real-time during CI/CD
• Generates resilience scores (0-100) with fail-fast thresholds
• Works as a GitHub Actions security gate

100% open source (Apache 2.0). No account, no API key, no cloud service.

Repo: https://github.com/visus-mcp/visus-chaos
Docs: https://chaos.visus-mcp.org

We're also building enterprise features (SIEM integration, compliance PDFs)
for SOC teams, but the core engine will always be free.

Feedback welcome!
```

**Reddit Strategy:**
- r/netsec: Focus on security testing angle
- r/programming: Focus on Go architecture + MCP protocol
- r/golang: Focus on clean stdlib-only design

**LinkedIn Strategy:**
```
I'm excited to share Visus-Chaos – an open-source adversarial testing
framework we built to make AI agents safer.

The problem: Most AI agents fetch web content without sanitization.
A malicious webpage can inject "Ignore previous instructions" and hijack
the agent's behavior.

Our solution: Protocol-level fuzzing. Chaos intercepts MCP messages and
injects 43 attack patterns before the server processes them. If a bypass
is detected, your CI/CD pipeline fails.

It's free, open-source (Apache 2.0), and works with any MCP server.

Try it: github.com/visus-mcp/visus-chaos

For enterprise teams: We're building SIEM connectors (Splunk, Sentinel)
and compliance artifacts (EU AI Act, NIST AI RMF). DM me if you're interested.

#AIAct #DevSecOps #LLMSecurity
```

**Twitter/X Strategy:**
- Thread (10 tweets) explaining the problem, demo GIF, link to repo
- Tag: @anthropicai, @openai, @GoogleAI, security researchers
- Retweet from @lateosai account

**YouTube Demo (5 minutes):**
1. Problem statement (1 min) — show a bypass in action
2. Install Chaos (30 sec) — `go install` or `docker pull`
3. Run first test (1 min) — `chaos proxy --mcp-server ...`
4. View JSON report (1 min) — findings, resilience score
5. GitHub Actions (1 min) — CI/CD integration example
6. Call to action (30 sec) — contribute payloads, star repo

---

### Phase 2: Enterprise Validation (Week 3-4)

**Outbound Sales Triggers:**

Monitor GitHub issues for these signals:
```
"Can Chaos send events to Splunk?" → Enterprise prospect
"We need compliance artifacts for SOC2" → Enterprise prospect
"How do I export OCSF events?" → Enterprise prospect
"Is there a paid tier with support?" → Pro/Enterprise prospect
```

**Outreach Template:**
```
Hi [Name],

I saw your comment on the Visus-Chaos repo about [SIEM/compliance].

We're building an Enterprise tier with:
• SIEM connectors (Splunk HEC, Sentinel API)
• PDF compliance artifacts (EU AI Act, NIST AI RMF)
• Encrypted audit logs (AES-256-GCM)
• Priority support (24hr SLA)

Would you be interested in a 30-day trial? I can provision access today.

Best,
Leo
Lateos AI Security
```

**Design Partner Criteria:**
- Using Visus-MCP in production (proof: GitHub star/issue history)
- Has Splunk or Sentinel already deployed
- Subject to compliance regime (SOC2, HIPAA, EU AI Act)
- Willing to provide feedback + testimonial

**Offer:**
- 50% off first year ($1,249/mo instead of $2,499/mo)
- Direct Slack channel to engineering
- Input on roadmap priorities
- Case study publication (with approval)

---

### Phase 3: Revenue Scale (Month 2-6)

**Inbound Funnel:**
```
1,000 GitHub stars → 500 weekly downloads → 100 active CI/CD users →
10 Enterprise conversations → 3 closed deals ($7.5k MRR)
```

**Conversion Tactics:**

1. **In-Product Upsell:**
   - After 10 successful Community runs → banner: "Upgrade to Pro for PDF reports"
   - After 50 successful runs → banner: "Send to Splunk with Enterprise"

2. **Email Drip (Docker Hub downloads):**
   - Day 1: "Thanks for trying Chaos! Here's a quick start guide"
   - Day 7: "Found any bypasses? Here's how to contribute"
   - Day 14: "See how [Company] uses Chaos in production" (case study)
   - Day 30: "Need SIEM integration? Try Enterprise free for 14 days"

3. **Webinar Series:**
   - "AI Security in CI/CD: A Practical Guide" (live demo of Chaos)
   - "EU AI Act Compliance for AI Agents" (showcase PDF artifacts)
   - "SOC Analyst Toolkit: Integrating Chaos with Splunk" (technical deep-dive)

**Content Marketing:**
- Blog: "How we found 12 bypasses in popular MCP servers" (name names, responsibly disclosed)
- Blog: "Building a chaos engineering pipeline for AI agents"
- Whitepaper: "The Adversarial Testing Maturity Model" (levels 0-5, position Chaos at level 4)

---

## Next Steps (Immediate Actions)

### Week 0 (Pre-Development)

1. **Create Public Repository:** `github.com/visus-mcp/visus-chaos` (Apache 2.0)
2. **Create Private Repository:** `github.com/lateos/visus-chaos-enterprise` (Proprietary)
3. **Register Domains:**
   - `chaos.visus-mcp.org` (docs site)
   - `visus-chaos.com` (marketing redirect → GitHub)
4. **Hire Go Engineer:** 3-month contract, remote, $120k annualized (or $30k for 3 months)
   - Post on: r/golang, GoLangBridge Slack, We Work Remotely
5. **Legal Review:**
   - Apache 2.0 for Community Edition (standard boilerplate)
   - EULA for Enterprise Edition (attorney review: $2k)
   - Export compliance check (encryption = EAR Category 5 Part 2)

### Week 1-2 (Community Edition Development)

6. **Build Community Edition** (see Sprint Schedule above)
7. **Write Launch Content:**
   - HackerNews post
   - Reddit posts (3 variants for different subs)
   - LinkedIn post
   - Twitter thread
   - YouTube demo script

### Week 3 (Launch Week)

8. **Launch Sequence:**
   - Monday: Publish to GitHub, submit to HackerNews
   - Tuesday: Reddit posts if HN didn't trend
   - Wednesday: LinkedIn + Twitter
   - Thursday: YouTube demo published
   - Friday: Email to Visus-MCP users (if >100 stars by then)

9. **Monitor & Engage:**
   - Respond to every GitHub issue within 4 hours
   - Answer every HN/Reddit comment within 2 hours
   - DM everyone who stars the repo on Twitter (if they have DMs open)

### Week 4-6 (Enterprise Development)

10. **Build Enterprise Features** (see Sprint Schedule)
11. **Sales Outreach:** Contact 20 prospects identified from Community engagement
12. **Close 3 Design Partners:** 50% discount, tight feedback loop

---

## Appendix: CLI Command Reference

```bash
# Start adversarial proxy
chaos proxy \
  --mcp-server ./dist/index.js \
  --corpus ./security/canaries \
  --mode strict \
  --threshold 85 \
  --siem splunk,sentinel \
  --output ./chaos-report.json \
  --exit-on-fail

# Generate compliance PDF
chaos pdf \
  --input ./chaos-report.json \
  --template compliance \
  --output ./eu-ai-act-report.pdf

# Test SIEM connectivity
chaos siem test --provider splunk

# Replay failed events
chaos siem replay --dlq ./failed-events.jsonl --siem sentinel

# Validate license key
chaos license validate --key $VISUS_CHAOS_LICENSE

# Run in Docker (CI/CD)
docker run --rm \
  -v $(pwd):/workspace \
  -e SPLUNK_HEC_TOKEN=$TOKEN \
  lateos/visus-chaos:v1.0.0 \
  proxy --mcp-server /workspace/dist/index.js --threshold 85
```

---

## Document History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-01-05 | Initial draft (fully proprietary model) | Lateos AI Security Team |
| 2.0 | 2026-01-05 | **Revised to Open Core model** | Lateos AI Security Team |

### Summary of Changes (v2.0)

**Major Strategic Shift: Fully Proprietary → Open Core Licensing**

#### What Changed

1. **Licensing Model:**
   - **Before:** Single proprietary product, no free tier
   - **After:** 4-tier model (Community/Pro/Enterprise/Enterprise+)
   - **Community Edition:** 100% open source (Apache 2.0), includes core adversarial engine

2. **Pricing:**
   - **Before:** $499/mo minimum (Pro tier)
   - **After:** Free Community Edition + $99/mo Pro + $2,499/mo Enterprise
   - **New Revenue Target:** $35k MRR in 6 months (was: undefined)

3. **Roadmap Priority:**
   - **Before:** Enterprise features first (SIEM, PDF) → then validate market
   - **After:** Community Edition first (Weeks 1-3) → validate with open source → build paid tiers

4. **Go-to-Market:**
   - **Before:** Traditional enterprise sales (6-12 month cycles)
   - **After:** Community-led growth → HackerNews/Reddit launch → identify Enterprise prospects from GitHub issues → <30 day sales cycles

5. **Module Structure:**
   - **Before:** Single private repository (`lateos/visus-chaos-enterprise`)
   - **After:** Dual repos (`visus-mcp/visus-chaos` public + `lateos/visus-chaos-enterprise` private)

6. **Success Metrics:**
   - **Added:** 1,000 GitHub stars, 500 weekly downloads, 20 community payload contributions
   - **Commercial:** 50 Pro + 10 Enterprise + 2 Enterprise+ customers

#### What Stayed the Same

- Go as primary language (static binaries for CI/CD)
- OCSF v1.3.0 event schema for SIEM integration
- EU AI Act + NIST AI RMF compliance artifact structure
- Durable execution with dead-letter queue
- 6-week sprint timeline (now: 3 weeks Community + 3 weeks Enterprise)

#### Rationale for Open Core

**Problem with Fully Proprietary:**
- No adoption flywheel (users can't try before buying)
- No community contributions (missed payload discoveries)
- Long enterprise sales cycles (6-12 months to first revenue)

**Benefits of Open Core:**
- Instant adoption (free Community Edition removes barriers)
- Faster time-to-revenue (<30 days from download to Enterprise trial)
- Community-driven payload corpus (strengthens product for all tiers)
- Competitive moat vs Garak/PyRIT (open-source competitors lack SIEM/compliance features)

**Revenue Protection:**
- Enterprise features (SIEM, PDF, DLQ) are complex to DIY (~300 eng hours = $60k)
- License key gating prevents unauthorized use of paid features
- Community users "prove value to themselves" before sales conversation

---

**Document Version:** 2.0 (OPEN CORE MODEL)
**Author:** Lateos AI Security Team
**Last Updated:** 2026-01-05
**Classification:** PUBLIC (Community Edition) + CONFIDENTIAL (Enterprise Features)
