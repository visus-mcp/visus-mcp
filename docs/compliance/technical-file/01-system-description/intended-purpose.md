# Visus-MCP Intended Purpose (Annex IV §1.1)

## System Overview
Visus-MCP is a local-first, stateless web content orchestrator designed for integration with Large Language Models (LLMs) such as Claude. It fetches, renders, and sanitizes untrusted web content to mitigate risks from Indirect Prompt Injection (IPI), direct injection attacks, Personally Identifiable Information (PII) exposure, and self-replicating threats (e.g., Morris II worms).

**Primary Function:** Pre-process web inputs before ingestion into LLM context windows, ensuring token efficiency, security, and regulatory compliance.

## Intended Purpose & Use Cases
- **Core Purpose:** Enable secure, low-latency web access for LLM agents without forwarding raw HTML/JS to the model. Processes content through a pipeline: Render (Playwright) → Detect (IPI/Worm) → Sanitize (45 patterns) → Redact (PII) → Prove (Crypto) → Log (Immutable Ledger).
- **High-Risk Deployment Contexts (Annex III §5(b)):** LLM agents in high-risk sectors like finance (fraud detection), healthcare (patient data queries), or legal (case research), where untrusted web inputs could introduce adversarial manipulation.
- **General Purpose AI (GPAI) Alignment (Art. 52):** As a foundational tool for GPAI systems, Visus-MCP provides systemic risk controls (e.g., Art. 52(3) training data governance via stateless design).
- **Non-Intended Uses:** Not for real-time processing (latency >2s); not a full browser (no user interaction); not for storage/compute-bound tasks (local-only).

**Performance Claims:** <2s end-to-end (95th percentile); 70% avg. token reduction; 100% detection on 43/45 injection patterns (validated tests).

**Deployment Model:** Local MCP server (stdio); Optional hosted renderer (Phase 2: AWS Lambda for scalability).
