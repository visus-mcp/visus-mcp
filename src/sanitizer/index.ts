/**
 * Sanitizer Orchestrator
 *
 * Main entry point for content sanitization. Coordinates injection detection
 * and PII redaction pipelines.
 *
 * CRITICAL: This is the core security mechanism. Every web page MUST pass
 * through this sanitizer before reaching the LLM. This cannot be bypassed.
 */

import { detectAndNeutralize, getSeverityScore, hasCriticalThreats } from './injection-detector.js';
import { redactPII } from './pii-redactor.js';
import { generateThreatReport, type ThreatReport } from './threat-reporter.js';
import { generateRequestId } from '../crypto/proof-builder.js';
import { buildProof, proofToResponseHeader } from '../crypto/proof-builder.js';
import type { SanitizationProofRecord } from '../crypto/primitives.js';
import { getAllPatternNames } from './patterns.js';

export interface SanitizationResult {
  content: string;
  sanitization: {
    patterns_detected: string[];
    pii_types_redacted: string[];
    pii_allowlisted: Array<{ type: string; value: string; reason: string }>;
    content_modified: boolean;
  };
  metadata: {
    original_length: number;
    sanitized_length: number;
    severity_score: number;
    has_critical_threats: boolean;
    detections_by_severity: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
  threat_report?: ThreatReport;
}

/**
 * Extended result with cryptographic proof
 */
export interface SanitizationResultWithProof extends SanitizationResult {
  proof: SanitizationProofRecord;
  proofHeader: Record<string, unknown>;
}

/**
 * Sanitize content through the full pipeline
 *
 * Pipeline:
 * 1. Injection detection and neutralization (43 patterns)
 * 2. PII redaction (email, phone, SSN, CC, IP) with allowlisting
 * 3. Metadata collection and logging
 *
 * @param content Raw content from web page
 * @param sourceUrl Optional source URL for domain-scoped PII allowlisting
 * @returns Sanitized content with detection metadata
 */
export function sanitize(content: string, sourceUrl?: string): SanitizationResult {
  const originalLength = content.length;

  // Step 1: Detect and neutralize injection patterns
  const injectionResult = detectAndNeutralize(content);

  // Step 2: Redact PII from the already-sanitized content (with allowlisting)
  const piiResult = redactPII(injectionResult.content, sourceUrl);

  // Step 3: Combine results
  const finalContent = piiResult.content;
  const contentModified = injectionResult.content_modified || piiResult.content_modified;

  const severityScore = getSeverityScore(injectionResult.metadata.detections_by_severity);
  const criticalThreats = hasCriticalThreats(injectionResult.metadata.detections_by_severity);

  // Log to stderr for monitoring (not stdout - MCP protocol)
  logSanitization({
    patterns_detected: injectionResult.patterns_detected,
    pii_types_redacted: piiResult.pii_types_redacted,
    pii_allowlisted: piiResult.pii_allowlisted,
    severity_score: severityScore,
    has_critical_threats: criticalThreats,
    content_modified: contentModified
  });

  // Step 4: Generate threat report (only if findings exist)
  const threatReport = generateThreatReport({
    patterns_detected: injectionResult.patterns_detected,
    pii_redacted: piiResult.pii_types_redacted.length,
    source_url: sourceUrl || 'unknown',
    detections_by_severity: injectionResult.metadata.detections_by_severity
  });

  const result: SanitizationResult = {
    content: finalContent,
    sanitization: {
      patterns_detected: injectionResult.patterns_detected,
      pii_types_redacted: piiResult.pii_types_redacted,
      pii_allowlisted: piiResult.pii_allowlisted,
      content_modified: contentModified
    },
    metadata: {
      original_length: originalLength,
      sanitized_length: finalContent.length,
      severity_score: severityScore,
      has_critical_threats: criticalThreats,
      detections_by_severity: injectionResult.metadata.detections_by_severity
    }
  };

  // Include threat_report only if findings exist
  if (threatReport) {
    result.threat_report = threatReport;
  }

  return result;
}

/**
 * Log sanitization events to stderr for monitoring
 * (structured JSON logging per Lateos conventions)
 */
function logSanitization(event: {
  patterns_detected: string[];
  pii_types_redacted: string[];
  pii_allowlisted: Array<{ type: string; value: string; reason: string }>;
  severity_score: number;
  has_critical_threats: boolean;
  content_modified: boolean;
}): void {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event: 'sanitization',
    ...event
  };

  // Only log if there were detections (reduce noise)
  if (event.content_modified || event.pii_allowlisted.length > 0) {
    console.error(JSON.stringify(logEntry));
  }
}

/**
 * Quick check: does content need sanitization?
 * (Used for optimization - skip pipeline if content is clean)
 *
 * Note: Still run full pipeline for safety, but this can be used for metrics
 */
export function needsSanitization(_content: string): boolean {
  // Always sanitize - this is just a helper for metrics
  return true;
}

/**
 * Sanitize content with cryptographic proof generation
 *
 * This is the primary entry point for MCP tools. It wraps the standard
 * sanitize() function and generates a tamper-evident cryptographic proof
 * that the sanitization pipeline executed before content was forwarded.
 *
 * EU AI Act Art. 9 (Risk Management) + Art. 13 (Transparency) compliance.
 *
 * @param rawContent Raw content from web page
 * @param sourceUrl Optional source URL for domain-scoped PII allowlisting
 * @param toolName Name of the calling MCP tool (for audit trail)
 * @param pipelineVersion Sanitization library version
 * @returns Sanitized content with cryptographic proof
 */
export async function sanitizeWithProof(
  rawContent: string,
  sourceUrl?: string,
  _toolName: string = 'unknown',
  pipelineVersion: string = '1.0.0'
): Promise<SanitizationResultWithProof> {
  // Generate request ID and timestamp BEFORE sanitization
  const requestId = generateRequestId();
  const timestampUtc = new Date().toISOString();
  const startMs = Date.now();

  // Run existing sanitization pipeline (unmodified)
  const sanitizationResult = sanitize(rawContent, sourceUrl);

  const processingDurationMs = Date.now() - startMs;

  // Count total redactions (injection patterns + PII)
  const redactionCount =
    sanitizationResult.sanitization.patterns_detected.length +
    sanitizationResult.sanitization.pii_types_redacted.length;

  // Build cryptographic proof
  const proof = buildProof({
    requestId,
    timestampUtc,
    rawContent,
    sanitizedContent: sanitizationResult.content,
    triggeredPatternIds: sanitizationResult.sanitization.patterns_detected,
    patternsEvaluated: getAllPatternNames().length,
    sanitizationApplied: sanitizationResult.sanitization.content_modified,
    pipelineVersion,
    processingDurationMs,
    redactionCount,
    piiDetected: sanitizationResult.sanitization.pii_types_redacted,
    threatsNeutralized: redactionCount,
  });

  return {
    ...sanitizationResult,
    proof,
    proofHeader: proofToResponseHeader(proof),
  };
}

/**
 * Export sub-components for testing
 */
export { detectAndNeutralize } from './injection-detector.js';
export { redactPII, containsPII, detectPIITypes } from './pii-redactor.js';
export { INJECTION_PATTERNS, getAllPatternNames } from './patterns.js';
