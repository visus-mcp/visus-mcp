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

export interface SanitizationResult {
  content: string;
  sanitization: {
    patterns_detected: string[];
    pii_types_redacted: string[];
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
}

/**
 * Sanitize content through the full pipeline
 *
 * Pipeline:
 * 1. Injection detection and neutralization (43 patterns)
 * 2. PII redaction (email, phone, SSN, CC, IP)
 * 3. Metadata collection and logging
 *
 * @param content Raw content from web page
 * @returns Sanitized content with detection metadata
 */
export function sanitize(content: string): SanitizationResult {
  const originalLength = content.length;

  // Step 1: Detect and neutralize injection patterns
  const injectionResult = detectAndNeutralize(content);

  // Step 2: Redact PII from the already-sanitized content
  const piiResult = redactPII(injectionResult.content);

  // Step 3: Combine results
  const finalContent = piiResult.content;
  const contentModified = injectionResult.content_modified || piiResult.content_modified;

  const severityScore = getSeverityScore(injectionResult.metadata.detections_by_severity);
  const criticalThreats = hasCriticalThreats(injectionResult.metadata.detections_by_severity);

  // Log to stderr for monitoring (not stdout - MCP protocol)
  logSanitization({
    patterns_detected: injectionResult.patterns_detected,
    pii_types_redacted: piiResult.pii_types_redacted,
    severity_score: severityScore,
    has_critical_threats: criticalThreats,
    content_modified: contentModified
  });

  return {
    content: finalContent,
    sanitization: {
      patterns_detected: injectionResult.patterns_detected,
      pii_types_redacted: piiResult.pii_types_redacted,
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
}

/**
 * Log sanitization events to stderr for monitoring
 * (structured JSON logging per Lateos conventions)
 */
function logSanitization(event: {
  patterns_detected: string[];
  pii_types_redacted: string[];
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
  if (event.content_modified) {
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
 * Export sub-components for testing
 */
export { detectAndNeutralize } from './injection-detector.js';
export { redactPII, containsPII, detectPIITypes } from './pii-redactor.js';
export { INJECTION_PATTERNS, getAllPatternNames } from './patterns.js';
