/**
 * Injection Detection Engine
 *
 * Scans content against all 43 injection patterns and neutralizes threats
 * based on pattern action directives (strip, redact, escape).
 */

import { INJECTION_PATTERNS, type InjectionPattern } from './patterns.js';

export interface DetectionResult {
  content: string;
  patterns_detected: string[];
  content_modified: boolean;
  metadata: {
    original_length: number;
    sanitized_length: number;
    detections_by_severity: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
}

/**
 * Detect and neutralize injection patterns in content
 */
export function detectAndNeutralize(content: string): DetectionResult {
  const originalLength = content.length;
  const patternsDetected = new Set<string>();
  const detectionsBySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  let sanitizedContent = content;

  // Apply each pattern
  for (const pattern of INJECTION_PATTERNS) {
    const matches = sanitizedContent.match(pattern.regex);

    if (matches && matches.length > 0) {
      patternsDetected.add(pattern.name);
      detectionsBySeverity[pattern.severity] += matches.length;

      // Apply action
      sanitizedContent = applyAction(sanitizedContent, pattern);
    }
  }

  return {
    content: sanitizedContent,
    patterns_detected: Array.from(patternsDetected),
    content_modified: sanitizedContent !== content,
    metadata: {
      original_length: originalLength,
      sanitized_length: sanitizedContent.length,
      detections_by_severity: detectionsBySeverity
    }
  };
}

/**
 * Apply the appropriate action for a pattern match
 */
function applyAction(content: string, pattern: InjectionPattern): string {
  switch (pattern.action) {
    case 'strip':
      // Remove matched content entirely
      return content.replace(pattern.regex, '');

    case 'redact':
      // Replace with redaction marker
      return content.replace(pattern.regex, `[REDACTED:${pattern.name.toUpperCase()}]`);

    case 'escape':
      // HTML escape matched content
      return content.replace(pattern.regex, (match) => escapeHtml(match));

    default:
      return content;
  }
}

/**
 * HTML escape special characters
 */
function escapeHtml(text: string): string {
  const htmlEntities: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;'
  };

  return text.replace(/[&<>"'/]/g, (char) => htmlEntities[char] || char);
}

/**
 * Get severity score for logging/monitoring
 */
export function getSeverityScore(detectionsBySeverity: DetectionResult['metadata']['detections_by_severity']): number {
  return (
    detectionsBySeverity.critical * 100 +
    detectionsBySeverity.high * 50 +
    detectionsBySeverity.medium * 10 +
    detectionsBySeverity.low * 1
  );
}

/**
 * Check if content has critical threats
 */
export function hasCriticalThreats(detectionsBySeverity: DetectionResult['metadata']['detections_by_severity']): boolean {
  return detectionsBySeverity.critical > 0;
}
