/**
 * Threat Summary Utilities
 *
 * Helper functions to compute threat summaries from threat annotations.
 *
 * @module security/threat-summary
 */

import type { ThreatAnnotation, ThreatSeverity, ThreatClass } from './threats.js';
import type { ThreatSummary } from '../types.js';

/**
 * Severity ranking for comparison (higher = more severe)
 */
const SEVERITY_RANK: Record<ThreatSeverity | 'NONE', number> = {
  NONE: 0,
  INFO: 1,
  LOW: 2,
  MEDIUM: 3,
  HIGH: 4,
  CRITICAL: 5,
};

/**
 * Compute threat summary from threat annotations
 *
 * @param threats - Array of threat annotations
 * @returns Threat summary with count, highest severity, and detected classes
 *
 * @example
 * ```typescript
 * const threats: ThreatAnnotation[] = [
 *   { id: 'IPI-001', severity: 'CRITICAL', confidence: 0.95, offset: 0, excerpt: '...', vector: 'html', mitigated: true },
 *   { id: 'IPI-002', severity: 'HIGH', confidence: 0.8, offset: 100, excerpt: '...', vector: 'html', mitigated: true },
 * ];
 * const summary = computeThreatSummary(threats);
 * // { threat_count: 2, highest_severity: 'CRITICAL', classes_detected: ['IPI-001', 'IPI-002'] }
 * ```
 */
export function computeThreatSummary(threats: ThreatAnnotation[]): ThreatSummary {
  if (threats.length === 0) {
    return {
      threat_count: 0,
      highest_severity: 'NONE',
      classes_detected: [],
    };
  }

  // Find highest severity
  let highestSeverity: ThreatSeverity | 'NONE' = 'NONE';
  for (const threat of threats) {
    if (SEVERITY_RANK[threat.severity] > SEVERITY_RANK[highestSeverity]) {
      highestSeverity = threat.severity;
    }
  }

  // Collect unique threat classes
  const classesSet = new Set<ThreatClass>();
  for (const threat of threats) {
    classesSet.add(threat.id);
  }

  return {
    threat_count: threats.length,
    highest_severity: highestSeverity,
    classes_detected: Array.from(classesSet),
  };
}
