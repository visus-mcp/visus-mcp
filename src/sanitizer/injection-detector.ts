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

export interface GlasswormDetection {
  detected: boolean;
  clusterCount: number;
  maxClusterSize: number;
  hasDecoderPattern: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
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

  // Run specialized Glassworm detector first
  const glasswormResult = detectGlassworm(sanitizedContent);
  if (glasswormResult.detected) {
    patternsDetected.add('glassworm_unicode_clusters');
    detectionsBySeverity[glasswormResult.severity]++;

    // Strip all Unicode Variation Selectors
    sanitizedContent = stripUnicodeVariationSelectors(sanitizedContent);
  }

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

/**
 * Detect Glassworm malware patterns
 *
 * Glassworm uses invisible Unicode Variation Selectors for steganographic payloads.
 * This detector identifies:
 * 1. Clusters of 3+ consecutive Unicode Variation Selectors
 * 2. The "decoder pattern": .codePointAt() near hex constants (0xFE00, 0xE0100)
 * 3. Marks clusters of 10+ characters as CRITICAL
 *
 * @param content - Content to scan
 * @returns GlasswormDetection result with severity assessment
 */
export function detectGlassworm(content: string): GlasswormDetection {
  // Unicode Variation Selector ranges:
  // Basic: U+FE00 to U+FE0F (16 selectors)
  // Supplement: U+E0100 to U+E01EF (240 selectors)

  const clusters: number[] = [];
  let currentClusterSize = 0;

  // Scan for clusters of variation selectors
  for (let i = 0; i < content.length; i++) {
    const codePoint = content.codePointAt(i);

    if (!codePoint) continue;

    // Check if this is a Unicode Variation Selector
    const isBasicVS = codePoint >= 0xFE00 && codePoint <= 0xFE0F;
    const isSupplementVS = codePoint >= 0xE0100 && codePoint <= 0xE01EF;

    if (isBasicVS || isSupplementVS) {
      currentClusterSize++;

      // Skip supplementary plane characters (they take 2 code units)
      if (isSupplementVS) {
        i++; // Skip the second code unit
      }
    } else {
      // End of cluster
      if (currentClusterSize >= 3) {
        clusters.push(currentClusterSize);
      }
      currentClusterSize = 0;
    }
  }

  // Check final cluster
  if (currentClusterSize >= 3) {
    clusters.push(currentClusterSize);
  }

  // Check for decoder pattern: .codePointAt() near hex constants
  const hasDecoderPattern = detectDecoderPattern(content);

  // Calculate severity
  const maxClusterSize = clusters.length > 0 ? Math.max(...clusters) : 0;
  let severity: 'critical' | 'high' | 'medium' | 'low' = 'low';

  if (maxClusterSize >= 10 || (hasDecoderPattern && clusters.length > 0)) {
    severity = 'critical';
  } else if (clusters.length > 0) {
    severity = 'high';
  }

  return {
    detected: clusters.length > 0 || hasDecoderPattern,
    clusterCount: clusters.length,
    maxClusterSize,
    hasDecoderPattern,
    severity
  };
}

/**
 * Detect Glassworm decoder pattern
 *
 * Looks for JavaScript code that uses .codePointAt() in proximity (within 500 chars)
 * to hex constants like 0xFE00 or 0xE0100, which is the typical Glassworm decoding pattern.
 *
 * @param content - Content to scan
 * @returns true if decoder pattern detected
 */
function detectDecoderPattern(content: string): boolean {
  // Look for .codePointAt() usage
  const codePointAtPattern = /\.codePointAt\s*\(/gi;
  const hexConstantPattern = /0x(FE0[0-9A-F]|E01[0-9A-F]{2})\b/gi;

  const codePointMatches = [...content.matchAll(codePointAtPattern)];
  const hexMatches = [...content.matchAll(hexConstantPattern)];

  // Check if any .codePointAt() is within 500 characters of a suspicious hex constant
  for (const cpMatch of codePointMatches) {
    const cpIndex = cpMatch.index || 0;

    for (const hexMatch of hexMatches) {
      const hexIndex = hexMatch.index || 0;
      const distance = Math.abs(cpIndex - hexIndex);

      if (distance <= 500) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Strip all Unicode Variation Selectors from content
 *
 * @param content - Content to sanitize
 * @returns Content with all variation selectors removed
 */
export function stripUnicodeVariationSelectors(content: string): string {
  // Remove basic variation selectors (U+FE00 to U+FE0F)
  let sanitized = content.replace(/[\uFE00-\uFE0F]/g, '');

  // Remove supplement variation selectors (U+E0100 to U+E01EF)
  // These are in the supplementary plane, so we need to handle them specially
  sanitized = sanitized.replace(/[\uDB40][\uDD00-\uDDEF]/g, '');

  return sanitized;
}
