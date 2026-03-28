/**
 * JSON Content Handler
 *
 * Handles application/json content type. Recursively traverses all nodes in the JSON
 * object tree and applies the full injection pattern registry to every string value.
 *
 * What it handles:
 * - All string values in the JSON tree (any depth)
 * - Arrays, nested objects, and mixed-type arrays
 * - Falls back to plain text pipeline if JSON.parse fails
 *
 * What it strips:
 * - Nothing (preserves original structure)
 *
 * What it passes through:
 * - Sanitized JSON with original structure preserved
 * - All non-string values pass through unchanged
 */

import { sanitize } from '../sanitizer/index.js';
import { ThreatDetector } from '../security/ThreatDetector.js';
import type { HandlerResult } from './types.js';

/**
 * Handle JSON content
 *
 * @param content - Raw JSON string
 * @param mimeType - Original MIME type
 * @returns Sanitized handler result
 */
export function handleJson(
  content: string | Buffer,
  mimeType: string
): HandlerResult {
  const startTime = Date.now();

  // Convert Buffer to string if needed
  const jsonString = Buffer.isBuffer(content) ? content.toString('utf-8') : content;

  // Run IPI threat detection on raw JSON string BEFORE sanitization
  const detector = new ThreatDetector();
  const threats = detector.scan(jsonString, 'json');

  try {
    // Parse JSON
    const parsed = JSON.parse(jsonString);

    // Track sanitization metadata across all fields
    let sanitizedFieldCount = 0;
    const allPatternsDetected = new Set<string>();
    const allPiiTypesRedacted = new Set<string>();
    const allPiiAllowlisted: Array<{ type: string; value: string; reason: string }> = [];

    // Recursively sanitize all string values
    const sanitized = recursiveSanitize(parsed, (text: string) => {
      const result = sanitize(text);
      if (result.sanitization.content_modified) {
        sanitizedFieldCount++;
      }

      // Aggregate metadata
      result.sanitization.patterns_detected.forEach(p => allPatternsDetected.add(p));
      result.sanitization.pii_types_redacted.forEach(p => allPiiTypesRedacted.add(p));
      allPiiAllowlisted.push(...result.sanitization.pii_allowlisted);

      return result.content;
    });

    // Re-stringify with 2-space indent
    const sanitizedJson = JSON.stringify(sanitized, null, 2);

    const processingTime = Date.now() - startTime;

    return {
      status: 'sanitized',
      content_type: mimeType,
      sanitized_content: sanitizedJson,
      sanitization: {
        patterns_detected: Array.from(allPatternsDetected),
        pii_types_redacted: Array.from(allPiiTypesRedacted),
        pii_allowlisted: allPiiAllowlisted,
        sanitized_fields: sanitizedFieldCount
      },
      processing_time_ms: processingTime,
      threats
    };

  } catch (error) {
    // JSON.parse failed - fall back to plain text sanitization
    const sanitizationResult = sanitize(jsonString);

    const processingTime = Date.now() - startTime;

    return {
      status: 'sanitized',
      content_type: mimeType,
      sanitized_content: sanitizationResult.content,
      sanitization: {
        patterns_detected: sanitizationResult.sanitization.patterns_detected,
        pii_types_redacted: sanitizationResult.sanitization.pii_types_redacted,
        pii_allowlisted: sanitizationResult.sanitization.pii_allowlisted,
        sanitized_fields: sanitizationResult.sanitization.patterns_detected.length
      },
      processing_time_ms: processingTime,
      threats
    };
  }
}

/**
 * Recursively traverse JSON tree and sanitize all string values
 *
 * @param obj - JSON object/array/primitive
 * @param sanitizeFn - Function to sanitize string values
 * @returns Sanitized object with same structure
 */
function recursiveSanitize(obj: any, sanitizeFn: (text: string) => string): any {
  // Handle null
  if (obj === null) {
    return null;
  }

  // Handle string - sanitize it
  if (typeof obj === 'string') {
    return sanitizeFn(obj);
  }

  // Handle array - recursively sanitize each element
  if (Array.isArray(obj)) {
    return obj.map((item) => recursiveSanitize(item, sanitizeFn));
  }

  // Handle object - recursively sanitize each value
  if (typeof obj === 'object') {
    const sanitizedObj: Record<string, any> = {};
    for (const [key, value] of Object.entries(obj)) {
      sanitizedObj[key] = recursiveSanitize(value, sanitizeFn);
    }
    return sanitizedObj;
  }

  // Handle primitives (number, boolean, undefined) - pass through
  return obj;
}
