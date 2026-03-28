/**
 * Content Handler Types
 *
 * Shared interfaces for content-type specific handlers.
 */

import type { ThreatAnnotation } from '../security/threats.js';

/**
 * Success result from a content handler
 */
export interface HandlerSuccessResult {
  status: 'sanitized';
  content_type: string;
  sanitized_content: string;
  sanitization: {
    patterns_detected: string[];
    pii_types_redacted: string[];
    pii_allowlisted: Array<{ type: string; value: string; reason: string }>;
    sanitized_fields: number;
  };
  processing_time_ms: number;
  /**
   * Fine-grained threat annotations from IPI detection system (v0.9.0+)
   */
  threats: ThreatAnnotation[];
}

/**
 * Error result from a content handler
 */
export interface HandlerErrorResult {
  status: 'error' | 'rejected';
  reason: string;
  mime: string;
  message: string;
}

/**
 * Union type for all handler results
 */
export type HandlerResult = HandlerSuccessResult | HandlerErrorResult;

/**
 * Content handler function signature
 */
export type ContentHandler = (
  content: string | Buffer,
  mimeType: string
) => Promise<HandlerResult> | HandlerResult;
