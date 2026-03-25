/**
 * Content Handlers Module
 *
 * Central routing for content-type specific sanitization handlers.
 * Detects MIME type from Content-Type header and routes to appropriate handler.
 *
 * Supported content types:
 * - application/pdf -> PDF handler
 * - application/json -> JSON handler
 * - image/svg+xml -> SVG handler
 *
 * Unsupported types return structured rejection (no throw).
 */

import { handlePdf } from './pdf-handler.js';
import { handleJson } from './json-handler.js';
import { handleSvg } from './svg-handler.js';
import type { HandlerResult } from './types.js';

/**
 * Normalize Content-Type header to base MIME type
 *
 * Examples:
 * - "application/pdf; charset=utf-8" -> "application/pdf"
 * - "application/json" -> "application/json"
 * - "IMAGE/SVG+XML" -> "image/svg+xml"
 *
 * @param contentType - Raw Content-Type header value
 * @returns Normalized MIME type (lowercase, parameters stripped)
 */
export function normalizeMimeType(contentType: string): string {
  return contentType.toLowerCase().split(';')[0].trim();
}

/**
 * Route content to appropriate handler based on MIME type
 *
 * @param content - Raw content (string or Buffer)
 * @param contentType - Content-Type header value
 * @returns Handler result (success or error/rejected)
 */
export async function routeContentHandler(
  content: string | Buffer,
  contentType: string
): Promise<HandlerResult> {
  const mimeType = normalizeMimeType(contentType);

  // Route to appropriate handler
  switch (mimeType) {
    case 'application/pdf':
      return handlePdf(content, mimeType);

    case 'application/json':
    case 'text/json':
      return handleJson(content, mimeType);

    case 'image/svg+xml':
      return handleSvg(content, mimeType);

    default:
      // Unsupported content type - return structured rejection
      return {
        status: 'rejected',
        reason: 'UNSUPPORTED_CONTENT_TYPE',
        mime: mimeType,
        message: `Content type ${mimeType} is not supported by Visus-MCP.`
      };
  }
}

// Re-export types
export type { HandlerResult, HandlerSuccessResult, HandlerErrorResult } from './types.js';
