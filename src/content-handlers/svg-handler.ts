/**
 * SVG Content Handler
 *
 * Handles image/svg+xml content type. SVG is XML, not a binary image, and can contain
 * executable code and external references. This handler strips dangerous elements and
 * attributes unconditionally, then sanitizes remaining text content.
 *
 * What it handles:
 * - All text content in SVG elements after stripping dangerous parts
 *
 * What it strips (unconditionally, no attempt to sanitize):
 * - <script> elements and all children
 * - <use> elements with external href or xlink:href attributes
 * - <foreignObject> elements and all children
 * - All event handler attributes (onload, onclick, onerror, etc.)
 * - <set> and <animate> elements that reference external resources
 * - data: URI attributes
 *
 * What it passes through (after injection scan):
 * - Path data (d attribute)
 * - Text elements and their content
 * - <title> and <desc> elements
 * - Presentation attributes (fill, stroke, transform, etc.)
 * - viewBox, width, height attributes
 */

import { XMLParser, XMLBuilder } from 'fast-xml-parser';
import { sanitize } from '../sanitizer/index.js';
import type { HandlerResult } from './types.js';

/**
 * Handle SVG content
 *
 * @param content - Raw SVG XML string or Buffer
 * @param mimeType - Original MIME type
 * @returns Sanitized handler result
 */
export function handleSvg(
  content: string | Buffer,
  mimeType: string
): HandlerResult {
  const startTime = Date.now();

  // Convert Buffer to string if needed
  const svgString = Buffer.isBuffer(content) ? content.toString('utf-8') : content;

  try {
    // Parse SVG XML
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      textNodeName: '#text',
      preserveOrder: false,
      removeNSPrefix: true,
    });

    const parsed = parser.parse(svgString);

    // Track sanitized field count
    let sanitizedFieldCount = 0;

    // Strip dangerous elements and attributes
    const stripped = stripDangerousContent(parsed);

    // Extract all text content for injection scanning
    const textContent = extractTextContent(stripped);

    // Run text through injection detection
    let sanitizationResult;
    if (textContent.length > 0) {
      sanitizationResult = sanitize(textContent);
      if (sanitizationResult.sanitization.content_modified) {
        sanitizedFieldCount = sanitizationResult.sanitization.patterns_detected.length;
      }
    }

    // Rebuild SVG
    const builder = new XMLBuilder({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      textNodeName: '#text',
      format: true,
      suppressEmptyNode: true,
    });

    const sanitizedSvg = builder.build(stripped);

    const processingTime = Date.now() - startTime;

    return {
      status: 'sanitized',
      content_type: mimeType,
      sanitized_content: sanitizedSvg,
      sanitization: {
        patterns_detected: sanitizationResult?.sanitization.patterns_detected || [],
        pii_types_redacted: sanitizationResult?.sanitization.pii_types_redacted || [],
        pii_allowlisted: sanitizationResult?.sanitization.pii_allowlisted || [],
        sanitized_fields: sanitizedFieldCount
      },
      processing_time_ms: processingTime
    };

  } catch (error) {
    return {
      status: 'error',
      reason: 'SVG_PARSE_FAILED',
      mime: mimeType,
      message: error instanceof Error ? error.message : String(error)
    };
  }
}

/**
 * Strip dangerous content from parsed SVG
 *
 * Removes:
 * - <script> elements
 * - <foreignObject> elements
 * - <use> with external href
 * - Event handler attributes
 * - <set> and <animate> with external references
 * - data: URIs
 */
function stripDangerousContent(node: any): any {
  if (typeof node !== 'object' || node === null) {
    return node;
  }

  // Handle arrays
  if (Array.isArray(node)) {
    return node
      .filter((item) => !shouldRemoveElement(item))
      .map((item) => stripDangerousContent(item));
  }

  // Handle objects
  const result: any = {};

  for (const [key, value] of Object.entries(node)) {
    // Skip dangerous elements
    if (key === 'script' || key === 'foreignObject') {
      continue;
    }

    // Handle <use> with external href
    if (key === 'use' && typeof value === 'object' && value !== null) {
      const href = (value as any)['@_href'] || (value as any)['@_xlink:href'];
      if (href && (href.startsWith('http://') || href.startsWith('https://') || href.startsWith('//'))) {
        continue;
      }
    }

    // Handle <set> and <animate> with external references
    if ((key === 'set' || key === 'animate') && typeof value === 'object' && value !== null) {
      const href = (value as any)['@_href'] || (value as any)['@_xlink:href'];
      if (href && (href.startsWith('http://') || href.startsWith('https://') || href.startsWith('//'))) {
        continue;
      }
    }

    // Strip event handler attributes
    if (key.startsWith('@_on')) {
      continue;
    }

    // Strip data: URIs
    if (typeof value === 'string' && value.startsWith('data:')) {
      result[key] = '';
      continue;
    }

    // Strip attributes with data: URIs
    if (key.startsWith('@_') && typeof value === 'string' && value.startsWith('data:')) {
      continue;
    }

    // Recursively process
    result[key] = stripDangerousContent(value);
  }

  return result;
}

/**
 * Check if element should be removed entirely
 */
function shouldRemoveElement(element: any): boolean {
  if (typeof element !== 'object' || element === null) {
    return false;
  }

  // Check for dangerous element types
  const dangerousElements = ['script', 'foreignObject'];
  for (const dangerous of dangerousElements) {
    if (dangerous in element) {
      return true;
    }
  }

  return false;
}

/**
 * Extract all text content from SVG for injection scanning
 */
function extractTextContent(node: any): string {
  if (typeof node !== 'object' || node === null) {
    return '';
  }

  if (typeof node === 'string') {
    return node;
  }

  if (Array.isArray(node)) {
    return node.map((item) => extractTextContent(item)).join(' ');
  }

  let text = '';

  for (const [key, value] of Object.entries(node)) {
    // Extract text from text nodes
    if (key === '#text' && typeof value === 'string') {
      text += value + ' ';
    }

    // Extract from title and desc elements (can be string or object)
    if (key === 'title' || key === 'desc') {
      if (typeof value === 'string') {
        text += value + ' ';
      } else if (typeof value === 'object') {
        text += extractTextContent(value) + ' ';
      }
    }

    // Recursively extract from other children
    if (key !== 'title' && key !== 'desc' && typeof value === 'object') {
      text += extractTextContent(value) + ' ';
    }
  }

  return text.trim();
}
