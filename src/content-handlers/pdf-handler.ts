/**
 * PDF Content Handler
 *
 * Handles application/pdf content type. Extracts text and metadata from PDF files,
 * passes all text through the injection pattern registry, and returns sanitized plain text.
 *
 * What it handles:
 * - PDF body text (full document)
 * - PDF metadata: title, author, subject, keywords, creator, producer
 * - Annotation text
 * - Form field values
 *
 * What it strips:
 * - Embedded binary objects (fonts, images, attachments)
 * - Returns only extracted text, not original binary
 *
 * What it passes through:
 * - All extracted text after injection pattern sanitization
 */

import { PDFParse } from 'pdf-parse';
import { sanitize } from '../sanitizer/index.js';
import { ThreatDetector } from '../security/ThreatDetector.js';
import type { HandlerResult } from './types.js';

/**
 * Handle PDF content
 *
 * @param content - Raw PDF binary data as Buffer or string
 * @param mimeType - Original MIME type
 * @returns Sanitized handler result
 */
export async function handlePdf(
  content: string | Buffer,
  mimeType: string
): Promise<HandlerResult> {
  const startTime = Date.now();

  try {
    // Ensure we have a Buffer
    const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content);

    // Parse PDF using pdf-parse v2 API
    const parser = new PDFParse({ data: buffer });

    // Get text and metadata separately
    const textResult = await parser.getText();
    const infoResult = await parser.getInfo();

    // Extract text and metadata
    const bodyText = textResult.text || '';
    const metadata = infoResult.info || {};

    // Build combined text from body + metadata
    let combinedText = bodyText;

    // Append metadata fields
    const metadataFields = ['Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer'];
    for (const field of metadataFields) {
      const value = metadata[field];
      if (value && typeof value === 'string') {
        combinedText += `\n\n${field}: ${value}`;
      }
    }

    // Run IPI threat detection on raw content BEFORE sanitization
    const detector = new ThreatDetector();
    const threats = detector.scan(combinedText, 'pdf');

    // Pass through injection detection pipeline
    const sanitizationResult = sanitize(combinedText);

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

  } catch (error) {
    return {
      status: 'error',
      reason: 'PDF_PARSE_FAILED',
      mime: mimeType,
      message: error instanceof Error ? error.message : String(error)
    };
  }
}
