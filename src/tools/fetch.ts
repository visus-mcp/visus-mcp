/**
 * visus_fetch MCP Tool
 *
 * Fetches a web page and returns sanitized content in markdown or text format.
 *
 * CRITICAL: ALL content MUST pass through the sanitizer. This cannot be bypassed.
 */

import { renderPage } from '../browser/playwright-renderer.js';
import { sanitizeWithProof } from '../sanitizer/index.js';
import { truncateContent } from '../utils/truncate.js';
import { detectFormat, convertJson, convertXml, convertRss } from '../utils/format-converter.js';
import { routeContentHandler, normalizeMimeType } from '../content-handlers/index.js';
import { ThreatDetector } from '../security/ThreatDetector.js';
import { computeThreatSummary } from '../security/threat-summary.js';
import type { VisusFetchInput, VisusFetchOutput, Result } from '../types.js';
import type { ThreatAnnotation } from '../security/threats.js';
import { Err } from '../types.js';

/**
 * visus_fetch tool implementation
 *
 * @param input Tool input parameters
 * @returns Sanitized page content with metadata
 */
export async function visusFetch(input: VisusFetchInput): Promise<Result<VisusFetchOutput, Error>> {
  const { url, format = 'markdown', timeout_ms = 10000 } = input;

  // Validate inputs
  if (!url || typeof url !== 'string') {
    return Err(new Error('Invalid input: url must be a non-empty string'));
  }

  try {
    // Step 1: Render the page using Playwright
    const renderResult = await renderPage(url, {
      timeout_ms,
      format: format === 'text' ? 'text' : 'markdown'
    });

    if (!renderResult.ok) {
      return Err(renderResult.error);
    }

    const { html, title, contentType } = renderResult.value;
    // rawContent can be string (HTML/JSON/SVG) or Buffer (PDF, binary)
    const rawContent = html || '';

    // Step 2: Detect content type and route to specialized handlers if applicable
    const detectedContentType = contentType || 'text/html';
    const normalizedMime = normalizeMimeType(detectedContentType);

    // Check if content requires specialized handler (PDF, JSON, SVG)
    if (normalizedMime === 'application/pdf' ||
        normalizedMime === 'application/json' ||
        normalizedMime === 'text/json' ||
        normalizedMime === 'image/svg+xml') {

      // Route to specialized content handler
      // Note: rawContent may be Buffer for PDFs, string for JSON/SVG
      const handlerResult = await routeContentHandler(rawContent, detectedContentType);

      // Handle unsupported or error cases
      if (handlerResult.status === 'rejected' || handlerResult.status === 'error') {
        return Err(new Error(handlerResult.message));
      }

      // Type guard: ensure we have a success result
      if (handlerResult.status !== 'sanitized') {
        return Err(new Error('Unexpected handler result status'));
      }

      // Handler success - use the already-sanitized content
      const sanitizedContent = handlerResult.sanitized_content;
      const sanitization = handlerResult.sanitization;
      const threats = handlerResult.threats;
      const truncationResult = truncateContent(sanitizedContent);

      // Determine format_detected based on MIME type
      let formatDetected: 'html' | 'json' | 'xml' | 'rss' = 'html';
      if (normalizedMime === 'application/json' || normalizedMime === 'text/json') {
        formatDetected = 'json';
      } else if (normalizedMime === 'image/svg+xml') {
        formatDetected = 'xml'; // SVG is XML-based
      } else if (normalizedMime === 'application/pdf') {
        // PDF doesn't have a format_detected value in the current schema
        // Leaving as 'html' for now
      }

      // Compute threat summary from handler threats
      const threatSummary = computeThreatSummary(threats);

      const output: VisusFetchOutput = {
        url,
        content: truncationResult.content,
        sanitization: {
          patterns_detected: sanitization.patterns_detected,
          pii_types_redacted: sanitization.pii_types_redacted,
          pii_allowlisted: sanitization.pii_allowlisted,
          content_modified: sanitization.sanitized_fields > 0
        },
        metadata: {
          title: title || 'Untitled',
          fetched_at: new Date().toISOString(),
          content_length_original: rawContent.length,
          content_length_sanitized: sanitizedContent.length,
          format_detected: formatDetected,
          content_type: detectedContentType,
          ...(truncationResult.truncated && {
            truncated: true,
            truncated_at_chars: truncationResult.truncated_at_chars
          })
        },
        ...(threatSummary.threat_count > 0 && { threat_summary: threatSummary })
      };

      return { ok: true, value: output };
    }

    // Step 3: For HTML/XML/RSS - use existing format conversion flow
    // Type guard: rawContent should be string for non-binary types
    if (Buffer.isBuffer(rawContent)) {
      return Err(new Error('Unexpected binary content in HTML/XML/RSS path'));
    }

    const formatType = detectFormat(detectedContentType);

    let processedContent = rawContent;

    // Apply format-specific conversion (skip Readability for non-HTML)
    if (formatType === 'json') {
      processedContent = convertJson(rawContent);
    } else if (formatType === 'xml') {
      processedContent = convertXml(rawContent);
    } else if (formatType === 'rss') {
      processedContent = convertRss(rawContent);
    }
    // For 'html' format, processedContent remains as rawContent

    // Step 3.5: Run IPI threat detection on processed content BEFORE sanitization
    const detector = new ThreatDetector();
    const threats: ThreatAnnotation[] = detector.scan(processedContent, 'html');

    // Step 4: CRITICAL - Sanitize content with cryptographic proof
    // (injection detection + PII redaction with allowlisting)
    // This step CANNOT be skipped or bypassed
    const sanitizationResult = await sanitizeWithProof(processedContent, url, 'visus_fetch', '1.0.0');

    // Step 5: Apply token ceiling truncation (AFTER sanitization)
    // Anthropic MCP Directory enforces 25,000 token response limit
    const truncationResult = truncateContent(sanitizationResult.content);

    // Step 5.5: Compute threat summary from IPI detections
    const threatSummary = computeThreatSummary(threats);

    // Step 6: Build output with cryptographic proof
    const output: VisusFetchOutput = {
      url,
      content: truncationResult.content,
      sanitization: {
        patterns_detected: sanitizationResult.sanitization.patterns_detected,
        pii_types_redacted: sanitizationResult.sanitization.pii_types_redacted,
        pii_allowlisted: sanitizationResult.sanitization.pii_allowlisted,
        content_modified: sanitizationResult.sanitization.content_modified
      },
      metadata: {
        title: title || 'Untitled',
        fetched_at: new Date().toISOString(),
        content_length_original: sanitizationResult.metadata.original_length,
        content_length_sanitized: sanitizationResult.metadata.sanitized_length,
        format_detected: formatType,
        content_type: detectedContentType,
        ...(truncationResult.truncated && {
          truncated: true,
          truncated_at_chars: truncationResult.truncated_at_chars
        })
      },
      // Include threat_report only if findings exist
      ...(sanitizationResult.threat_report && { threat_report: sanitizationResult.threat_report }),
      // Include threat_summary only if threats detected
      ...(threatSummary.threat_count > 0 && { threat_summary: threatSummary }),
      // Include cryptographic proof header (EU AI Act Art. 13 Transparency)
      ...sanitizationResult.proofHeader
    };

    // Log to stderr if critical threats detected
    if (sanitizationResult.metadata.has_critical_threats) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        event: 'critical_threat_detected',
        url,
        patterns: sanitizationResult.sanitization.patterns_detected,
        severity_score: sanitizationResult.metadata.severity_score
      }));
    }

    return { ok: true, value: output };

  } catch (error) {
    return Err(error instanceof Error ? error : new Error(String(error)));
  }
}

/**
 * MCP tool definition for registration
 */
export const visusFetchToolDefinition = {
  name: 'visus_fetch',
  title: 'Fetch Web Page (Sanitized)',
  description: 'Fetch and sanitize web page content. Returns clean, injection-free content in markdown or text format. SECURITY: All content passes through prompt injection sanitization (43 pattern categories) and PII redaction BEFORE reaching the LLM. This ensures safe consumption of untrusted web content.',
  inputSchema: {
    type: 'object',
    properties: {
      url: {
        type: 'string',
        description: 'The URL to fetch (must be http:// or https://)'
      },
      format: {
        type: 'string',
        enum: ['markdown', 'text'],
        description: 'Output format: markdown (default) or plain text',
        default: 'markdown'
      },
      timeout_ms: {
        type: 'number',
        description: 'Request timeout in milliseconds (default: 10000)',
        default: 10000
      }
    },
    required: ['url']
  },
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true
};
