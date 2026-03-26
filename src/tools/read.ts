/**
 * visus_read MCP Tool
 *
 * Extracts clean article content from a web page using Mozilla Readability,
 * stripping navigation, ads, and boilerplate. Full prompt injection sanitization
 * and PII redaction applied before content reaches the LLM.
 *
 * CRITICAL: ALL content MUST pass through the sanitizer. This cannot be bypassed.
 *
 * Pipeline order:
 * 1. Playwright renders page (full JS execution)
 * 2. Reader extracts main content (reduces input size)
 * 3. Sanitizer runs on clean text
 * 4. Token ceiling applied (24,000 token cap)
 */

import { renderPage } from '../browser/playwright-renderer.js';
import { extractArticle } from '../browser/reader.js';
import { sanitize } from '../sanitizer/index.js';
import { truncateContent } from '../utils/truncate.js';
import type { VisusReadInput, VisusReadOutput, Result } from '../types.js';
import { Err } from '../types.js';

/**
 * visus_read tool implementation
 *
 * @param input Tool input parameters
 * @returns Sanitized article content with metadata
 */
export async function visusRead(input: VisusReadInput): Promise<Result<VisusReadOutput, Error>> {
  const { url, timeout_ms = 10000 } = input;

  // Validate inputs
  if (!url || typeof url !== 'string') {
    return Err(new Error('Invalid input: url must be a non-empty string'));
  }

  try {
    // Step 1: Render the page using Playwright
    const renderResult = await renderPage(url, {
      timeout_ms,
      format: 'html'
    });

    if (!renderResult.ok) {
      return Err(renderResult.error);
    }

    const { html, title: pageTitle } = renderResult.value;

    // Type guard: visus_read only works with HTML (string), not binary content
    if (Buffer.isBuffer(html)) {
      return Err(new Error('visus_read does not support binary content types (PDFs, images). Use visus_fetch instead.'));
    }

    // Step 2: Extract article content using Readability
    const readerResult = extractArticle(html, url);

    if (!readerResult.ok) {
      return Err(readerResult.error);
    }

    const article = readerResult.value;

    // Step 3: CRITICAL - Sanitize content (injection detection + PII redaction)
    // Sanitization runs AFTER Readability, not before
    // This step CANNOT be skipped or bypassed
    const sanitizationResult = sanitize(article.content, url);

    // Step 4: Apply token ceiling truncation (AFTER sanitization)
    // Anthropic MCP Directory enforces 25,000 token response limit
    const truncationResult = truncateContent(sanitizationResult.content);

    // Step 5: Build output
    const output: VisusReadOutput = {
      url,
      content: truncationResult.content,
      metadata: {
        title: article.title || pageTitle || 'Untitled',
        author: article.byline,
        published: article.publishedTime,
        word_count: article.wordCount,
        reader_mode_available: article.readerModeAvailable,
        sanitized: true,
        injections_removed: sanitizationResult.sanitization.patterns_detected.length,
        pii_redacted: sanitizationResult.sanitization.pii_types_redacted.length,
        truncated: truncationResult.truncated,
        fetched_at: new Date().toISOString()
      },
      // Include threat_report only if findings exist
      ...(sanitizationResult.threat_report && { threat_report: sanitizationResult.threat_report })
    };

    // Log to stderr if critical threats detected
    if (sanitizationResult.metadata.has_critical_threats) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        event: 'reader_critical_threat_detected',
        url,
        patterns: sanitizationResult.sanitization.patterns_detected,
        severity_score: sanitizationResult.metadata.severity_score
      }));
    }

    // Log to stderr if reader mode failed (non-article page)
    if (!article.readerModeAvailable) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        event: 'reader_mode_fallback',
        url,
        reason: 'Readability could not extract article structure'
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
export const visusReadToolDefinition = {
  name: 'visus_read',
  title: 'Read Web Page (Reader Mode + Sanitized)',
  description: 'Extracts clean article content from a web page using Mozilla Readability, stripping navigation, ads, and boilerplate. Full prompt injection sanitization and PII redaction applied before content reaches the LLM. Optimized for context-efficient, safe web reading in Claude Desktop.',
  inputSchema: {
    type: 'object',
    properties: {
      url: {
        type: 'string',
        description: 'The URL to fetch (must be http:// or https://)'
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
