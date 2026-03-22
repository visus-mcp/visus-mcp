/**
 * visus_fetch MCP Tool
 *
 * Fetches a web page and returns sanitized content in markdown or text format.
 *
 * CRITICAL: ALL content MUST pass through the sanitizer. This cannot be bypassed.
 */

import { renderPage } from '../browser/playwright-renderer.js';
import { sanitize } from '../sanitizer/index.js';
import type { VisusFetchInput, VisusFetchOutput, Result } from '../types.js';
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

    const { html, title } = renderResult.value;
    const rawContent = html || '';

    // Step 2: CRITICAL - Sanitize content (injection detection + PII redaction with allowlisting)
    // This step CANNOT be skipped or bypassed
    const sanitizationResult = sanitize(rawContent, url);

    // Step 3: Build output
    const output: VisusFetchOutput = {
      url,
      content: sanitizationResult.content,
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
        content_length_sanitized: sanitizationResult.metadata.sanitized_length
      }
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
  description: 'Fetch and sanitize web page content. Returns clean, injection-free content in markdown or text format. All content is automatically scanned for prompt injection patterns and PII before being returned.',
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
  }
};
