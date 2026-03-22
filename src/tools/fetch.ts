/**
 * visus_fetch MCP Tool
 *
 * Fetches a web page and returns sanitized content in markdown or text format.
 *
 * CRITICAL: ALL content MUST pass through the sanitizer. This cannot be bypassed.
 */

import { renderPage } from '../browser/playwright-renderer.js';
import { sanitize } from '../sanitizer/index.js';
import { truncateContent } from '../utils/truncate.js';
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

    // Step 3: Apply token ceiling truncation (AFTER sanitization)
    // Anthropic MCP Directory enforces 25,000 token response limit
    const truncationResult = truncateContent(sanitizationResult.content);

    // Step 4: Build output
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
        ...(truncationResult.truncated && {
          truncated: true,
          truncated_at_chars: truncationResult.truncated_at_chars
        })
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
