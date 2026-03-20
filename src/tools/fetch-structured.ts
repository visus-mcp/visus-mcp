/**
 * visus_fetch_structured MCP Tool
 *
 * Fetches a web page and extracts structured data according to a schema.
 * All extracted data is sanitized before being returned.
 *
 * CRITICAL: ALL content MUST pass through the sanitizer. This cannot be bypassed.
 */

import * as cheerio from 'cheerio';
import { renderPage } from '../browser/playwright-renderer.js';
import { sanitize } from '../sanitizer/index.js';
import type { VisusFetchStructuredInput, VisusFetchStructuredOutput, Result } from '../types.js';
import { Err } from '../types.js';

/**
 * Extract structured data from HTML using cheerio
 *
 * Phase 1: cheerio-based semantic HTML extraction
 * Phase 2+: LLM-powered extraction with Bedrock for complex schemas
 */
function extractStructuredData(
  html: string,
  schema: Record<string, string>
): Record<string, string | null> {
  const $ = cheerio.load(html);
  const extracted: Record<string, string | null> = {};

  for (const [fieldName, description] of Object.entries(schema)) {
    const descLower = description.toLowerCase();
    let value: string | null = null;

    // Pattern: main heading, title, h1
    if (descLower.includes('heading') || descLower.includes('title') || descLower.includes('h1')) {
      const h1 = $('h1').first().text().trim();
      if (h1) value = h1;
    }

    // Pattern: subheading, subtitle, h2, h3
    else if (descLower.includes('subheading') || descLower.includes('subtitle') || descLower.includes('h2') || descLower.includes('h3')) {
      const h2 = $('h2, h3').first().text().trim();
      if (h2) value = h2;
    }

    // Pattern: paragraph, body text, description
    else if (descLower.includes('paragraph') || descLower.includes('body') || descLower.includes('description')) {
      const p = $('p').first().text().trim();
      if (p) value = p;
    }

    // Pattern: link, url, href
    else if (descLower.includes('link') || descLower.includes('url') || descLower.includes('href')) {
      const link = $('a').first();
      const href = link.attr('href');
      if (href) value = href;
    }

    // Pattern: link text, anchor text
    else if (descLower.includes('link text') || descLower.includes('anchor')) {
      const linkText = $('a').first().text().trim();
      if (linkText) value = linkText;
    }

    // Pattern: page title (from <title> tag)
    else if (descLower.includes('page title') || descLower.includes('document title')) {
      const title = $('title').text().trim();
      if (title) value = title;
    }

    // Fallback: try to find text containing the field name
    else {
      const elements = $('*').filter((_, el) => {
        const text = $(el).text().toLowerCase();
        return text.includes(fieldName.toLowerCase()) || text.includes(descLower);
      });

      if (elements.length > 0) {
        value = $(elements.first()).text().trim();
      }
    }

    extracted[fieldName] = value;
  }

  return extracted;
}

/**
 * visus_fetch_structured tool implementation
 *
 * @param input Tool input parameters
 * @returns Extracted and sanitized structured data
 */
export async function visusFetchStructured(
  input: VisusFetchStructuredInput
): Promise<Result<VisusFetchStructuredOutput, Error>> {
  const { url, schema, timeout_ms = 10000 } = input;

  // Validate inputs
  if (!url || typeof url !== 'string') {
    return Err(new Error('Invalid input: url must be a non-empty string'));
  }

  if (!schema || typeof schema !== 'object' || Object.keys(schema).length === 0) {
    return Err(new Error('Invalid input: schema must be a non-empty object'));
  }

  try {
    // Step 1: Render the page (use default format to get HTML)
    const renderResult = await renderPage(url, {
      timeout_ms
    });

    if (!renderResult.ok) {
      return Err(renderResult.error);
    }

    const { title, html } = renderResult.value;

    // Step 2: Extract structured data from HTML using cheerio
    const extractedData = extractStructuredData(html, schema);

    // Step 3: CRITICAL - Sanitize each extracted field
    // This step CANNOT be skipped or bypassed
    const sanitizedData: Record<string, string | null> = {};
    const allPatternsDetected = new Set<string>();
    const allPIITypesRedacted = new Set<string>();
    let anyContentModified = false;

    for (const [fieldName, value] of Object.entries(extractedData)) {
      if (value === null) {
        sanitizedData[fieldName] = null;
        continue;
      }

      const sanitizationResult = sanitize(value);
      sanitizedData[fieldName] = sanitizationResult.content;

      // Collect all patterns detected across fields
      sanitizationResult.sanitization.patterns_detected.forEach(p =>
        allPatternsDetected.add(p)
      );
      sanitizationResult.sanitization.pii_types_redacted.forEach(p =>
        allPIITypesRedacted.add(p)
      );

      if (sanitizationResult.sanitization.content_modified) {
        anyContentModified = true;
      }
    }

    // Step 4: Build output
    const output: VisusFetchStructuredOutput = {
      url,
      data: sanitizedData,
      sanitization: {
        patterns_detected: Array.from(allPatternsDetected),
        pii_types_redacted: Array.from(allPIITypesRedacted),
        content_modified: anyContentModified
      },
      metadata: {
        title: title || 'Untitled',
        fetched_at: new Date().toISOString(),
        content_length_original: html.length,
        content_length_sanitized: Object.values(sanitizedData)
          .filter(v => v !== null)
          .join(' ')
          .length
      }
    };

    // Log to stderr if threats detected
    if (allPatternsDetected.size > 0) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        event: 'structured_extraction_threats',
        url,
        patterns: Array.from(allPatternsDetected),
        fields: Object.keys(schema)
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
export const visusFetchStructuredToolDefinition = {
  name: 'visus_fetch_structured',
  description: 'Fetch a web page and extract structured data according to a schema. All extracted fields are automatically sanitized for prompt injection and PII before being returned.',
  inputSchema: {
    type: 'object',
    properties: {
      url: {
        type: 'string',
        description: 'The URL to fetch (must be http:// or https://)'
      },
      schema: {
        type: 'object',
        description: 'Field extraction schema: { fieldName: "field description", ... }',
        additionalProperties: {
          type: 'string'
        }
      },
      timeout_ms: {
        type: 'number',
        description: 'Request timeout in milliseconds (default: 10000)',
        default: 10000
      }
    },
    required: ['url', 'schema']
  }
};
