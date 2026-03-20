/**
 * visus_fetch_structured MCP Tool
 *
 * Fetches a web page and extracts structured data according to a schema.
 * All extracted data is sanitized before being returned.
 *
 * CRITICAL: ALL content MUST pass through the sanitizer. This cannot be bypassed.
 */

import { renderPage } from '../browser/playwright-renderer.js';
import { sanitize } from '../sanitizer/index.js';
import type { VisusFetchStructuredInput, VisusFetchStructuredOutput, Result } from '../types.js';
import { Err } from '../types.js';

/**
 * Extract structured data from content based on schema
 *
 * Simple extraction: looks for schema field names/descriptions in content
 * Phase 1: Basic pattern matching
 * Phase 2+: LLM-powered extraction with Bedrock
 */
function extractStructuredData(
  content: string,
  schema: Record<string, string>
): Record<string, string | null> {
  const extracted: Record<string, string | null> = {};

  for (const [fieldName, description] of Object.entries(schema)) {
    // Simple extraction: look for patterns near field name or description
    const searchPattern = new RegExp(
      `(${fieldName}|${description})\\s*[:=]?\\s*([^\\n]+)`,
      'i'
    );

    const match = content.match(searchPattern);

    if (match && match[2]) {
      extracted[fieldName] = match[2].trim();
    } else {
      // Try to find any mention of the field
      const lines = content.split('\n');
      let found = false;

      for (const line of lines) {
        if (line.toLowerCase().includes(fieldName.toLowerCase()) ||
            line.toLowerCase().includes(description.toLowerCase())) {
          // Extract value after the field name
          const parts = line.split(/[:=]/);
          if (parts.length > 1) {
            extracted[fieldName] = parts.slice(1).join(':').trim();
            found = true;
            break;
          }
        }
      }

      if (!found) {
        extracted[fieldName] = null;
      }
    }
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
    // Step 1: Render the page
    const renderResult = await renderPage(url, {
      timeout_ms,
      format: 'text' // Use text for structured extraction
    });

    if (!renderResult.ok) {
      return Err(renderResult.error);
    }

    const { title, text } = renderResult.value;
    const rawContent = text || '';

    // Step 2: Extract structured data from raw content
    const extractedData = extractStructuredData(rawContent, schema);

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
        content_length_original: rawContent.length,
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
