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
import { truncateContent } from '../utils/truncate.js';
import { generateThreatReport } from '../sanitizer/threat-reporter.js';
import { ThreatDetector } from '../security/ThreatDetector.js';
import { computeThreatSummary } from '../security/threat-summary.js';
import { calculateMetrics, formatMetricsHeader, shouldShowMetrics } from '../utils/tokenMetrics.js';
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
import { detectCommandInjection, type DetectionResult } from '../security/command-guard.js';
import { validateToolDescriptor } from '../security/tool-validator.js';

// Add schema-specific validation and param guards
export async function visusFetchStructured(
  input: VisusFetchStructuredInput
): Promise<Result<VisusFetchStructuredOutput, Error>> {
  const startTime = Date.now();
  const { url, schema, timeout_ms = 10000 } = input;

// Validate inputs
  if (!url || typeof url !== 'string') {
    return Err(new Error('Invalid input: url must be a non-empty string'));
  }

  if (!schema || typeof schema !== 'object' || Object.keys(schema).length === 0) {
    return Err(new Error('Invalid input: schema must be a non-empty object'));
  }

  // Schema poisoning validation
  const schemaValidation = validateToolDescriptor({ 
    name: 'visus_fetch_structured', 
    inputSchema: input.schema 
  }, 'visus_fetch_structured');
  if (!schemaValidation.isValid) {
    console.error('[SECURITY] Schema poisoning detected in visus_fetch_structured:', schemaValidation.risks);
    return Err(new Error(`Schema validation failed (risks: ${schemaValidation.risks.length}). Blocked.`));
  }
  // Use sanitized schema if modified
  const sanitizedSchema = schemaValidation.sanitized.inputSchema || schema;
  const sanitizedInput = { ...input, schema: sanitizedSchema };

  // Param injection check on URL and schema stringified
  const paramsForScan = { 
    command: url, 
    args: [JSON.stringify(sanitizedSchema)], 
    env: {} 
  };
  const detection: DetectionResult = detectCommandInjection(paramsForScan);
  if (detection.totalScore > 5) {
    console.error('[SECURITY] Injection risk in structured fetch params:', detection);
    return Err(new Error(`Potential injection in structured input (score: ${detection.totalScore}). Blocked.`));
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

    // Type guard: fetch-structured only works with HTML (string), not binary content
    if (Buffer.isBuffer(html)) {
      return Err(new Error('fetch-structured does not support binary content types (PDFs, images). Use visus_fetch instead.'));
    }

    // Step 1.5: Run IPI threat detection on raw HTML BEFORE extraction
    const detector = new ThreatDetector();
    const threats = detector.scan(html, 'html');

    // Step 2: Extract structured data from HTML using cheerio
    const extractedData = extractStructuredData(html, schema);

    // Step 3: CRITICAL - Sanitize each extracted field (with allowlisting)
    // This step CANNOT be skipped or bypassed
    const sanitizedData: Record<string, string | null> = {};
    const allPatternsDetected = new Set<string>();
    const allPIITypesRedacted = new Set<string>();
    const allPIIAllowlisted: Array<{ type: string; value: string; reason: string }> = [];
    let anyContentModified = false;

    for (const [fieldName, value] of Object.entries(extractedData)) {
      if (value === null) {
        sanitizedData[fieldName] = null;
        continue;
      }

      const sanitizationResult = sanitize(value, url);
      sanitizedData[fieldName] = sanitizationResult.content;

      // Collect all patterns detected across fields
      sanitizationResult.sanitization.patterns_detected.forEach(p =>
        allPatternsDetected.add(p)
      );
      sanitizationResult.sanitization.pii_types_redacted.forEach(p =>
        allPIITypesRedacted.add(p)
      );
      allPIIAllowlisted.push(...sanitizationResult.sanitization.pii_allowlisted);

      if (sanitizationResult.sanitization.content_modified) {
        anyContentModified = true;
      }
    }

    // Step 4: Apply token ceiling truncation to combined data (AFTER sanitization)
    // Combine all field values to check total content size
    const combinedData = Object.entries(sanitizedData)
      .map(([key, value]) => `${key}: ${value || 'null'}`)
      .join('\n');

    const truncationResult = truncateContent(combinedData);

    // If truncated, we need to reconstruct sanitizedData from truncated content
    let finalData = sanitizedData;
    if (truncationResult.truncated) {
      // Parse truncated content back into fields
      // This is a simple approach - in production you might want more sophisticated handling
      const lines = truncationResult.content.split('\n');
      finalData = {};
      for (const line of lines) {
        if (line.includes(':')) {
          const [key, ...valueParts] = line.split(':');
          const value = valueParts.join(':').trim();
          if (key.trim() in sanitizedData) {
            finalData[key.trim()] = value === 'null' ? null : value;
          }
        }
      }
      // Preserve any missing fields as null
      for (const key of Object.keys(sanitizedData)) {
        if (!(key in finalData)) {
          finalData[key] = null;
        }
      }
    }

    // Step 5: Generate aggregated threat report
    const threatReport = generateThreatReport({
      patterns_detected: Array.from(allPatternsDetected),
      pii_redacted: Array.from(allPIITypesRedacted).length,
      source_url: url
    });

    // Step 5.5: Compute threat summary from IPI detections
    const threatSummary = computeThreatSummary(threats);

    // Step 5.6: Calculate metrics and create content representation with header
    const elapsedMs = Date.now() - startTime;
    const threatsBlocked = threats.length;

    // Create human-readable content representation
    let contentRepresentation: string | undefined = undefined;
    if (shouldShowMetrics()) {
      // Use the sanitized combined data for token calculation
      const sanitizedCombinedData = Object.entries(sanitizedData)
        .map(([key, value]) => `${key}: ${value || 'null'}`)
        .join('\n');

      const metrics = calculateMetrics(html, sanitizedCombinedData, threatsBlocked, elapsedMs);
      const metricsHeader = formatMetricsHeader(metrics);

      // Create formatted content with metrics header
      const formattedData = Object.entries(finalData)
        .map(([key, value]) => `**${key}**: ${value || 'null'}`)
        .join('\n');

      contentRepresentation = metricsHeader + formattedData;
    }

    // Step 6: Build output
    const output: VisusFetchStructuredOutput = {
      url,
      data: finalData,
      ...(contentRepresentation && { content: contentRepresentation }),
      sanitization: {
        patterns_detected: Array.from(allPatternsDetected),
        pii_types_redacted: Array.from(allPIITypesRedacted),
        pii_allowlisted: allPIIAllowlisted,
        content_modified: anyContentModified
      },
      metadata: {
        title: title || 'Untitled',
        fetched_at: new Date().toISOString(),
        content_length_original: html.length,
        content_length_sanitized: Object.values(sanitizedData)
          .filter(v => v !== null)
          .join(' ')
          .length,
        ...(truncationResult.truncated && {
          truncated: true,
          truncated_at_chars: truncationResult.truncated_at_chars
        })
      },
      // Include threat_report only if findings exist
      ...(threatReport && { threat_report: threatReport }),
      // Include threat_summary only if threats detected
      ...(threatSummary.threat_count > 0 && { threat_summary: threatSummary })
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
  title: 'Fetch Structured Data (Sanitized)',
  description: 'Fetch a web page and extract structured data according to a schema. SECURITY: All extracted fields pass through prompt injection sanitization (43 pattern categories) and PII redaction BEFORE being returned to the LLM. Each field is independently sanitized to ensure safe consumption of untrusted web content.',
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
  },
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true
};
