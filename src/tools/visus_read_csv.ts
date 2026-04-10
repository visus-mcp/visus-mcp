/**
 * visus_read_csv MCP Tool
 *
 * Reads and sanitizes a CSV or TSV file from a local path or URL.
 * All cell content passes through the IPI injection scanner before being returned.
 *
 * CRITICAL: ALL content MUST pass through the sanitizer. This cannot be bypassed.
 *
 * Pipeline order:
 * 1. Fetch file (local or remote)
 * 2. Parse CSV/TSV with papaparse
 * 3. IPI threat detection on flattened cell content
 * 4. Sanitization (injection detection + PII redaction)
 * 5. Token metrics header
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import Papa from 'papaparse';
import { sanitizeWithProof } from '../sanitizer/index.js';
import { ThreatDetector } from '../security/ThreatDetector.js';
import { computeThreatSummary } from '../security/threat-summary.js';
import { calculateMetrics, formatMetricsHeader, shouldShowMetrics } from '../utils/tokenMetrics.js';
import type { VisusReadCsvInput, VisusReadCsvOutput, Result } from '../types.js';
import { Err, Ok } from '../types.js';

/**
 * Fetch content from a local file path or remote URL
 */
async function fetchSource(source: string): Promise<Result<string, Error>> {
  if (/^https?:\/\//i.test(source)) {
    try {
      const response = await fetch(source);
      if (!response.ok) {
        return Err(new Error(`HTTP ${response.status}: ${response.statusText}`));
      }
      const text = await response.text();
      return Ok(text);
    } catch (error) {
      return Err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  try {
    const filePath = resolve(source);
    const content = await readFile(filePath, 'utf-8');
    return Ok(content);
  } catch (error) {
    return Err(error instanceof Error ? error : new Error(String(error)));
  }
}

/**
 * Format parsed rows as a markdown table
 */
function formatAsTable(rows: Record<string, string>[], headers: string[]): string {
  if (headers.length === 0) return '';

  const headerLine = `| ${headers.join(' | ')} |`;
  const separatorLine = `| ${headers.map(() => '---').join(' | ')} |`;
  const dataLines = rows.map(row =>
    `| ${headers.map(h => row[h] ?? '').join(' | ')} |`
  );

  return [headerLine, separatorLine, ...dataLines].join('\n');
}

/**
 * visus_read_csv tool implementation
 *
 * @param input Tool input parameters
 * @returns Sanitized CSV content with metadata
 */
export async function visusReadCsv(input: VisusReadCsvInput): Promise<Result<VisusReadCsvOutput, Error>> {
  const startTime = Date.now();
  const { source, format = 'table', delimiter } = input;

  if (!source || typeof source !== 'string') {
    return Err(new Error('Invalid input: source must be a non-empty string'));
  }

  try {
    const fetchResult = await fetchSource(source);
    if (!fetchResult.ok) {
      return Err(fetchResult.error);
    }

    const rawText = fetchResult.value;

    const parseResult = Papa.parse<Record<string, string>>(rawText, {
      header: true,
      skipEmptyLines: true,
      delimiter: delimiter === '\\t' ? '\t' : delimiter,
      dynamicTyping: false,
    });

    if (parseResult.errors.length > 0 && parseResult.data.length === 0) {
      return Err(new Error(`CSV parse error: ${parseResult.errors[0].message}`));
    }

    const rows = parseResult.data;
    const headers = parseResult.meta.fields ?? [];

    const flatContent = rows.map(row => Object.values(row).join(' | ')).join('\n');

    const detector = new ThreatDetector();
    const threats = detector.scan(flatContent, 'text');

    const sanitizationResult = await sanitizeWithProof(flatContent, source, 'visus_read_csv', '1.0.0');

    const rowCount = rows.length;
    const colCount = headers.length;

    let formattedContent: string;
    if (format === 'json') {
      formattedContent = JSON.stringify(rows, null, 2);
    } else {
      formattedContent = formatAsTable(rows, headers);
    }

    const threatSummary = computeThreatSummary(threats);

    const elapsedMs = Date.now() - startTime;
    const threatsBlocked = threats.length;

    let finalContent = formattedContent;
    if (shouldShowMetrics()) {
      const metrics = calculateMetrics(flatContent, sanitizationResult.content, threatsBlocked, elapsedMs);
      const metricsHeader = formatMetricsHeader(metrics);
      finalContent = metricsHeader + finalContent;
    }

    const output: VisusReadCsvOutput = {
      source,
      content: finalContent,
      sanitization: {
        patterns_detected: sanitizationResult.sanitization.patterns_detected,
        pii_types_redacted: sanitizationResult.sanitization.pii_types_redacted,
        pii_allowlisted: sanitizationResult.sanitization.pii_allowlisted,
        content_modified: sanitizationResult.sanitization.content_modified,
      },
      metadata: {
        row_count: rowCount,
        column_count: colCount,
        fetched_at: new Date().toISOString(),
        content_length_original: flatContent.length,
        content_length_sanitized: sanitizationResult.content.length,
      },
      ...(threatSummary.threat_count > 0 && { threat_summary: threatSummary }),
      ...sanitizationResult.proofHeader,
    };

    return { ok: true, value: output };

  } catch (error) {
    return Err(error instanceof Error ? error : new Error(String(error)));
  }
}

export const visusReadCsvToolDefinition = {
  name: 'visus_read_csv',
  title: 'Read CSV/TSV File (Sanitized)',
  description: 'Read and sanitize a CSV or TSV file from a local path or URL. All cell content passes through the IPI injection scanner before being returned.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      source: {
        type: 'string',
        description: 'Local file path or URL to .csv/.tsv file',
      },
      format: {
        type: 'string',
        enum: ['table', 'json'],
        description: 'Output format (default: "table")',
        default: 'table',
      },
      delimiter: {
        type: 'string',
        description: 'Column delimiter (default: auto-detect, use "\\t" for TSV)',
      },
    },
    required: ['source'] as const,
  },
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};

export { fetchSource, formatAsTable };
