/**
 * visus_read_gsheet MCP Tool
 *
 * Reads and sanitizes a public Google Sheet. Accepts any standard Google Sheets
 * URL format and converts it to a CSV export endpoint. All cell content passes
 * through the IPI injection scanner before being returned.
 *
 * CRITICAL: ALL content MUST pass through the sanitizer. This cannot be bypassed.
 *
 * Pipeline order:
 * 1. Normalize Google Sheets URL to CSV export endpoint
 * 2. Fetch CSV from export endpoint
 * 3. Parse with papaparse (reuses visus_read_csv logic)
 * 4. IPI threat detection on flattened cell content
 * 5. Sanitization (injection detection + PII redaction)
 * 6. Token metrics header
 */

import Papa from 'papaparse';
import { sanitizeWithProof } from '../sanitizer/index.js';
import { ThreatDetector } from '../security/ThreatDetector.js';
import { computeThreatSummary } from '../security/threat-summary.js';
import { calculateMetrics, formatMetricsHeader, shouldShowMetrics } from '../utils/tokenMetrics.js';
import type { VisusReadGsheetInput, VisusReadGsheetOutput, Result } from '../types.js';
import { Err } from '../types.js';

/**
 * Extract spreadsheet ID and GID from various Google Sheets URL formats
 *
 * Supported formats:
 * - https://docs.google.com/spreadsheets/d/{ID}/edit#gid={GID}
 * - https://docs.google.com/spreadsheets/d/{ID}/edit
 * - https://docs.google.com/spreadsheets/d/{ID}
 *
 * @returns Object with spreadsheetId and gid, or error
 */
export function parseGsheetUrl(url: string): Result<{ spreadsheetId: string; gid: number }, Error> {
  const patterns = [
    /docs\.google\.com\/spreadsheets\/d\/([a-zA-Z0-9_-]+)(?:\/edit)?(?:#gid=(\d+))?/,
    /docs\.google\.com\/spreadsheets\/d\/([a-zA-Z0-9_-]+)\/edit#gid=(\d+)/,
  ];

  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return {
        ok: true,
        value: {
          spreadsheetId: match[1],
          gid: match[2] ? parseInt(match[2], 10) : 0,
        },
      };
    }
  }

  return Err(new Error('Invalid Google Sheets URL. Expected format: https://docs.google.com/spreadsheets/d/{ID}/...'));
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
 * visus_read_gsheet tool implementation
 *
 * @param input Tool input parameters
 * @returns Sanitized Google Sheet content with metadata
 */
export async function visusReadGsheet(input: VisusReadGsheetInput): Promise<Result<VisusReadGsheetOutput, Error>> {
  const startTime = Date.now();
  const { url, sheet_id, format = 'table' } = input;

  if (!url || typeof url !== 'string') {
    return Err(new Error('Invalid input: url must be a non-empty string'));
  }

  try {
    const parseResult = parseGsheetUrl(url);
    if (!parseResult.ok) {
      return Err(parseResult.error);
    }

    const { spreadsheetId, gid: urlGid } = parseResult.value;
    const gid = sheet_id !== undefined ? sheet_id : urlGid;

    const exportUrl = `https://docs.google.com/spreadsheets/d/${spreadsheetId}/export?format=csv&gid=${gid}`;

    let response: Response;
    try {
      response = await fetch(exportUrl);
    } catch (error) {
      return Err(error instanceof Error ? error : new Error(String(error)));
    }

    if (!response.ok) {
      return Err(new Error(`Failed to fetch Google Sheet: HTTP ${response.status} ${response.statusText}`));
    }

    const csvText = await response.text();

    const parseCsv = Papa.parse<Record<string, string>>(csvText, {
      header: true,
      skipEmptyLines: true,
      dynamicTyping: false,
    });

    if (parseCsv.errors.length > 0 && parseCsv.data.length === 0) {
      return Err(new Error(`CSV parse error: ${parseCsv.errors[0].message}`));
    }

    const rows = parseCsv.data;
    const headers = parseCsv.meta.fields ?? [];

    const flatContent = rows.map(row => Object.values(row).join(' | ')).join('\n');

    const detector = new ThreatDetector();
    const threats = detector.scan(flatContent, 'text');

    const sanitizationResult = await sanitizeWithProof(flatContent, url, 'visus_read_gsheet', '1.0.0');

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

    const output: VisusReadGsheetOutput = {
      url,
      content: finalContent,
      sanitization: {
        patterns_detected: sanitizationResult.sanitization.patterns_detected,
        pii_types_redacted: sanitizationResult.sanitization.pii_types_redacted,
        pii_allowlisted: sanitizationResult.sanitization.pii_allowlisted,
        content_modified: sanitizationResult.sanitization.content_modified,
      },
      metadata: {
        spreadsheet_id: spreadsheetId,
        gid,
        row_count: rows.length,
        column_count: headers.length,
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

export const visusReadGsheetToolDefinition = {
  name: 'visus_read_gsheet',
  title: 'Read Google Sheet (Sanitized)',
  description: 'Read and sanitize a public Google Sheet. Accepts any standard Google Sheets URL format and converts it to a CSV export. All cell content passes through the IPI injection scanner.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      url: {
        type: 'string',
        description: 'Google Sheets URL (any standard format)',
      },
      sheet_id: {
        type: 'number',
        description: 'Sheet GID (default: 0, first tab)',
        default: 0,
      },
      format: {
        type: 'string',
        enum: ['table', 'json'],
        description: 'Output format (default: "table")',
        default: 'table',
      },
    },
    required: ['url'] as const,
  },
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};
