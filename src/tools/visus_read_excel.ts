/**
 * visus_read_excel MCP Tool
 *
 * Reads and sanitizes an Excel workbook (.xlsx or .xls) from a local path or URL.
 * All cell content passes through the IPI injection scanner before being returned.
 *
 * CRITICAL: ALL content MUST pass through the sanitizer. This cannot be bypassed.
 *
 * Pipeline order:
 * 1. Fetch file (local or remote) as binary buffer
 * 2. Parse with SheetJS
 * 3. IPI threat detection on flattened cell content
 * 4. Sanitization (injection detection + PII redaction)
 * 5. Token metrics header
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import XLSX from 'xlsx';
import { sanitizeWithProof } from '../sanitizer/index.js';
import { ThreatDetector } from '../security/ThreatDetector.js';
import { computeThreatSummary } from '../security/threat-summary.js';
import { calculateMetrics, formatMetricsHeader, shouldShowMetrics } from '../utils/tokenMetrics.js';
import type { VisusReadExcelInput, VisusReadExcelOutput, Result } from '../types.js';
import { Err } from '../types.js';

/**
 * Fetch content as buffer from a local file path or remote URL
 */
async function fetchBuffer(source: string): Promise<Result<Buffer, Error>> {
  if (/^https?:\/\//i.test(source)) {
    try {
      const response = await fetch(source);
      if (!response.ok) {
        return Err(new Error(`HTTP ${response.status}: ${response.statusText}`));
      }
      const arrayBuffer = await response.arrayBuffer();
      return { ok: true, value: Buffer.from(arrayBuffer) };
    } catch (error) {
      return Err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  try {
    const filePath = resolve(source);
    const content = await readFile(filePath);
    return { ok: true, value: content };
  } catch (error) {
    return Err(error instanceof Error ? error : new Error(String(error)));
  }
}

/**
 * Format rows as a markdown table
 */
function rowsToMarkdownTable(rows: unknown[][], sheetName?: string): string {
  const parts: string[] = [];
  if (sheetName) {
    parts.push(`### ${sheetName}`);
    parts.push('');
  }

  if (rows.length === 0) {
    parts.push('(empty sheet)');
    return parts.join('\n');
  }

  const maxCols = Math.max(...rows.map(r => r.length));

  if (rows.length >= 1 && maxCols > 0) {
    const headerRow = rows[0].map(v => String(v ?? '')).map(v => v || '(empty)');
    const headerLine = `| ${headerRow.join(' | ')} |`;
    const separatorLine = `| ${headerRow.map(() => '---').join(' | ')} |`;

    const dataLines = rows.slice(1).map(row => {
      const cells = Array.from({ length: maxCols }, (_, i) => String(row[i] ?? ''));
      return `| ${cells.join(' | ')} |`;
    });

    parts.push(headerLine);
    parts.push(separatorLine);
    parts.push(...dataLines);
  }

  return parts.join('\n');
}

/**
 * visus_read_excel tool implementation
 *
 * @param input Tool input parameters
 * @returns Sanitized Excel content with metadata
 */
export async function visusReadExcel(input: VisusReadExcelInput): Promise<Result<VisusReadExcelOutput, Error>> {
  const startTime = Date.now();
  const { source, sheet, format = 'table' } = input;

  if (!source || typeof source !== 'string') {
    return Err(new Error('Invalid input: source must be a non-empty string'));
  }

  try {
    const fetchResult = await fetchBuffer(source);
    if (!fetchResult.ok) {
      return Err(fetchResult.error);
    }

    const buffer = fetchResult.value;
    const workbook = XLSX.read(buffer, { type: 'buffer' });

    let targetSheetNames: string[];
    if (sheet !== undefined) {
      if (typeof sheet === 'number') {
        if (sheet < 0 || sheet >= workbook.SheetNames.length) {
          return Err(new Error(`Sheet index ${sheet} out of range (workbook has ${workbook.SheetNames.length} sheets)`));
        }
        targetSheetNames = [workbook.SheetNames[sheet]];
      } else {
        if (!workbook.SheetNames.includes(sheet)) {
          return Err(new Error(`Sheet "${sheet}" not found. Available: ${workbook.SheetNames.join(', ')}`));
        }
        targetSheetNames = [sheet];
      }
    } else {
      targetSheetNames = workbook.SheetNames;
    }

    const allCellValues: string[] = [];
    const sheetData: Array<{
      name: string;
      rows: unknown[][];
      rowCount: number;
      colCount: number;
    }> = [];

    for (const sheetName of targetSheetNames) {
      const worksheet = workbook.Sheets[sheetName];
      const rows: unknown[][] = XLSX.utils.sheet_to_json(worksheet, { header: 1, defval: '' });

      const rowCount = rows.length;
      const colCount = rows.length > 0 ? Math.max(...rows.map(r => r.length)) : 0;

      sheetData.push({ name: sheetName, rows, rowCount, colCount });

      for (const row of rows) {
        for (const cell of row) {
          const val = String(cell ?? '');
          if (val) allCellValues.push(val);
        }
      }
    }

    const flatContent = allCellValues.join('\n');

    const detector = new ThreatDetector();
    const threats = detector.scan(flatContent, 'text');

    const sanitizationResult = await sanitizeWithProof(flatContent, source, 'visus_read_excel', '1.0.0');

    let formattedContent: string;
    if (format === 'json') {
      const jsonData: Record<string, unknown[]> = {};
      for (const sd of sheetData) {
        const headers = sd.rows[0]?.map((v, i) => String(v ?? `col_${i}`)) ?? [];
        const dataRows = sd.rows.slice(1).map(row => {
          const obj: Record<string, unknown> = {};
          headers.forEach((h, i) => {
            obj[h] = row[i] ?? '';
          });
          return obj;
        });
        jsonData[sd.name] = dataRows;
      }
      formattedContent = JSON.stringify(jsonData, null, 2);
    } else {
      const parts: string[] = [];
      for (const sd of sheetData) {
        parts.push(rowsToMarkdownTable(sd.rows, targetSheetNames.length > 1 ? sd.name : undefined));
        parts.push('');
      }
      formattedContent = parts.join('\n').trim();
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

    const output: VisusReadExcelOutput = {
      source,
      content: finalContent,
      sanitization: {
        patterns_detected: sanitizationResult.sanitization.patterns_detected,
        pii_types_redacted: sanitizationResult.sanitization.pii_types_redacted,
        pii_allowlisted: sanitizationResult.sanitization.pii_allowlisted,
        content_modified: sanitizationResult.sanitization.content_modified,
      },
      metadata: {
        sheet_count: targetSheetNames.length,
        sheets: sheetData.map(sd => ({
          name: sd.name,
          row_count: sd.rowCount,
          column_count: sd.colCount,
        })),
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

export const visusReadExcelToolDefinition = {
  name: 'visus_read_excel',
  title: 'Read Excel Workbook (Sanitized)',
  description: 'Read and sanitize an Excel workbook (.xlsx or .xls) from a local path or URL. All cell content passes through the IPI injection scanner before being returned.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      source: {
        type: 'string',
        description: 'Local file path or URL to .xlsx/.xls file',
      },
      sheet: {
        description: 'Sheet name or 0-based index (default: all sheets)',
        oneOf: [{ type: 'string' }, { type: 'number' }],
      },
      format: {
        type: 'string',
        enum: ['table', 'json'],
        description: 'Output format (default: "table")',
        default: 'table',
      },
    },
    required: ['source'] as const,
  },
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};

export { fetchBuffer, rowsToMarkdownTable };
