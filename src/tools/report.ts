/**
 * visus_report MCP Tool
 *
 * Generate compliance reports from Visus-MCP audit logs.
 * Required for EU AI Act Art. 13 transparency obligations and GDPR Art. 32 security documentation.
 */

import { ComplianceReportExporter } from '../audit/report.js';
import type { Result } from '../types.js';
import { Ok, Err } from '../types.js';

export interface VisusReportInput {
  report_type: 'summary_json' | 'csv' | 'gdpr_art30';
  days_back?: number;
  tool_filter?: 'visus_fetch' | 'visus_search' | 'visus_read' | 'all';
}

export interface VisusReportOutput {
  report: string;
  format: 'json' | 'csv';
  generated_at: string;
  period_days: number;
}

/**
 * visus_report tool implementation
 */
export async function visusReport(input: VisusReportInput): Promise<Result<VisusReportOutput, Error>> {
  const { report_type, days_back = 30, tool_filter = 'all' } = input;

  // Validate inputs
  if (days_back < 1 || days_back > 90) {
    return Err(new Error('days_back must be between 1 and 90'));
  }

  try {
    const exporter = new ComplianceReportExporter();
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days_back);

    const toolName = tool_filter === 'all' ? undefined : tool_filter;

    let reportContent: string;
    let format: 'json' | 'csv';

    switch (report_type) {
      case 'summary_json': {
        const summary = await exporter.generateSummaryJSON({ startDate, endDate, toolName, maxRecords: 1000 });
        reportContent = JSON.stringify(summary, null, 2);
        format = 'json';
        break;
      }

      case 'csv': {
        reportContent = await exporter.generateCSV({ startDate, endDate, toolName, maxRecords: 1000 });
        format = 'csv';
        break;
      }

      case 'gdpr_art30': {
        const art30 = await exporter.generateGDPRArt30Record();
        reportContent = JSON.stringify(art30, null, 2);
        format = 'json';
        break;
      }

      default:
        return Err(new Error(`Unknown report_type: ${report_type}`));
    }

    return Ok({
      report: reportContent,
      format,
      generated_at: new Date().toISOString(),
      period_days: days_back
    });

  } catch (error: any) {
    return Err(new Error(`Report generation failed: ${error.message}`));
  }
}

/**
 * MCP tool definition for visus_report
 */
export const visusReportToolDefinition = {
  name: 'visus_report',
  title: 'Generate Compliance Report',
  description: 'Generate a compliance report from Visus-MCP audit logs. Exports sanitization statistics, injection detection rates, and GDPR Art. 30 Records of Processing. Required for EU AI Act Art. 13 transparency obligations and GDPR Art. 32 security documentation.',
  inputSchema: {
    type: 'object',
    properties: {
      report_type: {
        type: 'string',
        enum: ['summary_json', 'csv', 'gdpr_art30'],
        description: 'Output format. summary_json: aggregated stats. csv: row-per-request export. gdpr_art30: Art. 30 Records of Processing template.',
        default: 'summary_json'
      },
      days_back: {
        type: 'number',
        description: 'Number of days to include in report (max 90, default 30)',
        default: 30,
        minimum: 1,
        maximum: 90
      },
      tool_filter: {
        type: 'string',
        description: 'Optional: filter by tool name',
        enum: ['visus_fetch', 'visus_search', 'visus_read', 'all'],
        default: 'all'
      }
    },
    required: []
  },
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false
  }
};
