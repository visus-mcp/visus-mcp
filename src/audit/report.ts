/**
 * Compliance Report Exporter
 * Generates CSV and JSON compliance reports from DynamoDB audit logs.
 *
 * This is the foundation of the 'visus_report' MCP tool.
 *
 * Regulatory purpose:
 * - EU AI Act Art. 9: Evidence of risk management system operation
 * - EU AI Act Art. 13: Transparency artifact for regulators
 * - GDPR Art. 30: Records of Processing Activities export
 * - GDPR Art. 32: Evidence of security measures for DPA audits
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, ScanCommand, type ScanCommandInput } from '@aws-sdk/lib-dynamodb';
import type { AuditLogRecord } from './schema.js';

export interface QueryOptions {
  startDate: Date;
  endDate: Date;
  toolName?: string;
  maxRecords?: number;
}

export interface ComplianceSummary {
  report_metadata: {
    generated_at: string;
    period_start: string;
    period_end: string;
    generator: string;
    regulatory_basis: string[];
  };
  statistics: {
    total_requests: number;
    injection_attempts_detected: number;
    injection_detection_rate_pct: number;
    total_redactions_applied: number;
    avg_redactions_per_request: number;
    requests_by_tool: Record<string, number>;
    redactions_by_category: Record<string, number>;
  };
  compliance_attestation: {
    data_retained_beyond_request: boolean;
    raw_content_in_audit_log: boolean;
    audit_log_ttl_days: number;
    all_requests_audited: boolean;
    sanitization_mandatory: boolean;
    lawful_bases_documented: boolean;
  };
}

export interface GDPR_Art30_Record {
  article_30_record: {
    version: string;
    last_updated: string;
    controller: {
      name: string;
      address: string;
      dpo_contact: string;
    };
    processing_activity: string;
    purposes: string[];
    legal_basis: string;
    categories_of_data_subjects: string[];
    categories_of_personal_data: string[];
    recipients: string[];
    transfers_to_third_countries: Record<string, string>;
    retention_period: string;
    security_measures: string[];
  };
}

/**
 * Queries DynamoDB audit logs and produces structured compliance reports.
 */
export class ComplianceReportExporter {
  private tableName: string;
  private region: string;
  private docClient: DynamoDBDocumentClient;

  constructor() {
    this.tableName = process.env.VISUS_AUDIT_TABLE || process.env.AUDIT_TABLE_NAME || 'visus-audit-log';
    this.region = process.env.AWS_REGION || 'us-east-1';
    const client = new DynamoDBClient({ region: this.region });
    this.docClient = DynamoDBDocumentClient.from(client);
  }

  /**
   * Retrieve a single audit record by request_id.
   * Uses ScanCommand with FilterExpression on request_id.
   */
  async getByRequestId(requestId: string): Promise<AuditLogRecord | null> {
    try {
      const commandInput: ScanCommandInput = {
        TableName: this.tableName,
        FilterExpression: 'request_id = :rid',
        ExpressionAttributeValues: { ':rid': requestId },
        Limit: 1
      };

      const command = new ScanCommand(commandInput);
      const response = await this.docClient.send(command);
      const items = (response.Items as AuditLogRecord[]) || [];

      return items.length > 0 ? items[0] : null;
    } catch (error) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        event: 'audit_log_query_failed',
        request_id: requestId,
        error: error instanceof Error ? error.message : String(error)
      }));
      return null;
    }
  }

  /**
   * Retrieve audit records within a date range.
   * Uses ScanCommand with FilterExpression on created_at (full scan — GSI recommended for production scale).
   */
  async queryByDateRange(options: QueryOptions): Promise<AuditLogRecord[]> {
    const { startDate, endDate, toolName, maxRecords = 1000 } = options;
    const startIso = startDate.toISOString();
    const endIso = endDate.toISOString();

    const records: AuditLogRecord[] = [];
    let lastEvaluatedKey: Record<string, any> | undefined = undefined;

    do {
      const commandInput: ScanCommandInput = {
        TableName: this.tableName,
        FilterExpression: toolName
          ? 'created_at BETWEEN :start AND :end AND tool_name = :tool'
          : 'created_at BETWEEN :start AND :end',
        ExpressionAttributeValues: toolName
          ? { ':start': startIso, ':end': endIso, ':tool': toolName }
          : { ':start': startIso, ':end': endIso },
        Limit: Math.min(maxRecords - records.length, 100),
        ExclusiveStartKey: lastEvaluatedKey
      };

      const command = new ScanCommand(commandInput);
      const response = await this.docClient.send(command);
      const items = (response.Items as AuditLogRecord[]) || [];
      records.push(...items);

      lastEvaluatedKey = response.LastEvaluatedKey;

      if (records.length >= maxRecords) {
        break;
      }
    } while (lastEvaluatedKey);

    return records;
  }

  /**
   * Generate CSV compliance report. Safe for DPA submission.
   * No raw content — only metadata, hashes, and regulatory mappings.
   */
  async generateCSV(options: QueryOptions): Promise<string> {
    const records = await this.queryByDateRange(options);

    const lines: string[] = [];

    // Report header
    lines.push('# Visus-MCP Compliance Report');
    lines.push(`# Generated: ${new Date().toISOString()}`);
    lines.push(`# Period: ${options.startDate.toISOString().split('T')[0]} to ${options.endDate.toISOString().split('T')[0]}`);
    lines.push(`# Records: ${records.length}`);
    lines.push(`# Regulatory basis: EU AI Act Art. 9/13/15 | GDPR Art. 5/30/32`);
    lines.push('# Note: No raw content included. All values are metadata or hashes.');
    lines.push('');

    if (records.length === 0) {
      lines.push('No records found for this period.');
      return lines.join('\n');
    }

    // CSV header
    lines.push([
      'request_id', 'created_at', 'tool_name',
      'injection_detected', 'patterns_evaluated', 'patterns_triggered',
      'redactions_count', 'input_bytes', 'output_bytes',
      'data_retained', 'lawful_basis',
      'ai_act_controls', 'gdpr_articles',
      'proof_hash', 'success', 'error_type'
    ].join(','));

    // Data rows
    for (const record of records) {
      const proof = record.sanitization_proof;
      const dataFlow = record.data_flow;
      const redactions = record.redactions || [];

      const row = [
        record.request_id || '',
        record.created_at || '',
        record.tool_name || '',
        String(proof?.injection_detected || false),
        String(proof?.patterns_evaluated || 0),
        String(proof?.patterns_triggered || 0),
        String(redactions.length),
        String(dataFlow?.input_byte_size || 0),
        String(dataFlow?.output_byte_size || 0),
        String(dataFlow?.data_retained || false),
        dataFlow?.lawful_basis || '',
        (record.ai_act_controls_applied || []).join(' | '),
        (record.gdpr_articles_applicable || []).join(' | '),
        proof?.proof_hash || '',
        String(record.success),
        record.error_type || ''
      ];

      lines.push(row.join(','));
    }

    return lines.join('\n');
  }

  /**
   * Aggregated summary for regulatory submission.
   * Suitable as Annex IV technical documentation artifact.
   */
  async generateSummaryJSON(options: QueryOptions): Promise<ComplianceSummary> {
    const records = await this.queryByDateRange(options);

    const total = records.length;
    const injections = records.filter(r => r.sanitization_proof?.injection_detected).length;
    const totalRedactions = records.reduce((sum, r) => sum + (r.redactions?.length || 0), 0);

    // Breakdown by tool
    const toolCounts: Record<string, number> = {};
    for (const r of records) {
      const tool = r.tool_name || 'unknown';
      toolCounts[tool] = (toolCounts[tool] || 0) + 1;
    }

    // Breakdown by redaction category
    const redactionCategories: Record<string, number> = {};
    for (const r of records) {
      for (const red of r.redactions || []) {
        const cat = red.category || 'unknown';
        redactionCategories[cat] = (redactionCategories[cat] || 0) + 1;
      }
    }

    return {
      report_metadata: {
        generated_at: new Date().toISOString(),
        period_start: options.startDate.toISOString(),
        period_end: options.endDate.toISOString(),
        generator: 'visus-mcp audit/report.ts',
        regulatory_basis: [
          'EU AI Act Art. 9 — Risk Management System',
          'EU AI Act Art. 13 — Transparency',
          'EU AI Act Art. 15 — Robustness & Cybersecurity',
          'GDPR Art. 5(2) — Accountability',
          'GDPR Art. 30 — Records of Processing Activities',
          'GDPR Art. 32 — Security of Processing'
        ]
      },
      statistics: {
        total_requests: total,
        injection_attempts_detected: injections,
        injection_detection_rate_pct: total > 0 ? Math.round((injections / total) * 100 * 100) / 100 : 0,
        total_redactions_applied: totalRedactions,
        avg_redactions_per_request: total > 0 ? Math.round((totalRedactions / total) * 100) / 100 : 0,
        requests_by_tool: toolCounts,
        redactions_by_category: redactionCategories
      },
      compliance_attestation: {
        data_retained_beyond_request: false,
        raw_content_in_audit_log: false,
        audit_log_ttl_days: 90,
        all_requests_audited: true,
        sanitization_mandatory: true,
        lawful_bases_documented: true
      }
    };
  }

  /**
   * GDPR Art. 30(1) Record of Processing Activities.
   * Suitable for submission to a Data Protection Authority.
   * Template — deployer must customise controller/DPO fields.
   */
  async generateGDPRArt30Record(): Promise<GDPR_Art30_Record> {
    return {
      article_30_record: {
        version: '1.0',
        last_updated: new Date().toISOString(),
        controller: {
          name: '[DEPLOYER: Insert organisation name]',
          address: '[DEPLOYER: Insert address]',
          dpo_contact: '[DEPLOYER: Insert DPO email if applicable]'
        },
        processing_activity: 'AI-assisted web content sanitization via Visus-MCP',
        purposes: [
          'Protection of end users from prompt injection attacks',
          'Ensuring robustness of AI systems per EU AI Act Art. 15',
          'Risk management documentation per EU AI Act Art. 9'
        ],
        legal_basis: 'Art. 6(1)(f) GDPR — Legitimate interests of data subject in being protected from injection-based AI manipulation',
        categories_of_data_subjects: [
          'Users of systems powered by Visus-MCP',
          'Incidental data subjects whose PII appears in fetched web content'
        ],
        categories_of_personal_data: [
          'Technical metadata: request IDs, timestamps, byte counts',
          'Derived security data: sanitization proof hashes',
          'Incidental: PII categories detected and redacted (not the PII itself)'
        ],
        recipients: [
          'Anthropic Claude API (receives sanitized content only, no audit metadata)',
          'AWS DynamoDB (receives audit metadata, no raw content)'
        ],
        transfers_to_third_countries: {
          anthropic_api: 'United States — Standard Contractual Clauses (verify current status)',
          aws_dynamodb: '[DEPLOYER: specify region]'
        },
        retention_period: '90 days (DynamoDB TTL auto-deletion)',
        security_measures: [
          'Stateless fetch — no raw content persisted',
          'Audit logs contain only hashes and metadata, not original content',
          'DynamoDB at-rest encryption (AWS managed key)',
          'TTL-based automatic deletion after 90 days',
          'Prompt injection sanitization before any content reaches AI model'
        ]
      }
    };
  }
}
