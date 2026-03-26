/**
 * DynamoDB Audit Logger for Visus-MCP
 * Activates the deployed but incomplete DynamoDB audit table.
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { createHash } from 'crypto';
import type {
  AuditLogRecord,
  RedactionRecord,
  LawfulBasis
} from './schema.js';
import {
  createAuditLogRecord,
  createSanitizationProof,
  createDataFlowRecord,
  createRedactionRecord
} from './schema.js';

// 90-day TTL in seconds (EU AI Act Code of Practice: retain audit records
// for minimum duration sufficient for conformity review)
export const AUDIT_TTL_SECONDS = 90 * 24 * 60 * 60;  // 7,776,000 seconds

/**
 * Details for building a RedactionRecord
 */
export interface RedactionDetail {
  category: string;
  pattern_id: string;
  original_length: number;
  replacement: string;
  risk_level?: 'low' | 'medium' | 'high' | 'critical';
  ai_act_article?: string;
  gdpr_article?: string;
}

/**
 * Writes structured audit records to DynamoDB with 90-day TTL.
 *
 * Designed for EU AI Act Art. 9 / Art. 13 / Art. 15 and GDPR Art. 30 / Art. 32
 * compliance documentation.
 *
 * Fail-open by default: if DynamoDB write fails, the MCP tool call still
 * returns its result. The error is logged to stderr for operational monitoring.
 * Deployers requiring fail-closed behaviour should set AUDIT_FAIL_CLOSED=true.
 */
export class AuditLogger {
  private tableName: string;
  private region: string;
  private failClosed: boolean;
  private enabled: boolean;
  private docClient: DynamoDBDocumentClient | null = null;

  constructor() {
    this.tableName = process.env.VISUS_AUDIT_TABLE || process.env.AUDIT_TABLE_NAME || 'visus-audit-log';
    this.region = process.env.AWS_REGION || 'us-east-1';
    this.failClosed = process.env.AUDIT_FAIL_CLOSED === 'true';
    this.enabled = process.env.VISUS_AUDIT_ENABLED !== 'false';
  }

  private getDocClient(): DynamoDBDocumentClient {
    if (!this.docClient) {
      const client = new DynamoDBClient({ region: this.region });
      this.docClient = DynamoDBDocumentClient.from(client);
    }
    return this.docClient;
  }

  /**
   * SHA-256(request_id + sorted_pattern_ids_joined + timestamp_utc)
   * Deterministic and verifiable without storing original content.
   */
  private computeProofHash(
    requestId: string,
    patternIds: string[],
    timestampUtc: string
  ): string {
    const payload = `${requestId}|${patternIds.sort().join(',')}|${timestampUtc}`;
    return createHash('sha256').update(payload, 'utf8').digest('hex');
  }

  /**
   * SHA-256 of content. Used for integrity verification, not reconstruction.
   */
  private computeContentHash(content: string): string {
    return createHash('sha256').update(content, 'utf8').digest('hex');
  }

  /**
   * Extract and hash domain for privacy-preserving audit records.
   */
  private anonymiseDomain(url: string): string {
    try {
      const { hostname } = new URL(url);
      const domainHash = createHash('sha256').update(hostname).digest('hex').substring(0, 16);
      return `domain:${domainHash}`;
    } catch {
      return 'domain:unknown';
    }
  }

  /**
   * Construct a complete AuditLogRecord from sanitization pipeline outputs.
   * Call this immediately after sanitization completes, before returning to MCP caller.
   */
  public buildRecord(params: {
    requestId: string;
    toolName: string;
    toolVersion: string;
    rawInput: string;
    sanitizedOutput: string;
    sourceUrl: string;
    patternsEvaluated: number;
    triggeredPatternIds: string[];
    redactionDetails: RedactionDetail[];
    processingDurationMs: number;
    success?: boolean;
    errorType?: string;
    lawfulBasis?: LawfulBasis;
    personalDataCategories?: string[];
    mcpServerVersion?: string;
    userId?: string;  // For Lambda mode
  }): AuditLogRecord {
    const {
      requestId,
      toolName,
      toolVersion,
      rawInput,
      sanitizedOutput,
      sourceUrl,
      patternsEvaluated,
      triggeredPatternIds,
      redactionDetails,
      processingDurationMs,
      success = true,
      errorType,
      lawfulBasis = 'legitimate_interests',
      personalDataCategories = [],
      mcpServerVersion = '1.0.0',
      userId
    } = params;

    const nowUtc = new Date().toISOString();
    const injectionDetected = triggeredPatternIds.length > 0;

    // Build sanitization proof
    const proof = createSanitizationProof(
      requestId,
      patternsEvaluated,
      triggeredPatternIds.length,
      injectionDetected,
      injectionDetected,
      this.computeContentHash(rawInput),
      this.computeContentHash(sanitizedOutput),
      this.computeProofHash(requestId, triggeredPatternIds, nowUtc),
      processingDurationMs,
      toolVersion
    );

    // Build data flow record
    const dataFlow = createDataFlowRecord(
      this.anonymiseDomain(sourceUrl),
      Buffer.byteLength(rawInput, 'utf8'),
      Buffer.byteLength(sanitizedOutput, 'utf8'),
      personalDataCategories,
      lawfulBasis
    );

    // Build per-redaction records
    const redactions: RedactionRecord[] = redactionDetails.map(r =>
      createRedactionRecord(
        r.category,
        r.pattern_id,
        r.original_length,
        r.replacement,
        r.risk_level || 'medium',
        r.ai_act_article || 'Art. 9 Risk Management',
        r.gdpr_article || 'Art. 5(1)(f) Integrity & Confidentiality'
      )
    );

    // Create base record
    const record = createAuditLogRecord(requestId, toolName, toolVersion, mcpServerVersion);

    // Add optional fields
    record.success = success;
    record.error_type = errorType;
    record.sanitization_proof = proof;
    record.data_flow = dataFlow;
    record.redactions = redactions;
    record.user_id = userId;

    // Add data protection by design article if PII was detected
    if (personalDataCategories.length > 0) {
      record.gdpr_articles_applicable.push('Art. 25 — Data Protection by Design');
    }

    return record;
  }

  /**
   * Write audit record to DynamoDB. Returns true on success, false on failure.
   * Never raises — failures are logged to stderr only (fail-open default).
   */
  public async write(record: AuditLogRecord): Promise<boolean> {
    if (!this.enabled) {
      return true;
    }

    try {
      // Convert to DynamoDB-compatible item
      const item: Record<string, any> = { ...record };

      // DynamoDB requires undefined values to be removed (not null)
      Object.keys(item).forEach(key => {
        if (item[key] === undefined) {
          delete item[key];
        }
      });

      await this.getDocClient().send(new PutCommand({
        TableName: this.tableName,
        Item: item,
        ConditionExpression: 'attribute_not_exists(record_id)'  // Prevent overwrites
      }));

      return true;

    } catch (err: any) {
      if (err.name === 'ConditionalCheckFailedException') {
        // Duplicate record_id — extremely unlikely with UUID4, log and continue
        console.error(JSON.stringify({
          timestamp: new Date().toISOString(),
          event: 'audit_duplicate_record',
          record_id: record.record_id
        }));
        return true;
      }

      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        event: 'audit_logging_failed',
        error: err.message || String(err),
        error_code: err.name || err.code,
        request_id: record.request_id
      }));

      if (this.failClosed) {
        throw err;
      }

      return false;
    }
  }

  /**
   * Synchronous write — use when not in async context.
   */
  public writeSync(record: AuditLogRecord): Promise<boolean> {
    return this.write(record);
  }

  /**
   * Fire-and-forget write (do not await result)
   */
  public writeFireAndForget(record: AuditLogRecord): void {
    this.write(record).catch(() => {
      // Already logged in write(), just suppress the unhandled promise rejection
    });
  }
}

// Module-level singleton
let _logger: AuditLogger | null = null;

/**
 * Get the singleton audit logger instance
 */
export function getLogger(): AuditLogger {
  if (!_logger) {
    _logger = new AuditLogger();
  }
  return _logger;
}
