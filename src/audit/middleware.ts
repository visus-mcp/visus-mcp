/**
 * Audit middleware: wraps the sanitization pipeline to produce audit records
 * for every MCP tool call.
 *
 * Integration pattern:
 *     import { audited_sanitize } from './audit/middleware.js';
 *     const { content, audit } = await audited_sanitize(requestId, url, rawContent, toolName);
 */

import { randomUUID } from 'crypto';
import { sanitize, type SanitizationResult } from '../sanitizer/index.js';
import { getLogger, type RedactionDetail } from './logger.js';
import type { AuditLogRecord, LawfulBasis } from './schema.js';

/**
 * Result of audited sanitization
 */
export interface AuditedSanitizationResult {
  content: string;
  audit_record: AuditLogRecord;
  sanitization_metadata: SanitizationResult['sanitization'];
  proof_hash: string;
  injections_blocked: number;
}

/**
 * Wraps the sanitization pipeline with full audit logging.
 *
 * Returns both sanitized_content and audit_record. The audit_record is written
 * to DynamoDB and also returned so callers can include the proof_hash in MCP tool responses.
 *
 * Usage in MCP tool handler:
 *     const { content, audit_record, proof_hash, injections_blocked } = await audited_sanitize({
 *       request_id: ctx.request_id,
 *       url: url,
 *       raw_content: fetched_html,
 *       tool_name: "visus_fetch",
 *     });
 *     // Include proof in response
 *     return {
 *       content: content,
 *       audit_proof: proof_hash,
 *       request_id: request_id,
 *       injections_blocked,
 *     };
 */
export async function audited_sanitize(params: {
  request_id?: string;
  url: string;
  raw_content: string;
  tool_name: string;
  tool_version?: string;
  lawful_basis?: LawfulBasis;
  user_id?: string;  // For Lambda mode
}): Promise<AuditedSanitizationResult> {
  const {
    request_id = randomUUID(),
    url,
    raw_content,
    tool_name,
    tool_version = '1.0.0',
    lawful_basis = 'legitimate_interests',
    user_id
  } = params;

  const logger = getLogger();
  const startMs = Date.now();

  // --- Run sanitization ---
  const result: SanitizationResult = sanitize(raw_content, url);

  const endMs = Date.now();
  const durationMs = endMs - startMs;

  // Extract redaction metadata from sanitization result
  const triggeredPatternIds = result.sanitization.patterns_detected;
  const patternsEvaluated = 43; // Total number of patterns in the pipeline

  // Build redaction details for audit record
  const redactionDetails: RedactionDetail[] = [];

  // Add injection redactions
  for (const patternName of triggeredPatternIds) {
    redactionDetails.push({
      category: 'prompt_injection',
      pattern_id: patternName,
      original_length: 0, // We don't track individual pattern lengths in current implementation
      replacement: '[INJECTION_REMOVED]',
      risk_level: getRiskLevelForPattern(patternName, result.metadata.detections_by_severity),
      ai_act_article: 'Art. 9 Risk Management',
      gdpr_article: 'Art. 5(1)(f) Integrity & Confidentiality'
    });
  }

  // Add PII redactions
  for (const piiType of result.sanitization.pii_types_redacted) {
    redactionDetails.push({
      category: `pii_${piiType}`,
      pattern_id: `pii_redactor_${piiType}`,
      original_length: 0, // We don't track individual PII lengths
      replacement: `[REDACTED:${piiType.toUpperCase()}]`,
      risk_level: 'medium',
      ai_act_article: 'Art. 15 Robustness',
      gdpr_article: 'Art. 5(1)(c) Data Minimisation'
    });
  }

  // Detect personal data categories (lightweight heuristic)
  const personalDataCategories = detectPIICategories(result.sanitization.pii_types_redacted);

  // --- Build and write audit record ---
  const record = logger.buildRecord({
    requestId: request_id,
    toolName: tool_name,
    toolVersion: tool_version,
    rawInput: raw_content,
    sanitizedOutput: result.content,
    sourceUrl: url,
    patternsEvaluated,
    triggeredPatternIds,
    redactionDetails,
    processingDurationMs: durationMs,
    lawfulBasis: lawful_basis,
    personalDataCategories,
    userId: user_id
  });

  // Fire-and-forget write to DynamoDB
  logger.writeFireAndForget(record);

  return {
    content: result.content,
    audit_record: record,
    sanitization_metadata: result.sanitization,
    proof_hash: record.sanitization_proof?.proof_hash || '',
    injections_blocked: triggeredPatternIds.length
  };
}

/**
 * Map redaction PII types to GDPR personal data categories
 */
function detectPIICategories(piiTypesRedacted: string[]): string[] {
  const categoryMap: Record<string, string> = {
    'email': 'email_address',
    'phone': 'phone_number',
    'name': 'personal_name',
    'ip': 'ip_address',
    'ssn': 'national_identifier',
    'credit_card': 'financial_data'
  };

  const found = new Set<string>();
  for (const piiType of piiTypesRedacted) {
    const category = categoryMap[piiType.toLowerCase()];
    if (category) {
      found.add(category);
    }
  }

  return Array.from(found);
}

/**
 * Determine risk level for a pattern based on severity detections
 */
function getRiskLevelForPattern(
  _patternName: string,
  detectionsBySeverity: { critical: number; high: number; medium: number; low: number }
): 'low' | 'medium' | 'high' | 'critical' {
  // Map patterns to risk levels based on the severity classifier
  // This is a simplified heuristic - in production you'd query the actual severity classifier

  if (detectionsBySeverity.critical > 0) {
    return 'critical';
  } else if (detectionsBySeverity.high > 0) {
    return 'high';
  } else if (detectionsBySeverity.medium > 0) {
    return 'medium';
  } else {
    return 'low';
  }
}
