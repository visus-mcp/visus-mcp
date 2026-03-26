/**
 * Visus-MCP Audit Log Schema
 * EU AI Act Art. 13 (Transparency) / Art. 9 (Risk Management)
 * GDPR Art. 5(2) (Accountability) / Art. 30 (Records of Processing)
 */

import { randomUUID } from 'crypto';

/**
 * GDPR Art. 6 lawful basis options
 */
export type LawfulBasis =
  | 'consent'                  // Art. 6(1)(a)
  | 'contract'                 // Art. 6(1)(b)
  | 'legal_obligation'         // Art. 6(1)(c)
  | 'vital_interests'          // Art. 6(1)(d)
  | 'public_task'              // Art. 6(1)(e)
  | 'legitimate_interests'     // Art. 6(1)(f)
  | 'not_applicable';          // No personal data processed

/**
 * GDPR Art. 30: Record of what was redacted and why.
 * AI Act Art. 9: Evidence of risk management measure applied.
 */
export interface RedactionRecord {
  redaction_id: string;                    // UUID
  category: string;                        // "prompt_injection" | "pii_email" | "pii_phone" | "pii_name" | "url" | "script_tag" | "encoded_payload"
  pattern_matched: string;                 // The specific pattern ID that triggered (not the raw content)
  original_length: number;                 // Length of removed content (not the content itself — data minimisation)
  replacement_token: string;               // What replaced it, e.g. "[INJECTION_REMOVED]", "[EMAIL_REDACTED]"
  ai_act_article: string;                  // e.g. "Art. 9 Risk Management" | "Art. 15 Robustness"
  gdpr_article: string;                    // e.g. "Art. 5(1)(c) Data Minimisation" | "Art. 5(1)(f) Integrity"
  risk_level: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * GDPR Art. 30(1)(d): Description of categories of data and recipients.
 * Records the data transformation chain for this request.
 */
export interface DataFlowRecord {
  source_type: string;                     // Always "external_url" for Visus
  source_domain: string;                   // Hashed or anonymised domain
  input_byte_size: number;                 // Raw content size before sanitization
  output_byte_size: number;                // Sanitized content size after processing
  forwarded_to: string;                    // The AI model that received sanitized content (e.g. "anthropic_claude")
  personal_data_categories: string[];      // ["email", "phone"] or []
  lawful_basis: LawfulBasis;
  lawful_basis_notes: string;
  data_retained: boolean;                  // Always false for stateless architecture
  retention_seconds: number;               // Always 0
}

/**
 * The cryptographically-linkable proof that sanitization ran for this request.
 * AI Act Art. 9 + Art. 15: Evidence that risk management and robustness controls executed.
 * GDPR Art. 32(1)(d): Evidence of regular testing and evaluation.
 *
 * The proof_hash is SHA-256(request_id + patterns_triggered_sorted + timestamp).
 * This allows audit verification without storing the original content.
 */
export interface SanitizationProof {
  proof_id: string;                        // UUID
  request_id: string;                      // Links to the MCP tool call
  timestamp_utc: string;                   // ISO 8601
  patterns_evaluated: number;              // Total patterns checked (e.g. 43)
  patterns_triggered: number;              // How many fired
  injection_detected: boolean;
  sanitization_applied: boolean;
  input_hash: string;                      // SHA-256 of raw input (for integrity, not reconstruction)
  output_hash: string;                     // SHA-256 of sanitized output
  proof_hash: string;                      // SHA-256(request_id + sorted_pattern_ids + timestamp_utc)
  pipeline_version: string;                // Sanitization library version
  processing_duration_ms: number;
}

/**
 * Master audit log record. One per MCP tool call.
 *
 * Regulatory basis:
 * - EU AI Act Art. 9: Risk Management System — documents that controls ran
 * - EU AI Act Art. 13: Transparency — machine-readable record of AI processing
 * - EU AI Act Art. 15: Robustness — proves sanitization executed before AI received content
 * - GDPR Art. 5(2): Accountability — controller can demonstrate compliance
 * - GDPR Art. 30: Records of Processing Activities
 * - GDPR Art. 32: Security of Processing — evidence of technical measures
 */
export interface AuditLogRecord {
  // Primary key fields (DynamoDB)
  record_id: string;                       // UUID
  request_id: string;                      // MCP request_id — the tracing key

  // Timestamps
  created_at: string;                      // ISO 8601
  ttl: number;                             // Unix epoch — auto-set to created_at + 90 days

  // Tool context
  tool_name: string;                       // e.g. "visus_fetch", "visus_search", "visus_read"
  tool_version: string;
  mcp_server_version: string;

  // User context (for Lambda mode)
  user_id?: string;                        // Cognito user ID (stdio mode: undefined)

  // Outcome
  success: boolean;
  error_type?: string;                     // Undefined if success

  // Sub-records
  sanitization_proof?: SanitizationProof;
  data_flow?: DataFlowRecord;
  redactions: RedactionRecord[];

  // Compliance metadata
  ai_act_controls_applied: string[];       // ["Art.9", "Art.15"]
  gdpr_articles_applicable: string[];      // ["Art.5(1)(c)", "Art.32"]
}

/**
 * Flat dict for PDF/CSV export. Safe for external disclosure.
 */
export interface ComplianceReportRow {
  'Request ID': string;
  'Timestamp (UTC)': string;
  'Tool': string;
  'Injection Detected': string;
  'Patterns Triggered': string;
  'Redactions Applied': string;
  'Input Size (bytes)': string;
  'Output Size (bytes)': string;
  'Data Retained': string;
  'Lawful Basis': string;
  'AI Act Controls': string;
  'GDPR Articles': string;
  'Proof Hash': string;
}

/**
 * Create a new RedactionRecord with sensible defaults
 */
export function createRedactionRecord(
  category: string,
  pattern_matched: string,
  original_length: number,
  replacement_token: string,
  risk_level: 'low' | 'medium' | 'high' | 'critical' = 'medium',
  ai_act_article = 'Art. 9 Risk Management',
  gdpr_article = 'Art. 5(1)(f) Integrity & Confidentiality'
): RedactionRecord {
  return {
    redaction_id: randomUUID(),
    category,
    pattern_matched,
    original_length,
    replacement_token,
    ai_act_article,
    gdpr_article,
    risk_level
  };
}

/**
 * Create a new DataFlowRecord with sensible defaults
 */
export function createDataFlowRecord(
  source_domain: string,
  input_byte_size: number,
  output_byte_size: number,
  personal_data_categories: string[] = [],
  lawful_basis: LawfulBasis = 'legitimate_interests'
): DataFlowRecord {
  return {
    source_type: 'external_url',
    source_domain,
    input_byte_size,
    output_byte_size,
    forwarded_to: 'anthropic_claude',
    personal_data_categories,
    lawful_basis,
    lawful_basis_notes: 'Visus processes web content on behalf of user to protect them from injection attacks. No data retained beyond request lifecycle.',
    data_retained: false,
    retention_seconds: 0
  };
}

/**
 * Create a new SanitizationProof with sensible defaults
 */
export function createSanitizationProof(
  request_id: string,
  patterns_evaluated: number,
  patterns_triggered: number,
  injection_detected: boolean,
  sanitization_applied: boolean,
  input_hash: string,
  output_hash: string,
  proof_hash: string,
  processing_duration_ms: number,
  pipeline_version = '1.0.0'
): SanitizationProof {
  return {
    proof_id: randomUUID(),
    request_id,
    timestamp_utc: new Date().toISOString(),
    patterns_evaluated,
    patterns_triggered,
    injection_detected,
    sanitization_applied,
    input_hash,
    output_hash,
    proof_hash,
    pipeline_version,
    processing_duration_ms
  };
}

/**
 * Create a new AuditLogRecord with sensible defaults
 */
export function createAuditLogRecord(
  request_id: string,
  tool_name: string,
  tool_version: string,
  mcp_server_version = '1.0.0'
): AuditLogRecord {
  const now = new Date();
  const ttl = Math.floor(now.getTime() / 1000) + (90 * 24 * 60 * 60); // 90 days from now

  return {
    record_id: randomUUID(),
    request_id,
    created_at: now.toISOString(),
    ttl,
    tool_name,
    tool_version,
    mcp_server_version,
    success: true,
    redactions: [],
    ai_act_controls_applied: [
      'Art. 9 — Risk Management',
      'Art. 13 — Transparency',
      'Art. 15 — Robustness'
    ],
    gdpr_articles_applicable: [
      'Art. 5(1)(c) — Data Minimisation',
      'Art. 5(1)(e) — Storage Limitation',
      'Art. 5(1)(f) — Integrity & Confidentiality',
      'Art. 5(2) — Accountability',
      'Art. 32 — Security of Processing'
    ]
  };
}

/**
 * Convert AuditLogRecord to compliance report row (safe for external disclosure)
 */
export function toComplianceReportRow(record: AuditLogRecord): ComplianceReportRow {
  return {
    'Request ID': record.request_id,
    'Timestamp (UTC)': record.created_at,
    'Tool': record.tool_name,
    'Injection Detected': record.sanitization_proof?.injection_detected ? 'Yes' : 'No',
    'Patterns Triggered': String(record.sanitization_proof?.patterns_triggered ?? 0),
    'Redactions Applied': String(record.redactions.length),
    'Input Size (bytes)': String(record.data_flow?.input_byte_size ?? 'N/A'),
    'Output Size (bytes)': String(record.data_flow?.output_byte_size ?? 'N/A'),
    'Data Retained': 'No',
    'Lawful Basis': record.data_flow?.lawful_basis ?? 'not_applicable',
    'AI Act Controls': record.ai_act_controls_applied.join(', '),
    'GDPR Articles': record.gdpr_articles_applicable.join(', '),
    'Proof Hash': record.sanitization_proof?.proof_hash ?? ''
  };
}
