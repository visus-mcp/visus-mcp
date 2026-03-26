/**
 * Unit tests for the audit logging system
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { createHash } from 'crypto';
import {
  createAuditLogRecord,
  createSanitizationProof,
  createRedactionRecord,
  createDataFlowRecord,
  toComplianceReportRow,
  type AuditLogRecord
} from '../src/audit/schema.js';
import { AuditLogger, AUDIT_TTL_SECONDS } from '../src/audit/logger.js';

describe('Audit Log Schema', () => {
  it('should create an audit log record with correct defaults', () => {
    const record = createAuditLogRecord('test-req-1', 'visus_fetch', '1.0.0');

    expect(record.record_id).toMatch(/^[0-9a-f-]{36}$/); // UUID format
    expect(record.request_id).toBe('test-req-1');
    expect(record.tool_name).toBe('visus_fetch');
    expect(record.tool_version).toBe('1.0.0');
    expect(record.success).toBe(true);
    expect(record.redactions).toEqual([]);
    expect(record.ai_act_controls_applied).toContain('Art. 9 — Risk Management');
    expect(record.gdpr_articles_applicable).toContain('Art. 32 — Security of Processing');
  });

  it('should set TTL to 90 days from now', () => {
    const record = createAuditLogRecord('test-req-2', 'visus_search', '1.0.0');
    const expectedTtl = Math.floor(Date.now() / 1000) + AUDIT_TTL_SECONDS;

    // Allow 5 second tolerance for test execution time
    expect(Math.abs(record.ttl - expectedTtl)).toBeLessThan(5);
  });

  it('should create a sanitization proof with deterministic proof hash', () => {
    const proof1 = createSanitizationProof(
      'req-123',
      43,
      2,
      true,
      true,
      'input_hash_1',
      'output_hash_1',
      'proof_hash_1',
      15
    );

    expect(proof1.request_id).toBe('req-123');
    expect(proof1.patterns_evaluated).toBe(43);
    expect(proof1.patterns_triggered).toBe(2);
    expect(proof1.injection_detected).toBe(true);
    expect(proof1.processing_duration_ms).toBe(15);
  });

  it('should create a redaction record with all fields', () => {
    const redaction = createRedactionRecord(
      'prompt_injection',
      'pattern_001',
      50,
      '[INJECTION_REMOVED]',
      'high'
    );

    expect(redaction.category).toBe('prompt_injection');
    expect(redaction.pattern_matched).toBe('pattern_001');
    expect(redaction.original_length).toBe(50);
    expect(redaction.risk_level).toBe('high');
  });

  it('should create a data flow record with GDPR compliance fields', () => {
    const dataFlow = createDataFlowRecord(
      'domain:12345678',
      1000,
      800,
      ['email', 'phone'],
      'legitimate_interests'
    );

    expect(dataFlow.source_type).toBe('external_url');
    expect(dataFlow.input_byte_size).toBe(1000);
    expect(dataFlow.output_byte_size).toBe(800);
    expect(dataFlow.personal_data_categories).toEqual(['email', 'phone']);
    expect(dataFlow.data_retained).toBe(false);
    expect(dataFlow.retention_seconds).toBe(0);
  });

  it('should convert audit record to compliance report row safely', () => {
    const record = createAuditLogRecord('export-test', 'visus_read', '1.0.0');
    const proof = createSanitizationProof(
      'export-test',
      43,
      3,
      true,
      true,
      'input_hash',
      'output_hash',
      'proof_hash_abc123',
      20
    );
    record.sanitization_proof = proof;

    const row = toComplianceReportRow(record);

    expect(row['Request ID']).toBe('export-test');
    expect(row['Tool']).toBe('visus_read');
    expect(row['Injection Detected']).toBe('Yes');
    expect(row['Patterns Triggered']).toBe('3');
    expect(row['Data Retained']).toBe('No');
    expect(row['Proof Hash']).toBe('proof_hash_abc123');
  });

  it('should not include raw content in compliance report', () => {
    const record = createAuditLogRecord('privacy-test', 'visus_fetch', '1.0.0');
    const row = toComplianceReportRow(record);

    const rowStr = JSON.stringify(row);
    expect(rowStr).not.toContain('sensitive');
    expect(rowStr).not.toContain('raw');
    expect(rowStr).not.toContain('content');
  });
});

describe('Audit Logger', () => {
  let logger: AuditLogger;

  beforeEach(() => {
    logger = new AuditLogger();
  });

  it('should compute content hash correctly (SHA-256)', () => {
    const content = 'test content for hashing';
    const expectedHash = createHash('sha256').update(content, 'utf8').digest('hex');

    // Access private method via any cast (for testing only)
    const actualHash = (logger as any).computeContentHash(content);

    expect(actualHash).toBe(expectedHash);
  });

  it('should compute deterministic proof hash', () => {
    const hash1 = (logger as any).computeProofHash('req-1', ['p1', 'p2'], '2025-01-01T00:00:00Z');
    const hash2 = (logger as any).computeProofHash('req-1', ['p2', 'p1'], '2025-01-01T00:00:00Z');

    // Proof hash should be order-independent (patterns are sorted)
    expect(hash1).toBe(hash2);
  });

  it('should compute different proof hashes for different requests', () => {
    const hash1 = (logger as any).computeProofHash('req-1', ['p1'], '2025-01-01T00:00:00Z');
    const hash2 = (logger as any).computeProofHash('req-2', ['p1'], '2025-01-01T00:00:00Z');

    expect(hash1).not.toBe(hash2);
  });

  it('should anonymise domain correctly', () => {
    const url = 'https://example.com/sensitive/path?q=secret';
    const anonymised = (logger as any).anonymiseDomain(url);

    expect(anonymised).toMatch(/^domain:[0-9a-f]{16}$/);
    expect(anonymised).not.toContain('example.com');
    expect(anonymised).not.toContain('sensitive');
    expect(anonymised).not.toContain('secret');
  });

  it('should build complete audit record with all sub-records', () => {
    const record = logger.buildRecord({
      requestId: 'build-test-1',
      toolName: 'visus_fetch',
      toolVersion: '1.0.0',
      rawInput: '<script>alert("xss")</script>Normal content',
      sanitizedOutput: '[INJECTION_REMOVED]Normal content',
      sourceUrl: 'https://example.com',
      patternsEvaluated: 43,
      triggeredPatternIds: ['pattern_001', 'pattern_007'],
      redactionDetails: [{
        category: 'prompt_injection',
        pattern_id: 'pattern_001',
        original_length: 30,
        replacement: '[INJECTION_REMOVED]',
        risk_level: 'high'
      }],
      processingDurationMs: 12
    });

    expect(record.request_id).toBe('build-test-1');
    expect(record.sanitization_proof).toBeDefined();
    expect(record.sanitization_proof?.injection_detected).toBe(true);
    expect(record.sanitization_proof?.patterns_triggered).toBe(2);
    expect(record.data_flow).toBeDefined();
    expect(record.data_flow?.data_retained).toBe(false);
    expect(record.redactions.length).toBe(1);
    expect(record.redactions[0].category).toBe('prompt_injection');
    expect(record.ttl).toBeGreaterThan(0);
  });

  it('should build audit record with no injections detected', () => {
    const record = logger.buildRecord({
      requestId: 'clean-test',
      toolName: 'visus_read',
      toolVersion: '1.0.0',
      rawInput: 'This is clean content with no attacks.',
      sanitizedOutput: 'This is clean content with no attacks.',
      sourceUrl: 'https://trusted-site.org',
      patternsEvaluated: 43,
      triggeredPatternIds: [],
      redactionDetails: [],
      processingDurationMs: 5
    });

    expect(record.sanitization_proof?.injection_detected).toBe(false);
    expect(record.sanitization_proof?.patterns_triggered).toBe(0);
    expect(record.redactions.length).toBe(0);
  });
});

describe('Audit Logging Integration', () => {
  it('should respect VISUS_AUDIT_ENABLED environment variable', () => {
    process.env.VISUS_AUDIT_ENABLED = 'false';
    const logger = new AuditLogger();
    expect((logger as any).enabled).toBe(false);

    process.env.VISUS_AUDIT_ENABLED = 'true';
    const logger2 = new AuditLogger();
    expect((logger2 as any).enabled).toBe(true);
  });

  it('should use correct table name from environment', () => {
    process.env.VISUS_AUDIT_TABLE = 'test-audit-table';
    const logger = new AuditLogger();
    expect((logger as any).tableName).toBe('test-audit-table');
  });

  it('should respect AUDIT_FAIL_CLOSED flag', () => {
    process.env.AUDIT_FAIL_CLOSED = 'true';
    const logger = new AuditLogger();
    expect((logger as any).failClosed).toBe(true);

    process.env.AUDIT_FAIL_CLOSED = 'false';
    const logger2 = new AuditLogger();
    expect((logger2 as any).failClosed).toBe(false);
  });
});
