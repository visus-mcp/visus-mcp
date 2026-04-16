/**
 * Unit tests for ImmutableLedger
 */

import { ImmutableLedger, type LedgerEvent } from '../../src/compliance/ImmutableLedger.js';
import { createHash } from 'crypto';
import fs from 'fs/promises';
import path from 'path';

describe('ImmutableLedger', () => {
  let ledger: ImmutableLedger;
  const testSessionId = 'test-session';
  const testPath = path.join(process.cwd(), 'test-audit');

  beforeEach(async () => {
    ledger = new ImmutableLedger();
    process.env.VISUS_LEDGER_PATH = testPath;
    await fs.mkdir(testPath, { recursive: true });
  });

  afterEach(async () => {
    await fs.rm(testPath, { recursive: true, force: true });
    process.env.VISUS_LEDGER_PATH = undefined;
  });

  test('should add event and generate Merkle root and proof', async () => {
    const event = {
      session_id: testSessionId,
      url: 'https://example.com',
      original_hash: 'abc123',
      sanitization_steps: ['strip_nav'],
      threats_detected: [],
      pii_redacted_count: 0,
      pii_types: [],
      cleaned_hash: 'def456',
      visus_proof: 'hmac-proof',
      human_review_flag: false,
      tool_name: 'visus_fetch'
    } as any;

    const { merkle_root, proof } = await ledger.addEvent(testSessionId, event);

    expect(merkle_root).toBeDefined();
    expect(proof.leaf).toBeDefined();
    expect(proof.siblings).toBeDefined();
    expect(proof.root).toBe(merkle_root);
  });

  test('should retrieve and verify proof', async () => {
    const rawEvent = {
      session_id: testSessionId,
      url: 'https://example.com',
      original_hash: createHash('sha256').update('raw content').digest('hex'),
      sanitization_steps: ['redact_pii'],
      threats_detected: [{ pattern_id: 'ipi_001', severity: 'LOW', snippet_hash: 'hash1' }],
      pii_redacted_count: 1,
      pii_types: ['email'],
      cleaned_hash: createHash('sha256').update('clean content').digest('hex'),
      visus_proof: 'test-hmac',
      human_review_flag: false,
      tool_name: 'visus_fetch'
    } as LedgerEvent;

    const result = await ledger.addEvent(testSessionId, rawEvent);
    const merkle_root = result.merkle_root;

    // Simulate getProof
    // Since in memory, assume it works
    // Full test would mock fs and tree

    // Verify proof (simplified)
    const retrieved = await ledger.getProof(rawEvent.request_id!);
    expect(retrieved).toBeDefined();
    expect(await ledger.verifyProof(retrieved.proof, retrieved)).toBe(true);
  });

  test('should purge old ledger files for retention', async () => {
    // Create old file
    const oldDate = new Date('2025-01-01').toISOString().split('T')[0];
    const oldFile = path.join(testPath, `ledger-${oldDate}.jsonl`);
    await fs.writeFile(oldFile, 'test line\n');

    // Set retention to 0 months (purge all)
    (ledger as any).retention_months = 0;

    await ledger.purgeOldLedgers();

    const exists = await fs.access(oldFile).then(() => true).catch(() => false);
    expect(exists).toBe(false);
  });
});
