import { describe, it, expect, beforeAll } from '@jest/globals';
import { verifyProof } from '../src/crypto/primitives.js';
import { sanitizeWithProof } from '../src/sanitizer/index.js';

const MOCK_SECRET = 'test-hmac-secret-32-bytes-exactly-for-testing-1234';

describe('Crypto Security Tests (Adversarial)', () => {
  beforeAll(() => {
    process.env.VISUS_HMAC_SECRET = MOCK_SECRET;
  });

  describe('Tampering Attacks', () => {
    it('should detect tampered content hash', async () => {
      const result = await sanitizeWithProof('test content', 'test-url');
      const verification = verifyProof(result.proof, MOCK_SECRET);
      expect(verification.valid).toBe(true);

      const tampered = { ...result.proof, outputHash: 'tampered_hash' };
      const tamperedVerification = verifyProof(tampered, MOCK_SECRET);
      expect(tamperedVerification.valid).toBe(false);
      expect(tamperedVerification.issues.length).toBeGreaterThan(0);
    });

    it('should detect forged proofSignature', async () => {
      const result = await sanitizeWithProof('clean content', 'test-url');
      const forgedProof = { ...result.proof, proofSignature: 'forged-signature' };
      const { valid, issues } = verifyProof(forgedProof, MOCK_SECRET);
      expect(valid).toBe(false);
      expect(issues).toEqual(expect.arrayContaining([expect.stringContaining('signature')]));
    });

    it('should reject proof schema version mismatch', async () => {
      const result = await sanitizeWithProof('timestamp sensitive', 'test-url');
      const badSchema = { ...result.proof, schemaVersion: '0.0.0' };
      const { valid } = verifyProof(badSchema, MOCK_SECRET);
      expect(valid).toBe(false);
    });
  });

  describe('Tamper Evidence', () => {
    it('should flag proofHash mismatch on content change', async () => {
      const result = await sanitizeWithProof('original content', 'test-url');
      // Changing a hash field: valid should be false
      const tampered = { ...result.proof, inputHash: '0000000000000000000000000000000000000000000000000000000000000000' };
      const { valid, proofHashMatch } = verifyProof(tampered, MOCK_SECRET);
      expect(valid).toBe(false);
      expect(proofHashMatch).toBe(false);
    });

    it('should detect signature change', async () => {
      const result = await sanitizeWithProof('clean content', 'test-url');
      const tampered = { ...result.proof, proofSignature: 'bad' };
      const { valid, signatureMatch } = verifyProof(tampered, MOCK_SECRET);
      expect(valid).toBe(false);
      expect(signatureMatch).toBe(false);
    });
  });

  describe('Fuzzing and Edge Cases', () => {
    it('should handle non-UTF8 content gracefully', async () => {
      const binaryContent = Buffer.from('binary \xFF data').toString('utf8');
      const result = await sanitizeWithProof(binaryContent, 'test-url');
      const { valid } = verifyProof(result.proof, MOCK_SECRET);
      expect(valid).toBe(true);
    });
  });
});