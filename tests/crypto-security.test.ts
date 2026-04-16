import { describe, it, expect, beforeAll } from '@jest/globals';
import crypto from 'crypto';
import { buildProof, verifyProof } from '../../src/crypto/proof-builder.js';
import { sanitizeWithProof } from '../../src/sanitizer/index.js';
import { INJECTION_PAYLOADS } from '../injection-corpus.js';

describe('Crypto Security Tests (Adversarial)', () => {
  const mockSecret = 'test-hmac-secret-32-bytes-exactly-for-testing-1234';

  beforeAll(() => {
    process.env.VISUS_HMAC_SECRET = mockSecret;
  });

  describe('Tampering Attacks', () => {
    it('should detect tampered content hash', async () => {
      const rawContent = INJECTION_PAYLOADS[0].payload;
      const result = await sanitizeWithProof(rawContent, 'test-url');
      const tamperedContent = result.content + ' forged';
      const { valid, reason } = verifyProof(result.proof, tamperedContent, result.sanitization);
      expect(valid).toBe(false);
      expect(reason).toContain('hash mismatch');
    });

    it('should detect forged HMAC tag', async () => {
      const rawContent = 'clean content';
      const result = await sanitizeWithProof(rawContent, 'test-url');
      const forgedProof = { ...result.proof, hmacTag: 'forged-random-tag' };
      const { valid, reason } = verifyProof(forgedProof, result.content, result.sanitization);
      expect(valid).toBe(false);
      expect(reason).toContain('HMAC signature invalid');
    });

    it('should reject replayed old proof', async () => {
      const rawContent = 'timestamp sensitive';
      const result = await sanitizeWithProof(rawContent, 'test-url');
      const oldProof = { ...result.proof, timestampUtc: new Date(Date.now() - 2 * 3600000).toISOString() }; // 2 hours old
      const { valid, reason } = verifyProof(oldProof, result.content, result.sanitization);
      expect(valid).toBe(false);
      expect(reason).toContain('Proof expired');
    });
  });

  describe('Collision/Forgery Resistance', () => {
    it('should not allow hash collision with different inputs', async () => {
      const content1 = 'content1';
      const content2 = 'content2';
      const proof1 = buildProof({ sanitizedContent: content1, /* mocks */ });
      const { valid: valid2 } = verifyProof(proof1, content2, { /* mock */ });
      expect(valid2).toBe(false);
    });

    it('should error on short secret for HMAC', async () => {
      const shortSecret = 'short';
      delete process.env.VISUS_HMAC_SECRET;
      expect(() => verifyProof({ /* mock proof */ }, 'content', { /* meta */ }, shortSecret))
        .toThrow('Invalid or missing HMAC secret');
    });
  });

  describe('Fuzzing and Edge Cases', () => {
    it.each(INJECTION_PAYLOADS.slice(0, 10))('should verify proof for injection payload $name', async ({ payload }) => {
      const result = await sanitizeWithProof(payload, 'test-url');
      const { valid } = verifyProof(result.proof, result.content, result.sanitization);
      expect(valid).toBe(true);
    });

    it('should handle non-UTF8 content gracefully', async () => {
      const binaryContent = Buffer.from('binary \xFF data').toString('utf8');
      const result = await sanitizeWithProof(binaryContent, 'test-url');
      const { valid } = verifyProof(result.proof, result.content, result.sanitization);
      expect(valid).toBe(true); // Assumes UTF8 handling
    });
  });
});
