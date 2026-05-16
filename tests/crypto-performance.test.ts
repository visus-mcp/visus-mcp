import { describe, it, expect, beforeAll } from '@jest/globals';
import { performance } from 'perf_hooks';
import { verifyProof } from '../src/crypto/primitives.js';
import { sanitizeWithProof } from '../src/sanitizer/index.js';

const MOCK_SECRET = 'test-hmac-secret-32-bytes-exactly-for-testing-1234';

describe('Crypto Performance and Compliance', () => {
  beforeAll(() => {
    process.env.VISUS_HMAC_SECRET = MOCK_SECRET;
  });

  describe('Performance', () => {
    it('should build proofs efficiently', async () => {
      const times: number[] = [];
      for (let i = 0; i < 100; i++) {
        const start = performance.now();
        await sanitizeWithProof('test content ' + i, 'test-url');
        times.push(performance.now() - start);
      }
      const avg = times.reduce((a, b) => a + b, 0) / times.length;
      expect(avg).toBeLessThan(100);
    });

    it('should verify proofs efficiently', async () => {
      const result = await sanitizeWithProof('test content', 'test-url');
      const start = performance.now();
      for (let i = 0; i < 100; i++) {
        verifyProof(result.proof, MOCK_SECRET);
      }
      const total = performance.now() - start;
      expect(total).toBeLessThan(1000);
    });

    it('should keep proof size <1KB', async () => {
      const result = await sanitizeWithProof('test content', 'test-url');
      const size = JSON.stringify(result.proof).length;
      expect(size).toBeLessThan(1024);
    });
  });

  describe('Compliance', () => {
    it('should produce verifiable proof', async () => {
      const result = await sanitizeWithProof('content with mappings', 'test-url');
      const { valid } = verifyProof(result.proof, MOCK_SECRET);
      expect(valid).toBe(true);
    });

    it('should have proof fields for audit trail', async () => {
      const result = await sanitizeWithProof('audit content', 'test-url');
      expect(result.proof).toHaveProperty('proofHash');
      expect(result.proof).toHaveProperty('proofSignature');
      expect(result.proof).toHaveProperty('timestampUtc');
      expect(result.proof).toHaveProperty('requestId');
      expect(result.proof).toHaveProperty('inputHash');
      expect(result.proof).toHaveProperty('outputHash');
    });
  });
});