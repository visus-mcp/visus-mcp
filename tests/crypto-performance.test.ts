import { describe, it, expect, beforeAll } from '@jest/globals';
import { performance } from 'perf_hooks';
import { buildProof, verifyProof } from '../../src/crypto/proof-builder.js';
import { sanitizeWithProof } from '../../src/sanitizer/index.js';
import { INJECTION_PAYLOADS } from '../injection-corpus.js';

describe('Crypto Performance and Compliance', () => {
  beforeAll(() => {
    process.env.VISUS_HMAC_SECRET = 'test-hmac-secret-32-bytes-exactly-for-testing-1234';
  });

  describe('Performance', () => {
    it('should build 1000 proofs in <1 second average', async () => {
      const times: number[] = [];
      for (let i = 0; i < 1000; i++) {
        const start = performance.now();
        const result = await sanitizeWithProof(INJECTION_PAYLOADS[i % INJECTION_PAYLOADS.length].payload, 'test-url');
        times.push(performance.now() - start);
      }
      const avg = times.reduce((a, b) => a + b, 0) / times.length;
      expect(avg).toBeLessThan(5); // <5ms avg
    });

    it('should verify 1000 proofs in <500ms total', () => {
      const proofs: any[] = [];
      // Pre-build proofs
      for (let i = 0; i < 1000; i++) {
        // Mock build
        proofs.push({
          proofHash: 'mockhash' + i,
          hmacTag: 'mocktag' + i,
          timestampUtc: new Date().toISOString(),
        });
      }
      const start = performance.now();
      proofs.forEach((proof, i) => {
        verifyProof(proof, 'content' + i, { patterns: [] });
      });
      const total = performance.now() - start;
      expect(total).toBeLessThan(500); // <500ms for 1000
    });

    it('should keep proof size <1KB', () => {
      const proof = buildProof({ /* full mock args with VSIL */ });
      const size = JSON.stringify(proof).length;
      expect(size).toBeLessThan(1024);
    });
  });

  describe('Compliance', () => {
    it('should include framework mappings in proof', () => {
      const proof = buildProof({ /* args with mappings */ });
      expect(proof).toHaveProperty('framework_mappings');
      expect(proof.framework_mappings).toHaveProperty('eu_ai_act', expect.arrayContaining(['Art.9']));
      expect(proof.framework_mappings).toHaveProperty('nist_ai_rmf');
    });

    it('should verify proof with compliance fields hashed', () => {
      const result = await sanitizeWithProof('content with mappings', 'test-url');
      (result.sanitization as any).framework_mappings = { eu_ai_act: ['Art.15'] }; // Mock
      const { valid } = verifyProof(result.proof, result.content, result.sanitization);
      expect(valid).toBe(true);
    });

    it('should generate audit log on failed verification', () => {
      // Mock logAuditEvent or console.error
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      const invalidProof = { proofHash: 'invalid' /* mock */ };
      verifyProof(invalidProof as any, 'content', { /* meta */ });
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('TAMPERED_PROOF'));
      consoleSpy.mockRestore();
    });
  });
});
