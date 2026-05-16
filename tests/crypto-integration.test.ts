import { describe, it, expect, beforeAll } from '@jest/globals';
import { sanitizeWithProof } from '../src/sanitizer/index.js';
import { verifyProof } from '../src/crypto/primitives.js';

const MOCK_URL = 'https://example.com';
const MOCK_SECRET = 'test-hmac-secret-32-bytes-exactly-for-testing-1234';

describe('Crypto Integration Tests', () => {
  beforeAll(() => {
    process.env.VISUS_HMAC_SECRET = MOCK_SECRET;
  });

  it('should generate and verify proof in full sanitization pipeline', async () => {
    const result = await sanitizeWithProof('Some content with test injection', MOCK_URL);
    expect(result.proof).toBeDefined();
    expect(result.proof.proofHash).toBeDefined();
    const { valid } = verifyProof(result.proof, MOCK_SECRET);
    expect(valid).toBe(true);
  });

  it('should handle clean content without threats', async () => {
    const rawContent = 'This is clean benign content that should not trigger anything.';
    const result = await sanitizeWithProof(rawContent, MOCK_URL);
    expect(result.sanitization.content_modified).toBe(false);
    const { valid } = verifyProof(result.proof, MOCK_SECRET);
    expect(valid).toBe(true);
  });

  it('should fail verification on tampered proof', async () => {
    const result = await sanitizeWithProof('Clean content', MOCK_URL);
    const tampered = { ...result.proof, outputHash: '0000000000000000000000000000000000000000000000000000000000000000' };
    const { valid } = verifyProof(tampered, MOCK_SECRET);
    expect(valid).toBe(false);
  });

  it('should include proof in sanitizeWithProof output', async () => {
    const result = await sanitizeWithProof('test', MOCK_URL);
    expect(result).toHaveProperty('proof');
    expect(result.proof).toHaveProperty('proofHash');
  });
});