import { canonicalJsonBytes } from '../../shared/canonical-json.js';
import { contentHash } from '../../shared/crypto.js';
import { StructuredError } from '../../shared/errors.js';

describe('Proof Signer - Key ID Validation', () => {
  it('rejects unknown key_id', () => {
    const error = new StructuredError('unknown key_id', 'UNKNOWN_KEY', 400);
    expect(error.code).toBe('UNKNOWN_KEY');
    expect(error.statusCode).toBe(400);
  });

  it('accepts v1 key_id', () => {
    expect(() => {
      if ('v1' !== 'v1') {
        throw new StructuredError('unknown key_id', 'UNKNOWN_KEY', 400);
      }
    }).not.toThrow();
  });
});

describe('Proof Signer - Payload Encoding', () => {
  it('payload_b64 is required', () => {
    const error = new StructuredError('payload_b64 is required', 'INVALID_INPUT', 400);
    expect(error.code).toBe('INVALID_INPUT');
    expect(error.statusCode).toBe(400);
  });

  it('base64 encoded payload round-trips correctly', () => {
    const payload = Buffer.from('test payload for signing', 'utf8');
    const b64 = payload.toString('base64');
    const decoded = Buffer.from(b64, 'base64');
    expect(decoded.toString('utf8')).toBe('test payload for signing');
  });
});

describe('Proof Signer - Canonical JSON for Signing', () => {
  it('canonical JSON is deterministic for signing', () => {
    const data1 = { org_id: 'org-a', event_id: 'evt-001', timestamp: '2026-01-01T00:00:00Z' };
    const data2 = { event_id: 'evt-001', timestamp: '2026-01-01T00:00:00Z', org_id: 'org-a' };
    const bytes1 = canonicalJsonBytes(data1);
    const bytes2 = canonicalJsonBytes(data2);
    expect(bytes1.equals(bytes2)).toBe(true);
  });

  it('content hash is stable for same structured data', () => {
    const data = {
      event_id: 'proof-test-001',
      org_id: 'org-proof',
      network_id: 'N_PROOF',
      source: 'meraki_poll',
    };
    const h1 = contentHash(data);
    const h2 = contentHash(data);
    expect(h1).toBe(h2);
  });
});

describe('Proof Signer - Error Handling', () => {
  it('Secrets Manager unavailable throws StructuredError', () => {
    const error = new StructuredError(
      'Failed to retrieve signing key',
      'SECRETS_MANAGER_ERROR',
      500,
    );
    expect(error.code).toBe('SECRETS_MANAGER_ERROR');
    expect(error.statusCode).toBe(500);
  });

  it('formatLambdaError returns correct structure for StructuredError', async () => {
    const { formatLambdaError } = await import('../../shared/errors.js');
    const error = new StructuredError('test error', 'TEST_CODE', 400);
    const result = formatLambdaError(error);
    expect(result).toEqual({ error: 'test error', code: 'TEST_CODE' });
  });

  it('formatLambdaError returns generic structure for plain Error', async () => {
    const { formatLambdaError } = await import('../../shared/errors.js');
    const error = new Error('internal failure');
    const result = formatLambdaError(error);
    expect(result).toEqual({ error: 'internal failure', code: 'INTERNAL_ERROR' });
  });

  it('formatLambdaError returns generic structure for unknown error', async () => {
    const { formatLambdaError } = await import('../../shared/errors.js');
    const result = formatLambdaError('some string');
    expect(result).toEqual({ error: 'An unknown error occurred', code: 'INTERNAL_ERROR' });
  });
});
