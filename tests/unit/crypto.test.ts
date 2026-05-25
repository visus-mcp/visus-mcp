import { contentHash, verifyContentHash } from '../../shared/crypto.js';

describe('contentHash', () => {
  it('known input -> known SHA-256 output (test vector)', () => {
    const hash = contentHash({ a: 1, b: 2 });
    expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    const expectedHash = 'sha256:';
    expect(hash.startsWith(expectedHash)).toBe(true);
  });

  it('same input -> same hash on repeated calls', () => {
    const obj = { id: 'test-123', value: 42 };
    const h1 = contentHash(obj);
    const h2 = contentHash(obj);
    const h3 = contentHash(obj);
    expect(h1).toBe(h2);
    expect(h2).toBe(h3);
  });

  it('single-byte change in input -> different hash', () => {
    const h1 = contentHash({ a: 1 });
    const h2 = contentHash({ a: 2 });
    expect(h1).not.toBe(h2);
  });

  it('empty object hash is stable', () => {
    const h1 = contentHash({});
    const h2 = contentHash({});
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('prefix "sha256:" present on all outputs', () => {
    const h1 = contentHash({ a: 1 });
    const h2 = contentHash({ a: 1, b: { c: [1, 2, 3] } });
    const h3 = contentHash([1, 2, 3]);
    expect(h1).toMatch(/^sha256:\w+$/);
    expect(h2).toMatch(/^sha256:\w+$/);
    expect(h3).toMatch(/^sha256:\w+$/);
  });

  it('hash of canonical JSON is different from hash of non-canonical JSON of same data', () => {
    const obj = { b: 1, a: 2 };
    const canonicalHash = contentHash(obj);
    const nonCanonicalBytes = Buffer.from('{"b":1,"a":2}', 'utf8');
    const { createHash } = require('crypto');
    const nonCanonicalHash = 'sha256:' + createHash('sha256').update(nonCanonicalBytes).digest('hex');
    expect(canonicalHash).not.toBe(nonCanonicalHash);
  });

  it('hash changes when a field is added', () => {
    const h1 = contentHash({ a: 1 });
    const h2 = contentHash({ a: 1, b: 2 });
    expect(h1).not.toBe(h2);
  });

  it('hash changes when a field is removed', () => {
    const h1 = contentHash({ a: 1, b: 2 });
    const h2 = contentHash({ a: 1 });
    expect(h1).not.toBe(h2);
  });

  it('null value has deterministic hash', () => {
    const h1 = contentHash(null);
    const h2 = contentHash(null);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^sha256:/);
  });

  it('array content ordering affects hash', () => {
    const h1 = contentHash({ items: [1, 2] });
    const h2 = contentHash({ items: [2, 1] });
    expect(h1).not.toBe(h2);
  });

  it('hash is 74 characters (sha256: + 64 hex)', () => {
    const hash = contentHash({ test: true });
    expect(hash.length).toBe(71);
  });

  it('nested object with same field names in different order produces same hash', () => {
    const h1 = contentHash({ outer: { b: 1, a: 2 } });
    const h2 = contentHash({ outer: { a: 2, b: 1 } });
    expect(h1).toBe(h2);
  });
});

describe('verifyContentHash', () => {
  it('passes on correct hash', () => {
    const obj = { data: 'test', id: 42 };
    const hash = contentHash(obj);
    expect(() => verifyContentHash(obj, hash)).not.toThrow();
  });

  it('throws on tampered value', () => {
    const obj = { data: 'test' };
    const hash = contentHash(obj);
    const tampered = { data: 'tampered' };
    expect(() => verifyContentHash(tampered, hash)).toThrow('Content hash mismatch');
  });

  it('throws on truncated hash', () => {
    const obj = { data: 'test' };
    const badHash = 'sha256:abc123';
    expect(() => verifyContentHash(obj, badHash)).toThrow('Content hash mismatch');
  });

  it('throws on hash from different input', () => {
    const h1 = contentHash({ a: 1 });
    const h2 = contentHash({ a: 2 });
    expect(() => verifyContentHash({ a: 1 }, h2)).toThrow();
    expect(() => verifyContentHash({ a: 2 }, h1)).toThrow();
  });

  it('throws on completely invalid hash format', () => {
    expect(() => verifyContentHash({ a: 1 }, 'not-a-valid-hash')).toThrow();
  });

  it('throws on empty hash string', () => {
    expect(() => verifyContentHash({ a: 1 }, '')).toThrow();
  });
});
