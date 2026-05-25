import { createHash } from 'crypto';
import { canonicalJsonBytes } from './canonical-json.js';

/**
 * Computes SHA-256 of the canonical JSON representation of a value.
 * Returns hex string prefixed with "sha256:"
 */
export function contentHash(value: unknown): string {
  const bytes = canonicalJsonBytes(value);
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex');
}

/**
 * Verifies that a stored content_hash matches recomputed hash of value.
 * Throws if mismatch — never returns false silently.
 */
export function verifyContentHash(value: unknown, storedHash: string): void {
  const computed = contentHash(value);
  if (computed !== storedHash) {
    throw new Error(
      `Content hash mismatch. Stored: ${storedHash}. Computed: ${computed}`,
    );
  }
}
