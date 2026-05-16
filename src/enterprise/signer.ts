/**
 * Enterprise Integration Layer — HMAC Event Signing
 *
 * Every exported security event is HMAC-SHA256 signed for audit chain integrity.
 * The signing key is read from VISUS_SIEM_HMAC_KEY env var.
 * In production, this key should come from AWS Secrets Manager / KMS.
 *
 * Verification can be performed by the SIEM to confirm events originated
 * from a trusted Visus-MCP instance.
 */

import { createHmac, createHash } from 'crypto';
import type { SecurityEvent } from './types.js';

// In production, use AWS Secrets Manager. For development, default is fine
// for local testing but MUST be overridden in enterprise deployments.
function getHmacKey(): string {
  return process.env.VISUS_SIEM_HMAC_KEY || 'visus-dev-hmac-key';
}

/**
 * Compute HMAC-SHA256 over the canonical event payload.
 * Fields are sorted lexicographically to prevent field-ordering attacks.
 */
export function signEvent(event: Omit<SecurityEvent, 'signature'>): string {
  const canonical = canonicalize(event);
  return createHmac('sha256', getHmacKey())
    .update(canonical, 'utf8')
    .digest('hex');
}

/**
 * Verify an event's HMAC signature.
 */
export function verifyEventSignature(event: SecurityEvent): boolean {
  const { signature, ...rest } = event;
  const expected = signEvent(rest);
  // Constant-time comparison to prevent timing attacks
  if (signature.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < signature.length; i++) {
    diff |= signature.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Compute SHA-256 hash of a string payload.
 */
export function hashPayload(payload: string): string {
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * Canonicalize event fields to a deterministic JSON string for signing.
 * Only the essential identity fields are included — metadata is excluded
 * from the signature to allow SIEM enrichment without breaking the chain.
 */
function canonicalize(event: Omit<SecurityEvent, 'signature'>): string {
  const fields: Record<string, unknown> = {
    event_id: event.event_id,
    timestamp: event.timestamp,
    event_type: event.event_type,
    severity: event.severity,
    risk_score: event.risk_score,
    patterns: [...event.patterns].sort(),
    pii_types: [...event.pii_types].sort(),
    payload_hash: event.payload_hash,
    source: event.source,
    tool_name: event.tool_name,
    session_id: event.session_id,
  };
  return JSON.stringify(fields, Object.keys(fields).sort());
}