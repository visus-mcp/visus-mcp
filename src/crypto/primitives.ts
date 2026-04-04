/**
 * Visus-MCP Cryptographic Primitives
 *
 * Uses Node.js built-in `crypto` module only.
 * Zero external dependencies — no supply chain risk.
 *
 * Regulatory basis:
 *   EU AI Act Art. 9  — Risk Management: tamper-evident proof controls ran
 *   EU AI Act Art. 13 — Transparency: independently verifiable records
 *   EU AI Act Art. 15 — Robustness: cryptographic integrity of pipeline
 *   GDPR Art. 5(2)    — Accountability: controller can prove compliance
 *   GDPR Art. 32      — Security: cryptographic measures for processing records
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";
import type { ComplianceMetadata } from "../types.js";

// ─── Constants ───────────────────────────────────────────────────────────────

/** SHA-256 output length in hex characters */
export const SHA256_HEX_LENGTH = 64;

/** HMAC-SHA-256 output length in hex characters */
export const HMAC_SHA256_HEX_LENGTH = 64;

/** Current proof schema version — increment on breaking changes */
export const PROOF_SCHEMA_VERSION = "1.0.0";

/** Separator used in hash inputs — chosen to be unambiguous */
const FIELD_SEPARATOR = "\x00|\x00";

// ─── Core Hash Functions ──────────────────────────────────────────────────────

/**
 * SHA-256 of arbitrary string input. Returns lowercase hex.
 * Used for content fingerprinting (input/output integrity).
 */
export function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * SHA-256 of a Buffer. Used when hashing binary content.
 */
export function sha256Buffer(input: Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/**
 * HMAC-SHA-256 using the pipeline signing key.
 * Used for proof_signature — proves the proof was issued by this pipeline,
 * not forged by an attacker who observed the proof_hash.
 *
 * Key source: VISUS_HMAC_SECRET env var (minimum 32 bytes recommended).
 * If not set, falls back to a deterministic but non-secret key with a warning.
 */
export function hmacSha256(data: string, key: string): string {
  return createHmac("sha256", key).update(data, "utf8").digest("hex");
}

/**
 * Timing-safe comparison of two hex strings.
 * Prevents timing attacks when validating proof signatures.
 */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufA = Buffer.from(a, "hex");
  const bufB = Buffer.from(b, "hex");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/**
 * Generate a cryptographically random request ID.
 * 16 bytes = 128-bit entropy = UUID4-equivalent uniqueness.
 */
export function generateRequestId(): string {
  return randomBytes(16).toString("hex");
}

// ─── Canonical Hash Construction ─────────────────────────────────────────────

/**
 * Canonical input hash — SHA-256 of the raw content before sanitization.
 *
 * This is NOT used to reconstruct content. It proves that the specific
 * input that was processed maps to this proof record.
 *
 * Format: SHA-256(raw_content_utf8)
 */
export function computeInputHash(rawContent: string): string {
  return sha256(rawContent);
}

/**
 * Canonical output hash — SHA-256 of sanitized content after processing.
 *
 * Format: SHA-256(sanitized_content_utf8)
 */
export function computeOutputHash(sanitizedContent: string): string {
  return sha256(sanitizedContent);
}

/**
 * Proof hash — the primary verifiable artifact.
 *
 * Binds together: request identity + what was detected + when + pipeline version.
 * Deterministic given the same inputs — two independent runs of the same
 * sanitization WILL produce the same proof_hash (reproducibility).
 *
 * Format: SHA-256(
 *   request_id  + SEP +
 *   input_hash  + SEP +
 *   output_hash + SEP +
 *   sorted(triggered_pattern_ids).join(",") + SEP +
 *   patterns_evaluated.toString() + SEP +
 *   timestamp_utc_iso8601 + SEP +
 *   pipeline_version
 * )
 *
 * Regulatory purpose:
 *   The proof_hash is the "traceability identifier" required by EU AI Act Art. 9(4)
 *   and the "technical documentation" artifact under Art. 11 / Annex IV.
 *   A conformity assessment body can recompute this hash from disclosed fields
 *   and verify it matches the stored record without seeing original content.
 */
export function computeProofHash(params: {
  requestId: string;
  inputHash: string;
  outputHash: string;
  triggeredPatternIds: string[];
  patternsEvaluated: number;
  timestampUtc: string;
  pipelineVersion: string;
}): string {
  const canonical = [
    params.requestId,
    params.inputHash,
    params.outputHash,
    [...params.triggeredPatternIds].sort().join(","),
    params.patternsEvaluated.toString(),
    params.timestampUtc,
    params.pipelineVersion,
  ].join(FIELD_SEPARATOR);

  return sha256(canonical);
}

/**
 * Proof signature — HMAC-SHA-256 over the proof_hash.
 *
 * Proves the proof was issued by a pipeline instance holding VISUS_HMAC_SECRET.
 * Without this, a passive observer who sees the proof_hash could forge a record
 * claiming sanitization ran when it didn't (by predicting the hash inputs).
 *
 * The signature is what allows a DPA to distinguish:
 *   "sanitization provably ran" vs "someone claims sanitization ran"
 *
 * Format: HMAC-SHA-256(proof_hash, VISUS_HMAC_SECRET)
 */
export function computeProofSignature(proofHash: string, signingKey: string): string {
  return hmacSha256(proofHash, signingKey);
}

/**
 * Chain hash — links this proof to the previous proof in the audit chain.
 *
 * Enables detection of deleted or reordered audit records.
 * Inspired by blockchain-style chaining but without the overhead.
 *
 * Format: SHA-256(previous_proof_hash + SEP + current_proof_hash)
 * First record in chain: SHA-256("GENESIS" + SEP + current_proof_hash)
 */
export function computeChainHash(
  previousProofHash: string | "GENESIS",
  currentProofHash: string
): string {
  return sha256(
    [previousProofHash, currentProofHash].join(FIELD_SEPARATOR)
  );
}

// ─── Verification ─────────────────────────────────────────────────────────────

/**
 * Verify a proof record without access to original content.
 *
 * A conformity assessment body or DPA can call this function with:
 *   - The disclosed proof fields (request_id, hashes, pattern counts, timestamp)
 *   - The VISUS_HMAC_SECRET (shared under NDA for audit purposes)
 *
 * Returns a structured verification result, not just a boolean, so the
 * auditor knows exactly which fields matched and which didn't.
 */
export function verifyProof(
  proof: SanitizationProofRecord,
  signingKey: string
): ProofVerificationResult {
  const recomputedProofHash = computeProofHash({
    requestId: proof.requestId,
    inputHash: proof.inputHash,
    outputHash: proof.outputHash,
    triggeredPatternIds: proof.triggeredPatternIds,
    patternsEvaluated: proof.patternsEvaluated,
    timestampUtc: proof.timestampUtc,
    pipelineVersion: proof.pipelineVersion,
  });

  const proofHashMatch = safeEqual(recomputedProofHash, proof.proofHash);

  const recomputedSignature = computeProofSignature(recomputedProofHash, signingKey);
  const signatureMatch = safeEqual(recomputedSignature, proof.proofSignature);

  const schemaVersionMatch = proof.schemaVersion === PROOF_SCHEMA_VERSION;

  return {
    valid: proofHashMatch && signatureMatch && schemaVersionMatch,
    proofHashMatch,
    signatureMatch,
    schemaVersionMatch,
    recomputedProofHash,
    storedProofHash: proof.proofHash,
    verifiedAt: new Date().toISOString(),
    requestId: proof.requestId,
    issues: [
      !proofHashMatch && "proof_hash mismatch — content or metadata may have been altered",
      !signatureMatch && "proof_signature mismatch — signing key incorrect or record forged",
      !schemaVersionMatch && `schema version mismatch: expected ${PROOF_SCHEMA_VERSION}, got ${proof.schemaVersion}`,
    ].filter(Boolean) as string[],
  };
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SanitizationProofRecord {
  /** Proof schema version — for forward compatibility */
  schemaVersion: string;

  /** MCP request identifier — links proof to tool call */
  requestId: string;

  /** ISO 8601 UTC timestamp of when sanitization completed */
  timestampUtc: string;

  /** SHA-256 of raw content before sanitization */
  inputHash: string;

  /** SHA-256 of sanitized content after processing */
  outputHash: string;

  /**
   * Primary verifiable artifact.
   * SHA-256 of canonical string binding all proof fields.
   * Recomputable by third parties from disclosed fields.
   */
  proofHash: string;

  /**
   * HMAC-SHA-256(proof_hash, VISUS_HMAC_SECRET).
   * Proves proof was issued by a pipeline holding the signing key.
   */
  proofSignature: string;

  /**
   * Links this proof to the previous proof (or "GENESIS").
   * Enables detection of deleted audit records.
   */
  chainHash: string;

  /** Total number of injection patterns evaluated */
  patternsEvaluated: number;

  /** IDs of patterns that fired (not their content) */
  triggeredPatternIds: string[];

  /** Whether any injection was detected */
  injectionDetected: boolean;

  /** Whether sanitization was applied (may be true without injection if encoding normalisation ran) */
  sanitizationApplied: boolean;

  /** Sanitization pipeline version */
  pipelineVersion: string;

  /** Processing duration in milliseconds */
  processingDurationMs: number;

  /** Byte size of input */
  inputByteSize: number;

  /** Byte size of output */
  outputByteSize: number;

  /** Number of redactions applied */
  redactionCount: number;

  /**
   * Extended compliance metadata for regulatory traceability.
   * EU AI Act Art. 9: Evidence of risk management controls
   * EU AI Act Art. 13: Transparency artifact
   * EU AI Act Art. 15: Robustness measures
   * NIST AI RMF: Control mappings for governance and security
   */
  compliance_metadata?: ComplianceMetadata;
}

export interface ProofVerificationResult {
  /** True only if ALL checks pass */
  valid: boolean;
  proofHashMatch: boolean;
  signatureMatch: boolean;
  schemaVersionMatch: boolean;
  recomputedProofHash: string;
  storedProofHash: string;
  verifiedAt: string;
  requestId: string;
  /** Human-readable list of failures. Empty if valid. */
  issues: string[];
}
