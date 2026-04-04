/**
 * Proof Builder
 *
 * Constructs complete SanitizationProofRecord from sanitization
 * pipeline outputs. Handles signing key lifecycle and chain management.
 */

import {
  computeInputHash,
  computeOutputHash,
  computeProofHash,
  computeProofSignature,
  computeChainHash,
  PROOF_SCHEMA_VERSION,
  SanitizationProofRecord,
} from "./primitives.js";
import type { ComplianceMetadata } from "../types.js";

// ─── Signing Key Management ───────────────────────────────────────────────────

const MINIMUM_KEY_LENGTH = 32;
const FALLBACK_KEY_WARNING_SHOWN = new Set<string>();

function getSigningKey(): string {
  const key = process.env.VISUS_HMAC_SECRET;

  if (!key) {
    const warningKey = "missing_key";
    if (!FALLBACK_KEY_WARNING_SHOWN.has(warningKey)) {
      console.error(
        "[VISUS CRYPTO] WARNING: VISUS_HMAC_SECRET not set. " +
        "Proof signatures are not cryptographically secure. " +
        "Set VISUS_HMAC_SECRET to a random 32+ byte hex string in production. " +
        "Generate one: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\""
      );
      FALLBACK_KEY_WARNING_SHOWN.add(warningKey);
    }
    // Deterministic fallback — proofs are internally consistent but not
    // signed with a secret. Acceptable for development, not production.
    return "visus-dev-fallback-key-not-for-production-use-00000000000000";
  }

  if (key.length < MINIMUM_KEY_LENGTH) {
    console.error(
      `[VISUS CRYPTO] WARNING: VISUS_HMAC_SECRET is only ${key.length} chars. ` +
      `Minimum recommended: ${MINIMUM_KEY_LENGTH}. Use: ` +
      "node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\""
    );
  }

  return key;
}

// ─── Chain State ──────────────────────────────────────────────────────────────

/**
 * In-memory chain tip. Resets on process restart.
 * For persistent chaining across restarts, persist to DynamoDB
 * and load on startup (see audit/logger.ts integration).
 */
let chainTip: string = "GENESIS";

export function getChainTip(): string {
  return chainTip;
}

export function setChainTip(proofHash: string): void {
  chainTip = proofHash;
}

// ─── Main Builder ─────────────────────────────────────────────────────────────

export interface BuildProofParams {
  /** MCP request ID — must be set before sanitization begins */
  requestId: string;
  /** ISO 8601 UTC timestamp — set at start of sanitization, not after */
  timestampUtc: string;
  /** Raw content before any processing */
  rawContent: string;
  /** Content after sanitization pipeline completed */
  sanitizedContent: string;
  /** Pattern IDs that fired (strings like "PI-001", not pattern text) */
  triggeredPatternIds: string[];
  /** Total number of patterns evaluated */
  patternsEvaluated: number;
  /** Whether sanitization was applied (may differ from injection detected) */
  sanitizationApplied: boolean;
  /** Sanitization library version */
  pipelineVersion: string;
  /** Processing duration */
  processingDurationMs: number;
  /** Number of distinct redactions applied */
  redactionCount: number;
  /** PII categories detected during processing */
  piiDetected?: string[];
  /** Number of threats neutralized (triggered patterns + redactions) */
  threatsNeutralized?: number;
}

export function buildProof(params: BuildProofParams): SanitizationProofRecord {
  const signingKey = getSigningKey();

  const inputHash = computeInputHash(params.rawContent);
  const outputHash = computeOutputHash(params.sanitizedContent);

  const proofHash = computeProofHash({
    requestId: params.requestId,
    inputHash,
    outputHash,
    triggeredPatternIds: params.triggeredPatternIds,
    patternsEvaluated: params.patternsEvaluated,
    timestampUtc: params.timestampUtc,
    pipelineVersion: params.pipelineVersion,
  });

  const proofSignature = computeProofSignature(proofHash, signingKey);
  const chainHash = computeChainHash(chainTip, proofHash);

  // Advance the chain
  chainTip = proofHash;

  // Build compliance metadata
  const complianceMetadata: ComplianceMetadata = {
    visus_version: params.pipelineVersion,
    sanitization_timestamp: params.timestampUtc,
    pii_detected: params.piiDetected || [],
    threats_neutralized: params.threatsNeutralized ??
      (params.triggeredPatternIds.length + params.redactionCount),
    framework_mappings: {
      eu_ai_act: ["Art.9", "Art.15"],
      nist_ai_rmf: ["GV-4.1-002", "MS-2.10-002"]
    },
    chain_of_custody: true // Always true when using chain_hash
  };

  return {
    schemaVersion: PROOF_SCHEMA_VERSION,
    requestId: params.requestId,
    timestampUtc: params.timestampUtc,
    inputHash,
    outputHash,
    proofHash,
    proofSignature,
    chainHash,
    patternsEvaluated: params.patternsEvaluated,
    triggeredPatternIds: params.triggeredPatternIds,
    injectionDetected: params.triggeredPatternIds.length > 0,
    sanitizationApplied: params.sanitizationApplied,
    pipelineVersion: params.pipelineVersion,
    processingDurationMs: params.processingDurationMs,
    inputByteSize: Buffer.byteLength(params.rawContent, "utf8"),
    outputByteSize: Buffer.byteLength(params.sanitizedContent, "utf8"),
    redactionCount: params.redactionCount,
    compliance_metadata: complianceMetadata,
  };
}

/**
 * Returns the public-safe proof header to include in every MCP tool response.
 * The proof_signature is intentionally excluded from public responses —
 * it requires the HMAC key to verify and is only for auditors.
 */
export function proofToResponseHeader(proof: SanitizationProofRecord): Record<string, unknown> {
  return {
    visus_proof: {
      request_id: proof.requestId,
      proof_hash: proof.proofHash,
      chain_hash: proof.chainHash,
      injection_detected: proof.injectionDetected,
      patterns_evaluated: proof.patternsEvaluated,
      patterns_triggered: proof.triggeredPatternIds.length,
      redactions: proof.redactionCount,
      sanitization_applied: proof.sanitizationApplied,
      timestamp_utc: proof.timestampUtc,
      pipeline_version: proof.pipelineVersion,
      schema_version: proof.schemaVersion,
      compliance_metadata: proof.compliance_metadata,
      verify_instruction:
        "Recompute proof_hash from disclosed fields per visus-mcp/CRYPTO-PROOF-SPEC.md",
    },
  };
}

/**
 * Export generateRequestId from primitives for convenience
 */
export { generateRequestId } from "./primitives.js";
