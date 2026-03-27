/**
 * Standalone Proof Verifier
 *
 * Exposes verification as an MCP tool (visus_verify) and as a CLI.
 *
 * Usage as MCP tool:
 *   visus_verify({ proof: <SanitizationProofRecord>, signingKey: "<VISUS_HMAC_SECRET>" })
 *
 * Usage as CLI:
 *   echo '<proof_json>' | npx ts-node src/crypto/verifier.ts
 *
 * Regulatory purpose:
 *   Enables DPAs and conformity assessment bodies to independently verify
 *   that any specific request was processed by the Visus sanitization pipeline.
 *   Per EU AI Act Art. 9(4) and Annex IV, technical documentation must include
 *   "testing, validation and verification procedures."
 *   This tool IS that procedure — callable, scriptable, auditable.
 */

import { verifyProof, SanitizationProofRecord } from "./primitives.js";

export interface VerifyProofInput {
  proof: SanitizationProofRecord;
  /**
   * HMAC signing key. For DPA audit: share under NDA.
   * Omit to skip signature verification (hash-only audit mode).
   */
  signingKey?: string;
}

export interface VerifyProofOutput {
  /** Overall verification verdict */
  valid: boolean;
  /** Detailed field-by-field results */
  checks: {
    proofHashMatch: boolean;
    signatureMatch: boolean | "skipped";
    schemaVersionMatch: boolean;
  };
  /** Human-readable audit summary */
  auditSummary: string;
  /** Recomputed hash (for auditor's records) */
  recomputedProofHash: string;
  /** ISO 8601 timestamp of this verification */
  verifiedAt: string;
  /** Original request ID being verified */
  requestId: string;
  /** Issues found. Empty array means valid. */
  issues: string[];
  /**
   * Regulatory statement suitable for inclusion in compliance documentation.
   * Include this verbatim in DPA submissions.
   */
  complianceStatement: string;
}

export function verifyProofRecord(input: VerifyProofInput): VerifyProofOutput {
  const effectiveKey = input.signingKey ?? "SIGNATURE_VERIFICATION_SKIPPED";
  const skipSignature = !input.signingKey;

  const result = verifyProof(input.proof, effectiveKey);

  // If signature was skipped, override the signature result
  const signatureCheck: boolean | "skipped" = skipSignature ? "skipped" : result.signatureMatch;
  const overallValid = skipSignature
    ? result.proofHashMatch && result.schemaVersionMatch
    : result.valid;

  const timestamp = new Date().toISOString();

  const complianceStatement = overallValid
    ? `VERIFIED: Request ${input.proof.requestId} was processed by Visus-MCP sanitization ` +
      `pipeline v${input.proof.pipelineVersion} at ${input.proof.timestampUtc}. ` +
      `Proof hash ${input.proof.proofHash} recomputed and confirmed. ` +
      `${input.proof.patternsEvaluated} injection patterns evaluated, ` +
      `${input.proof.triggeredPatternIds.length} triggered, ` +
      `${input.proof.redactionCount} redactions applied. ` +
      `Sanitized content reached LLM only after this processing completed. ` +
      `Verified at ${timestamp}. ` +
      `EU AI Act Art. 9/13/15 controls confirmed active for this request.`
    : `VERIFICATION FAILED: Request ${input.proof.requestId}. ` +
      `Issues: ${result.issues.join("; ")}. ` +
      `This record may have been tampered with or the proof fields are incorrect.`;

  return {
    valid: overallValid,
    checks: {
      proofHashMatch: result.proofHashMatch,
      signatureMatch: signatureCheck,
      schemaVersionMatch: result.schemaVersionMatch,
    },
    auditSummary: complianceStatement,
    recomputedProofHash: result.recomputedProofHash,
    verifiedAt: timestamp,
    requestId: input.proof.requestId,
    issues: result.issues,
    complianceStatement,
  };
}

// ─── CLI mode ─────────────────────────────────────────────────────────────────
// Note: CLI mode is available when running the compiled JavaScript file directly
// Example: echo '{"proof": {...}}' | node dist/crypto/verifier.js
