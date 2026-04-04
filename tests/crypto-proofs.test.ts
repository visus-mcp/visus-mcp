/**
 * Comprehensive Cryptographic Proof Test Suite
 *
 * Tests all aspects of the proof system:
 * - Primitives (hashing, HMAC, request ID generation)
 * - Proof construction
 * - Proof verification
 * - Chain integrity
 * - Test vector validation
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  sha256,
  hmacSha256,
  safeEqual,
  generateRequestId,
  computeProofHash,
  computeProofSignature,
  computeChainHash,
  verifyProof,
  PROOF_SCHEMA_VERSION,
  SHA256_HEX_LENGTH,
  type SanitizationProofRecord,
} from '../src/crypto/primitives.js';
import { buildProof, setChainTip, proofToResponseHeader } from '../src/crypto/proof-builder.js';
import { verifyProofRecord } from '../src/crypto/verifier.js';

const SIGNING_KEY = "test-signing-key-for-unit-tests-only-00000000000000";

beforeEach(() => {
  // Reset chain tip before each test
  setChainTip("GENESIS");
  // Set test signing key
  process.env.VISUS_HMAC_SECRET = SIGNING_KEY;
});

describe("Primitives", () => {
  it("sha256 produces 64-char lowercase hex", () => {
    const h = sha256("hello");
    expect(h.length).toBe(SHA256_HEX_LENGTH);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it("sha256 is deterministic", () => {
    expect(sha256("same")).toBe(sha256("same"));
  });

  it("sha256 differs for different inputs", () => {
    expect(sha256("a")).not.toBe(sha256("b"));
  });

  it("hmacSha256 produces 64-char hex", () => {
    const h = hmacSha256("data", "key");
    expect(h.length).toBe(64);
  });

  it("hmacSha256 differs with different keys", () => {
    expect(hmacSha256("data", "key1")).not.toBe(hmacSha256("data", "key2"));
  });

  it("safeEqual returns true for equal strings", () => {
    const h = sha256("test");
    expect(safeEqual(h, h)).toBe(true);
  });

  it("safeEqual returns false for different strings", () => {
    expect(safeEqual(sha256("a"), sha256("b"))).toBe(false);
  });

  it("safeEqual returns false for different lengths", () => {
    expect(safeEqual("abc", "abcd")).toBe(false);
  });

  it("generateRequestId produces 32-char hex", () => {
    const id = generateRequestId();
    expect(id.length).toBe(32);
    expect(id).toMatch(/^[0-9a-f]{32}$/);
  });

  it("generateRequestId is unique", () => {
    expect(generateRequestId()).not.toBe(generateRequestId());
  });
});

describe("Proof Hash", () => {
  const baseParams = {
    requestId: "req-abc",
    inputHash: sha256("raw"),
    outputHash: sha256("clean"),
    triggeredPatternIds: ["PI-001", "PI-007"],
    patternsEvaluated: 43,
    timestampUtc: "2026-03-28T00:00:00.000Z",
    pipelineVersion: "1.0.0",
  };

  it("produces 64-char hex", () => {
    const h = computeProofHash(baseParams);
    expect(h.length).toBe(64);
  });

  it("is deterministic", () => {
    expect(computeProofHash(baseParams)).toBe(computeProofHash(baseParams));
  });

  it("pattern order does not matter (sorted)", () => {
    const h1 = computeProofHash({ ...baseParams, triggeredPatternIds: ["PI-007", "PI-001"] });
    const h2 = computeProofHash({ ...baseParams, triggeredPatternIds: ["PI-001", "PI-007"] });
    expect(h1).toBe(h2);
  });

  it("changes when request_id changes", () => {
    const h1 = computeProofHash({ ...baseParams, requestId: "req-1" });
    const h2 = computeProofHash({ ...baseParams, requestId: "req-2" });
    expect(h1).not.toBe(h2);
  });

  it("changes when input_hash changes", () => {
    const h1 = computeProofHash({ ...baseParams, inputHash: sha256("content-a") });
    const h2 = computeProofHash({ ...baseParams, inputHash: sha256("content-b") });
    expect(h1).not.toBe(h2);
  });

  it("changes when timestamp changes", () => {
    const h1 = computeProofHash({ ...baseParams, timestampUtc: "2026-01-01T00:00:00Z" });
    const h2 = computeProofHash({ ...baseParams, timestampUtc: "2026-01-02T00:00:00Z" });
    expect(h1).not.toBe(h2);
  });

  it("changes when a new pattern is added", () => {
    const h1 = computeProofHash({ ...baseParams, triggeredPatternIds: ["PI-001"] });
    const h2 = computeProofHash({ ...baseParams, triggeredPatternIds: ["PI-001", "PI-999"] });
    expect(h1).not.toBe(h2);
  });
});

describe("Chain Hash", () => {
  it("GENESIS chain produces valid hash", () => {
    const h = computeChainHash("GENESIS", sha256("first-proof"));
    expect(h.length).toBe(64);
  });

  it("chain advances correctly", () => {
    const proof1 = sha256("proof-1");
    const proof2 = sha256("proof-2");
    const chain1 = computeChainHash("GENESIS", proof1);
    const chain2 = computeChainHash(proof1, proof2);
    expect(chain1).not.toBe(chain2);
  });

  it("reordering proofs changes chain hash", () => {
    const p1 = sha256("p1");
    const p2 = sha256("p2");
    const forward = computeChainHash(p1, p2);
    const reversed = computeChainHash(p2, p1);
    expect(forward).not.toBe(reversed);
  });
});

describe("Full Proof Build and Verify", () => {
  it("builds a complete proof", () => {
    const proof = buildProof({
      requestId: "test-build-001",
      timestampUtc: new Date().toISOString(),
      rawContent: "raw content with <script>attack</script>",
      sanitizedContent: "raw content with [INJECTION_REMOVED]",
      triggeredPatternIds: ["PI-001"],
      patternsEvaluated: 43,
      sanitizationApplied: true,
      pipelineVersion: "1.0.0",
      processingDurationMs: 7,
      redactionCount: 1,
    });

    expect(proof.schemaVersion).toBe(PROOF_SCHEMA_VERSION);
    expect(proof.proofHash.length).toBe(64);
    expect(proof.proofSignature.length).toBe(64);
    expect(proof.chainHash.length).toBe(64);
    expect(proof.injectionDetected).toBe(true);
    expect(proof.sanitizationApplied).toBe(true);
    expect(proof.redactionCount).toBe(1);
    expect(proof.inputByteSize).toBeGreaterThan(0);
    expect(proof.outputByteSize).toBeGreaterThan(0);
  });

  it("verifies a valid proof", () => {
    const proof = buildProof({
      requestId: "verify-test-001",
      timestampUtc: "2026-03-28T12:00:00.000Z",
      rawContent: "test input",
      sanitizedContent: "test input",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "1.0.0",
      processingDurationMs: 3,
      redactionCount: 0,
    });

    const result = verifyProof(proof, SIGNING_KEY);
    expect(result.valid).toBe(true);
    expect(result.proofHashMatch).toBe(true);
    expect(result.signatureMatch).toBe(true);
    expect(result.schemaVersionMatch).toBe(true);
    expect(result.issues.length).toBe(0);
  });

  it("rejects tampered proof_hash", () => {
    const proof = buildProof({
      requestId: "tamper-test-001",
      timestampUtc: "2026-03-28T12:00:00.000Z",
      rawContent: "legitimate content",
      sanitizedContent: "legitimate content",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "1.0.0",
      processingDurationMs: 2,
      redactionCount: 0,
    });

    const tampered: SanitizationProofRecord = { ...proof, proofHash: "a".repeat(64) };
    const result = verifyProof(tampered, SIGNING_KEY);
    expect(result.valid).toBe(false);
    expect(result.proofHashMatch).toBe(false);
  });

  it("rejects proof with wrong signing key", () => {
    const proof = buildProof({
      requestId: "wrong-key-test",
      timestampUtc: "2026-03-28T12:00:00.000Z",
      rawContent: "content",
      sanitizedContent: "content",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "1.0.0",
      processingDurationMs: 1,
      redactionCount: 0,
    });

    const result = verifyProof(proof, "wrong-key-00000000000000000000000000");
    expect(result.signatureMatch).toBe(false);
    expect(result.valid).toBe(false);
  });

  it("proof response header contains no proof_signature", () => {
    const proof = buildProof({
      requestId: "header-test",
      timestampUtc: new Date().toISOString(),
      rawContent: "r",
      sanitizedContent: "r",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "1.0.0",
      processingDurationMs: 1,
      redactionCount: 0,
    });
    const header = proofToResponseHeader(proof);
    const headerStr = JSON.stringify(header);
    expect(headerStr.includes("proof_signature")).toBe(false);
    expect(headerStr.includes(proof.proofHash)).toBe(true);
  });

  it("two sequential proofs have different chain hashes", () => {
    const p1 = buildProof({
      requestId: "chain-1",
      timestampUtc: new Date().toISOString(),
      rawContent: "a",
      sanitizedContent: "a",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "1.0.0",
      processingDurationMs: 1,
      redactionCount: 0,
    });
    const p2 = buildProof({
      requestId: "chain-2",
      timestampUtc: new Date().toISOString(),
      rawContent: "b",
      sanitizedContent: "b",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "1.0.0",
      processingDurationMs: 1,
      redactionCount: 0,
    });
    expect(p1.chainHash).not.toBe(p2.chainHash);
  });

  it("visus_verify produces compliance statement", async () => {
    const proof = buildProof({
      requestId: "compliance-stmt-test",
      timestampUtc: "2026-03-28T00:00:00.000Z",
      rawContent: "safe content",
      sanitizedContent: "safe content",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "1.0.0",
      processingDurationMs: 2,
      redactionCount: 0,
    });
    const result = await verifyProofRecord({ proof, signingKey: SIGNING_KEY });
    expect(result.valid).toBe(true);
    expect(result.complianceStatement.includes("VERIFIED")).toBe(true);
    expect(result.complianceStatement.includes("EU AI Act")).toBe(true);
  });

  it("hash-only verification without signing key", async () => {
    const proof = buildProof({
      requestId: "hash-only-test",
      timestampUtc: "2026-03-28T00:00:00.000Z",
      rawContent: "content",
      sanitizedContent: "content",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "1.0.0",
      processingDurationMs: 1,
      redactionCount: 0,
    });
    const result = await verifyProofRecord({ proof }); // No signing key
    expect(result.checks.signatureMatch).toBe("skipped");
    expect(result.checks.proofHashMatch).toBe(true);
  });

  it("handles partial proof object with missing audit record gracefully", async () => {
    // Simulate what users receive in tool responses (PublicProofObject)
    const partialProof = {
      request_id: "test-partial-proof-001",
      proof_hash: "a".repeat(64),
      chain_hash: "b".repeat(64),
      injection_detected: false,
      patterns_evaluated: 43,
      patterns_triggered: 0,
      redactions: 0,
      sanitization_applied: false,
      timestamp_utc: "2026-03-28T00:00:00.000Z",
      pipeline_version: "1.0.0",
      schema_version: "1.0.0",
    };

    // Verify without audit log access (should return structured error, not throw)
    const result = await verifyProofRecord({ proof: partialProof as any });

    // Should return a structured response, not throw
    expect(result).toBeDefined();
    expect(result.valid).toBe(false);
    expect(result.requestId).toBe("test-partial-proof-001");

    // Should include helpful error messages
    expect(result.issues).toContain("audit_record_not_found");
    expect(result.complianceStatement).toContain("VERIFICATION INCOMPLETE");
    expect(result.complianceStatement).toContain("complete audit record");

    // Should still validate basic fields
    expect(result.checks.schemaVersionMatch).toBe(true);
    expect(result.recomputedProofHash).toContain("N/A");
  });

  it("handles partial proof object with invalid schema version", async () => {
    const partialProof = {
      request_id: "test-invalid-schema",
      proof_hash: "a".repeat(64),
      chain_hash: "b".repeat(64),
      injection_detected: false,
      patterns_evaluated: 43,
      patterns_triggered: 0,
      redactions: 0,
      sanitization_applied: false,
      timestamp_utc: "2026-03-28T00:00:00.000Z",
      pipeline_version: "1.0.0",
      schema_version: "99.0.0", // Invalid schema version
    };

    const result = await verifyProofRecord({ proof: partialProof as any });

    expect(result.valid).toBe(false);
    expect(result.checks.schemaVersionMatch).toBe(false);
  });
});

describe("Test Vector Validation", () => {
  it("validates specification test vectors", () => {
    // From CRYPTO-PROOF-SPEC.md
    const inputHash = sha256("raw content");
    const outputHash = sha256("clean content");

    expect(inputHash).toBe("a6e5d15bf571ca7a23fd704caad6c4c071210ba8d38ea0296dc58c3ce0a0e514");
    expect(outputHash).toBe("573b1d8589d0623b86749785dae7a299483d140d551299578f0fcb30bdcece28");

    const proofHash = computeProofHash({
      requestId: "test-request-id-0000",
      inputHash,
      outputHash,
      triggeredPatternIds: ["PI-001", "PI-007"],
      patternsEvaluated: 43,
      timestampUtc: "2026-03-26T00:00:00.000Z",
      pipelineVersion: "1.0.0",
    });

    expect(proofHash).toBe("9cda5595b2f9865e1f1f50ac366a79daa488bd85db02551c20c3de22a65c902d");

    const proofSignature = computeProofSignature(
      proofHash,
      "test-signing-key-for-spec-vectors-only-000000"
    );

    expect(proofSignature).toBe("0d7a6102117ed1c6d5ceb8dcc132000f96ddf3d1c4a97bf18328063dded959b5");
  });
});

describe("Compliance Metadata", () => {
  it("includes compliance metadata in proof", () => {
    const proof = buildProof({
      requestId: "compliance-test-001",
      timestampUtc: "2026-03-28T12:00:00.000Z",
      rawContent: "test content with email@example.com",
      sanitizedContent: "test content with [REDACTED:EMAIL]",
      triggeredPatternIds: ["PI-001"],
      patternsEvaluated: 43,
      sanitizationApplied: true,
      pipelineVersion: "0.13.0",
      processingDurationMs: 5,
      redactionCount: 2,
      piiDetected: ["email"],
      threatsNeutralized: 2,
    });

    expect(proof.compliance_metadata).toBeDefined();
    expect(proof.compliance_metadata?.visus_version).toBe("0.13.0");
    expect(proof.compliance_metadata?.sanitization_timestamp).toBe("2026-03-28T12:00:00.000Z");
    expect(proof.compliance_metadata?.pii_detected).toEqual(["email"]);
    expect(proof.compliance_metadata?.threats_neutralized).toBe(2);
    expect(proof.compliance_metadata?.chain_of_custody).toBe(true);
  });

  it("includes EU AI Act framework mappings", () => {
    const proof = buildProof({
      requestId: "framework-test-001",
      timestampUtc: "2026-03-28T12:00:00.000Z",
      rawContent: "content",
      sanitizedContent: "content",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "0.13.0",
      processingDurationMs: 1,
      redactionCount: 0,
    });

    expect(proof.compliance_metadata?.framework_mappings.eu_ai_act).toContain("Art.9");
    expect(proof.compliance_metadata?.framework_mappings.eu_ai_act).toContain("Art.15");
  });

  it("includes NIST AI RMF framework mappings", () => {
    const proof = buildProof({
      requestId: "nist-test-001",
      timestampUtc: "2026-03-28T12:00:00.000Z",
      rawContent: "content",
      sanitizedContent: "content",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "0.13.0",
      processingDurationMs: 1,
      redactionCount: 0,
    });

    expect(proof.compliance_metadata?.framework_mappings.nist_ai_rmf).toContain("GV-4.1-002");
    expect(proof.compliance_metadata?.framework_mappings.nist_ai_rmf).toContain("MS-2.10-002");
  });

  it("compliance metadata is included in proof response header", () => {
    const proof = buildProof({
      requestId: "header-compliance-test",
      timestampUtc: "2026-03-28T12:00:00.000Z",
      rawContent: "test",
      sanitizedContent: "test",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "0.13.0",
      processingDurationMs: 1,
      redactionCount: 0,
      piiDetected: ["phone"],
      threatsNeutralized: 1,
    });

    const header = proofToResponseHeader(proof);
    expect(header.visus_proof).toHaveProperty("compliance_metadata");

    const metadata = (header.visus_proof as any).compliance_metadata;
    expect(metadata).toBeDefined();
    expect(metadata.pii_detected).toEqual(["phone"]);
    expect(metadata.threats_neutralized).toBe(1);
    expect(metadata.framework_mappings).toBeDefined();
  });

  it("calculates threats_neutralized correctly when not provided", () => {
    const proof = buildProof({
      requestId: "auto-threats-test",
      timestampUtc: "2026-03-28T12:00:00.000Z",
      rawContent: "content with injection",
      sanitizedContent: "content [REDACTED]",
      triggeredPatternIds: ["PI-001", "PI-002"],
      patternsEvaluated: 43,
      sanitizationApplied: true,
      pipelineVersion: "0.13.0",
      processingDurationMs: 3,
      redactionCount: 3, // 2 injections + 1 PII
    });

    // When threatsNeutralized not provided, should equal triggeredPatternIds.length + redactionCount
    expect(proof.compliance_metadata?.threats_neutralized).toBe(5); // 2 + 3
  });

  it("handles empty PII list", () => {
    const proof = buildProof({
      requestId: "no-pii-test",
      timestampUtc: "2026-03-28T12:00:00.000Z",
      rawContent: "clean content",
      sanitizedContent: "clean content",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "0.13.0",
      processingDurationMs: 1,
      redactionCount: 0,
    });

    expect(proof.compliance_metadata?.pii_detected).toEqual([]);
    expect(proof.compliance_metadata?.threats_neutralized).toBe(0);
  });

  it("verifyProofRecord handles compliance metadata in full proof", async () => {
    const proof = buildProof({
      requestId: "verify-compliance-test",
      timestampUtc: "2026-03-28T12:00:00.000Z",
      rawContent: "test",
      sanitizedContent: "test",
      triggeredPatternIds: [],
      patternsEvaluated: 43,
      sanitizationApplied: false,
      pipelineVersion: "0.13.0",
      processingDurationMs: 1,
      redactionCount: 0,
      piiDetected: ["email", "phone"],
      threatsNeutralized: 2,
    });

    const result = await verifyProofRecord({ proof, signingKey: SIGNING_KEY });
    expect(result.valid).toBe(true);

    // Compliance metadata should not affect verification
    expect(result.checks.proofHashMatch).toBe(true);
    expect(result.checks.signatureMatch).toBe(true);
  });
});
