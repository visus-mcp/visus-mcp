/**
 * visus_verify MCP Tool
 *
 * Verifies a Visus-MCP sanitization proof record.
 * Confirms that a specific request was processed by the Visus injection
 * detection pipeline before content reached the LLM.
 *
 * Regulatory purpose: EU AI Act Art. 9/13 documentation and GDPR Art. 32
 * security evidence. Required for regulatory audit responses.
 */

import { verifyProofRecord, type VerifyProofInput, type VerifyProofOutput } from '../crypto/verifier.js';
import type { Result } from '../types.js';
import { Ok, Err } from '../types.js';

/**
 * visus_verify tool implementation
 *
 * @param input Proof record and optional signing key
 * @returns Verification result with compliance statement
 */
export async function visusVerify(input: VerifyProofInput): Promise<Result<VerifyProofOutput, Error>> {
  try {
    // Validate input
    if (!input.proof || typeof input.proof !== 'object') {
      return Err(new Error('Invalid input: proof must be an object'));
    }

    const result = await verifyProofRecord(input);

    return Ok(result);
  } catch (error) {
    return Err(error instanceof Error ? error : new Error(String(error)));
  }
}

/**
 * MCP tool definition for registration
 */
export const visusVerifyToolDefinition = {
  name: 'visus_verify',
  title: 'Verify Sanitization Proof',
  description: 'Verify a Visus-MCP sanitization proof record. Confirms that a specific request was processed by the Visus injection detection pipeline before content reached the LLM. Produces a compliance statement suitable for EU AI Act Art. 9/13 documentation and GDPR Art. 32 security evidence. Required for regulatory audit responses.',
  inputSchema: {
    type: 'object',
    properties: {
      proof: {
        type: 'object',
        description: 'The visus_proof object returned by any Visus tool call',
        required: true
      },
      signingKey: {
        type: 'string',
        description: 'VISUS_HMAC_SECRET value (optional — skip for hash-only verification). Required for full cryptographic proof. Share with auditors under NDA.',
        required: false
      }
    },
    required: ['proof']
  },
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
};
