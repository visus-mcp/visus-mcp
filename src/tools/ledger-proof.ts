import { ImmutableLedger, type InclusionProof, type LedgerEvent } from '../compliance/ImmutableLedger.js';
import { randomUUID } from 'crypto';
import { createHash } from 'crypto';

/**
 * visus_get_ledger_proof MCP Tool
 *
 * Retrieves a tamper-evident proof for a specific request, including the event and Merkle inclusion proof.
 * For auditors and compliance verification (EU AI Act Art. 12).
 */

export async function visusGetLedgerProof(request_id: string): Promise<LedgerEvent & { proof: InclusionProof }> {
  const ledger = new ImmutableLedger();
  const proofEvent = await ledger.getProof(request_id);
  if (!proofEvent) {
    throw new Error(`No ledger event found for request_id: ${request_id}`);
  }
  return proofEvent;
}

export const visusGetLedgerProofToolDefinition = {
  name: 'visus_get_ledger_proof',
  title: 'Get Ledger Proof',
  description: 'Retrieve tamper-evident proof for a specific request ID, including event details and Merkle inclusion proof for audit verification.',
  inputSchema: {
    type: 'object',
    properties: {
      request_id: {
        type: 'string',
        description: 'The UUID of the request to retrieve proof for'
      }
    },
    required: ['request_id']
  },
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true
};
