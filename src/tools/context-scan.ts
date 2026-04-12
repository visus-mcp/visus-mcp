/**
 * visus_context_scan Tool
 * Standalone tool to scan provided history for multi-turn priming risks.
 * Call manually before high-risk tools (visus_fetch, visus_search) if stateful concerns.
 * Integrates with local JSON cache for session persistence.
 */

import crypto from 'crypto';
import type { CallToolRequestHandler } from '@modelcontextprotocol/sdk/types.js';

import { cacheManager } from '../state/local-cache.js';
import { scanContext } from '../security/stateful-detector.js';
import type { ContextScanInput, ContextScanOutput } from '../types.js';
import { runElicitation } from '../sanitizer/elicit-runner.js';

/**
 * Tool definition
 */
export const visusContextScanToolDefinition = {
  name: 'visus_context_scan',
  description: `
Detect multi-turn priming risks in conversation history (e.g., "save this URL from Page 1" used in Page 2 tool call). 
Scans for stateful chaining attacks. Use before visus_fetch/visus_search when suspicious.

Provides risk score (0-1), primed entities (hashed URLs/IPs/tools), and threats. 
High risk (>0.7) triggers HITL confirmation. Persists primed hashes in local session cache.

Input history should include last 5-10 messages. priorExtractions optional (from prior visus tools).
  `,
  strict: true,
  inputSchema: {
    type: 'object',
    properties: {
      sessionId: { 
        type: 'string', 
        description: 'Session ID for cache persistence (auto-generated if missing)' 
      },
      history: { 
        type: 'array', 
        items: { type: 'string' }, 
        minItems: 1,
        description: 'Conversation history (last 5-10 messages recommended)' 
      },
      priorExtractions: { 
        type: 'array', 
        description: 'Prior visus_fetch/search/read outputs (metadata only, 3-5 recommended)' 
      },
      currentTool: { 
        type: 'string', 
        enum: ['visus_fetch', 'visus_search', 'visus_read'], 
        description: 'Current tool call for cross-reference (required)' 
      }
    },
    required: ['history', 'currentTool'],
    additionalProperties: false
  },
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false  // Internal analysis
} as const;

/**
 * visus_context_scan implementation
 */
export const visusContextScan: CallToolRequestHandler = async (request) => {
  const args = request.params.arguments as ContextScanInput & { sessionId?: string };

  // Input validation (schema enforced, but extra checks)
  if (!Array.isArray(args.history) || args.history.length === 0) {
    return { content: [{ type: 'text', text: 'Error: history required and must be non-empty array' }] };
  }
  if (!args.currentTool || !['visus_fetch', 'visus_search', 'visus_read'].includes(args.currentTool)) {
    return { content: [{ type: 'text', text: 'Error: currentTool must be visus_fetch, visus_search, or visus_read' }] };
  }

  const sessionId = args.sessionId || crypto.randomUUID();

  // Load cached primed entities
  const cachedPrimed = await cacheManager.getPrimed(sessionId);

  // Prepare input for scan (priorExtractions metadata only)
  const input: ContextScanInput = {
    sessionId,
    history: args.history,
    priorExtractions: args.priorExtractions || [],
    currentTool: args.currentTool
  };

  let scanResult = await scanContext(input);

  // Merge with cached for fuller picture
  scanResult.primedEntities = [...new Set([...scanResult.primedEntities, ...cachedPrimed])];  // Dedupe by hash

  // HITL elicitation if risk high (VISUS_HITL_ENABLED default true)
  if (scanResult.riskScore > 0.7 && process.env.VISUS_HITL_ENABLED !== 'false') {
    // Mock threatReport for elicit (use scanResult.threats)
    const mockThreatReport = {
      total_findings: scanResult.threats.length,
      highest_severity: scanResult.threats.length > 0 ? scanResult.threats[0]?.severity || 'HIGH' : 'NONE'
    };

    const { proceed, includeReport } = await runElicitation(
      request.server,  // Pass MCP server for elicitation
      mockThreatReport,
      `Stateful priming risk ${scanResult.riskScore.toFixed(2)} detected (primed entities: ${scanResult.primedEntities.length})`
    );

    if (!proceed) {
      return {
        content: [{
          type: 'text',
          text: `Blocked due to high stateful risk (score: ${scanResult.riskScore.toFixed(2)}). Review primed entities: ${scanResult.primedEntities.map(e => e.valueHash.substring(0,8)).join(', ')}.`
        }]
      };
    }

    // User accepted: Optionally strip report
    if (!includeReport) {
      const { threats, ...cleanResult } = scanResult;
      scanResult = cleanResult as ContextScanOutput;
    }
  }

  // Cache new/updated primed entities
  await cacheManager.setPrimed(sessionId, scanResult.primedEntities);

  // Simple proof (extend existing in real impl)
  const proof = {
    request_id: sessionId,
    proof_hash: crypto.createHash('sha256').update(JSON.stringify(scanResult)).digest('hex').substring(0,16),
    chain_hash: 'placeholder',  // Integrate with existing chain
    injection_detected: scanResult.threats.length > 0,
    patterns_evaluated: 20,  // IPI + priming
    patterns_triggered: scanResult.threats.length,
    timestamp_utc: new Date().toISOString(),
    pipeline_version: '0.17.0',
    schema_version: '1.0.0'
  };

  const output: ContextScanOutput & { visus_proof: typeof proof; sessionId: string } = {
    ...scanResult,
    visus_proof: proof,
    sessionId  // Echo back for logging
  };

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(output, null, 2)
    }]
  };
};
