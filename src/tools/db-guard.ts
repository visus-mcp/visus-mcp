import type { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { SessionLedger } from '../security/session-ledger.js';
import { visusDbSanitize } from './db-guard.js';  // Self-import for now (will cycle)
import { postLlmToolGuard } from './db-rce-detector.js';

// Extend MCP handler for DB guard
// In server.setRequestHandler(CallToolRequestSchema, async (request) => {
const ledger = new SessionLedger();

// Middleware wrapper (call before tool exec)
export async function dbGuardMiddleware(name: string, args: any, sessionId: string): Promise<any> {
  // For DB-related tools (e.g., sql_query, terms fetch)
  if (name === 'sql_query' || name.includes('terms')) {
    // Sanitize input if DB terms
    if (args.terms || args.description) {
      const terms = { ...args.terms, description: args.description || '' };
      const sanitized = await visusDbSanitize(terms, sessionId);
      args = { ...args, ...sanitized.content };  // Replace
      if (sanitized.risk_score > 0.7) {
        throw new McpError(ErrorCode.InternalError, 'DB terms sanitized due to RCE risk (CVE-2026-32622)');
      }
    }

    // Post-LLM guard simulation (for tool args as output proxy)
    if (args.sql || args.query) {
      const guard = postLlmToolGuard({ name, args });
      if (!guard) {
        throw new McpError(ErrorCode.InternalError, 'SQL execution blocked: RCE detected (CVE-2026-32622)');
      }
    }

    // Goal hijack check (if session history available)
    // Assume sessionEvents from ledger; stub for now
    const events = ledger.getSessionEvents(sessionId);  // Implement in ledger
    if (events.length > 1) {
      const hijackScore = detectGoalHijack(events);
      if (hijackScore > 0.8) {
        // HITL: Elicit user confirmation
        const message = 'Potential goal hijack detected (DB admin deviation). Proceed?';
        // Integrate with existing runElicitation
        const { proceed } = await require('./hitl-gate').runElicitation(message);  // Stub
        if (!proceed) {
          throw new McpError(ErrorCode.InternalError, 'Session blocked: Goal hijack (CVE-2026-32622)');
        }
      }
    }
  }

  // Proceed to original tool
  return { name, args };  // Or execute
}

// Hook into new tool: visus_db_verify
export const visusDbVerifyToolDefinition = {
  name: 'visus_db_verify',
  description: 'Verify and sanitize DB terms for RCE (CVE-2026-32622)',
  inputSchema: {
    type: 'object',
    properties: {
      terms: { type: 'object' },
      sessionId: { type: 'string' }
    }
  }
};

export async function visusDbVerify(args: any) {
  const { terms, sessionId } = args;
  const result = await visusDbSanitize(terms, sessionId || 'anon');
  if (result.cve_flagged) {
    // Audit + optional purge flag
    ledger.addEvent({ type: 'CVE_32622_DETECTED', sessionId, proof: hash(terms) });
  }
  return result;
}

// Utility hash
function hash(data: any): string {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex').slice(0, 16);
}
