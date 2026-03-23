/**
 * Elicitation Runner
 *
 * Executes MCP elicitation requests with comprehensive error handling
 * and fail-safe behavior. If elicitation fails for ANY reason, the
 * sanitized content is delivered — security is never compromised.
 *
 * Error handling includes:
 * - Client doesn't support elicitation
 * - Client timeout
 * - Network errors
 * - Unexpected responses
 *
 * Fail-safe principle: Elicitation is UX. Sanitization is security.
 * Never block content delivery due to elicitation failures.
 */

import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { ThreatReport } from './threat-reporter.js';
import { buildElicitMessage, ElicitSchema } from './hitl-gate.js';

/**
 * Result of elicitation execution
 */
export interface ElicitationResult {
  /** Whether user chose to proceed with sanitized content */
  proceed: boolean;
  /** Whether to include threat report in response */
  includeReport: boolean;
}

/**
 * Runs MCP elicitation for CRITICAL threat confirmation
 *
 * Three possible outcomes:
 * 1. User accepts → proceed: true, includeReport: user's choice
 * 2. User declines → proceed: false, includeReport: false
 * 3. User cancels → proceed: false, includeReport: false
 *
 * Fail-safe: Any error → proceed: true, includeReport: true
 * (Content reaches user in sanitized form, security maintained)
 *
 * CRITICAL: Only ONE elicitation per tool call is allowed per MCP spec.
 * Calling this function twice in the same request will cause timeout.
 *
 * @param server The MCP server instance
 * @param threatReport The CRITICAL threat report
 * @param url The source URL
 * @returns Elicitation result with proceed and includeReport flags
 */
export async function runElicitation(
  server: Server,
  threatReport: ThreatReport,
  url: string
): Promise<ElicitationResult> {
  try {
    // Build user-facing message
    const message = buildElicitMessage(threatReport, url);

    // Execute elicitation
    const result = await server.elicitInput({
      mode: 'form' as const,
      message,
      requestedSchema: ElicitSchema as any // Type cast due to SDK's strict schema definition
    });

    // Handle user response
    if (result.action === 'accept') {
      // User explicitly accepted
      // Content values can be string | number | boolean | string[]
      const proceed = result.content?.proceed === true || result.content?.proceed === 'true';
      const includeReport = result.content?.view_report === true || result.content?.view_report === 'true' || result.content?.view_report === undefined;

      return {
        proceed,
        includeReport: proceed ? includeReport : false // Only include report if proceeding
      };
    }

    if (result.action === 'decline') {
      // User explicitly declined
      return {
        proceed: false,
        includeReport: false
      };
    }

    if (result.action === 'cancel') {
      // User canceled or dismissed dialog
      return {
        proceed: false,
        includeReport: false
      };
    }

    // Unknown action (should never happen)
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'elicitation_unknown_action',
      action: result.action,
      message: 'Unexpected elicitation action, proceeding with sanitized content (fail-safe)'
    }));

    return {
      proceed: true,
      includeReport: true
    };

  } catch (error) {
    // Elicitation failed — FAIL SAFE
    // Client may not support elicitation, or timeout occurred
    // Proceed with sanitized content + include report
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'elicitation_failed',
      error: error instanceof Error ? error.message : String(error),
      message: 'Elicitation not supported or timed out, proceeding with sanitized content (fail-safe)'
    }));

    return {
      proceed: true,
      includeReport: true
    };
  }
}
