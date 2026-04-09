/**
 * visus_session_report MCP Tool
 *
 * Returns the current session state including threat level, hits, chains,
 * and actionable recommendations.
 *
 * @module tools/session-report
 */

import { sessionStore } from '../session/session-store.js';
import type { SessionThreatLevel, ChainAlert } from '../session/session-store.js';
import type { ThreatSeverity } from '../security/threats.js';
import type { Result } from '../types.js';
import { Err, Ok } from '../types.js';

/**
 * Input schema for visus_session_report
 */
export interface VisusSessionReportInput {
  /** Output format: 'summary' or 'detailed' */
  format?: 'summary' | 'detailed';
}

/**
 * Output schema for visus_session_report
 */
export interface VisusSessionReportOutput {
  /** UUID v4 session identifier */
  session_id: string;
  /** ISO 8601 session start time */
  started_at: string;
  /** Total tool calls in session */
  total_calls: number;
  /** Current threat level */
  threat_level: SessionThreatLevel;
  /** Total threat annotations across all calls */
  total_hits: number;
  /** Count of annotations by severity */
  hits_by_severity: Record<ThreatSeverity, number>;
  /** Count of annotations per IPI class */
  hits_by_class: Record<string, number>;
  /** Number of attack chains detected */
  chains_detected: number;
  /** Detailed chain information */
  chain_details: ChainAlert[];
  /** Per-call timeline (only in detailed format) */
  call_timeline?: Array<{
    call_index: number;
    tool: string;
    source: string;
    threats: number;
    highest_severity: ThreatSeverity | 'NONE';
  }>;
  /** Actionable recommendations based on session state */
  recommendations: string[];
}

/**
 * Get recommendations based on threat level
 *
 * @param level - Current session threat level
 * @returns Array of recommendation strings
 */
function getRecommendations(level: SessionThreatLevel): string[] {
  switch (level) {
    case 'CLEAN':
      return ['No threats detected in this session. Continue with confidence.'];
    case 'LOW':
      return ['Low-level signals detected. Monitor for escalation patterns.'];
    case 'MEDIUM':
      return [
        'Multiple medium-severity threats detected. Review sources before proceeding.',
        'Consider using visus_session_report with format=detailed for per-call breakdown.',
      ];
    case 'HIGH':
      return [
        'High-severity threats accumulated. Exercise caution with web content.',
        'Review call timeline for patterns. Avoid visiting the flagged URLs again.',
      ];
    case 'CRITICAL':
      return [
        'CRITICAL threat level reached. Multiple high-severity injections detected.',
        'Review chain details for multi-step attack patterns.',
        'Consider restarting the session if threats persist.',
      ];
    case 'BLOCKED':
      return [
        'Session BLOCKED. Two or more CRITICAL threats detected.',
        'Review chain details and hit timeline above.',
        'Consider restarting the MCP server to begin a new session.',
        'Do not proceed with further web content fetching until the threat source is identified.',
      ];
    default:
      return ['Unknown threat level.'];
  }
}

/**
 * Execute the visus_session_report tool
 *
 * @param input - Tool input parameters
 * @returns Session report with threat analysis
 *
 * @example
 * ```typescript
 * const result = visusSessionReport({ format: 'detailed' });
 * // { session_id: '...', threat_level: 'LOW', total_hits: 3, ... }
 * ```
 */
export function visusSessionReport(
  input: VisusSessionReportInput
): Result<VisusSessionReportOutput, Error> {
  try {
    const state = sessionStore.getState();
    const format = input.format || 'summary';

    // Count annotations by severity
    const hitsBySeverity: Record<ThreatSeverity, number> = {
      INFO: 0,
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    };

    // Count annotations by class
    const hitsByClass: Record<string, number> = {};

    for (const hit of state.hits) {
      for (const annotation of hit.annotations) {
        // Count by severity
        hitsBySeverity[annotation.severity]++;

        // Count by class
        const classId = annotation.id;
        hitsByClass[classId] = (hitsByClass[classId] || 0) + 1;
      }
    }

    // Calculate total hits
    const totalHits = state.hits.reduce(
      (sum, hit) => sum + hit.annotations.length,
      0
    );

    // Build call timeline if detailed format
    let callTimeline: VisusSessionReportOutput['call_timeline'] = undefined;
    if (format === 'detailed') {
      callTimeline = state.hits.map((hit) => ({
        call_index: hit.call_index,
        tool: hit.tool_name,
        source: hit.source_url,
        threats: hit.annotations.length,
        highest_severity: hit.highest_severity,
      }));
    }

    // Get recommendations
    const recommendations = getRecommendations(state.current_level);

    const output: VisusSessionReportOutput = {
      session_id: state.session_id,
      started_at: state.started_at,
      total_calls: state.total_calls,
      threat_level: state.current_level,
      total_hits: totalHits,
      hits_by_severity: hitsBySeverity,
      hits_by_class: hitsByClass,
      chains_detected: state.chains.length,
      chain_details: [...state.chains] as ChainAlert[],
      ...(callTimeline && { call_timeline: callTimeline }),
      recommendations,
    };

    return Ok(output);
  } catch (error) {
    return Err(error instanceof Error ? error : new Error(String(error)));
  }
}

/**
 * MCP tool definition for registration
 */
export const visusSessionReportToolDefinition = {
  name: 'visus_session_report',
  title: 'Session Threat Report',
  description:
    'Returns the current session state including accumulated threat signals, attack chain detection, and actionable recommendations. Use this to audit the session threat level after multiple web content operations.',
  inputSchema: {
    type: 'object',
    properties: {
      format: {
        type: 'string',
        enum: ['summary', 'detailed'],
        description:
          "Output format. 'summary': session-level stats only. 'detailed': includes per-call timeline and chain details.",
        default: 'summary',
      },
    },
    required: [],
  },
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};