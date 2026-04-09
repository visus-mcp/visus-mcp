/**
 * Session-Level Threat Accumulation (SLTA) - Session Store
 *
 * In-process session state manager that accumulates threat signals across
 * tool calls and computes rolling threat level with chain detection.
 *
 * @module session/session-store
 */

import { randomUUID } from 'crypto';
import type { ThreatAnnotation, ThreatClass, ThreatSeverity } from '../security/threats.js';
import { computeThreatLevel } from './escalation-engine.js';

/**
 * Session-level threat level
 */
export type SessionThreatLevel = 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'BLOCKED';

/**
 * A single recorded threat hit from one tool call
 */
export interface SessionHit {
  /** 0-based sequential call number */
  call_index: number;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Tool name: 'visus_fetch' | 'visus_read' | 'visus_search' | 'visus_fetch_structured' */
  tool_name: string;
  /** URL or 'search: <query>' */
  source_url: string;
  /** Raw annotations from ThreatDetector */
  annotations: ThreatAnnotation[];
  /** Deduplicated IPI-NNN class IDs */
  threat_classes: ThreatClass[];
  /** Highest severity in this hit */
  highest_severity: ThreatSeverity;
}

/**
 * A detected multi-call attack chain
 */
export interface ChainAlert {
  /** Chain pattern name */
  pattern: string;
  /** Call N (the probing call) */
  trigger_call_index: number;
  /** Call N+M (the exploit call) */
  exploit_call_index: number;
  /** All IPI classes involved in the chain */
  involved_classes: ThreatClass[];
  /** Severity of the chain */
  severity: ThreatSeverity;
  /** Human-readable description */
  description: string;
}

/**
 * Full session state
 */
export interface SessionState {
  /** UUID v4 session identifier */
  session_id: string;
  /** ISO 8601 session start time */
  started_at: string;
  /** Total number of tool calls in this session */
  total_calls: number;
  /** All recorded hits */
  hits: SessionHit[];
  /** All detected chains */
  chains: ChainAlert[];
  /** Current computed threat level */
  current_level: SessionThreatLevel;
  /** ISO 8601 last update timestamp */
  last_updated: string;
}

/**
 * Session store singleton that manages session-level threat accumulation
 *
 * @remarks
 * This store maintains state across all tool calls within a single MCP session.
 * Session ID is generated once on first instantiation (per-process UUID).
 */
class SessionStoreManager {
  private state: SessionState;

  /**
   * Create a new session store
   */
  constructor() {
    this.state = {
      session_id: randomUUID(),
      started_at: new Date().toISOString(),
      total_calls: 0,
      hits: [],
      chains: [],
      current_level: 'CLEAN',
      last_updated: new Date().toISOString(),
    };
  }

  /**
   * Get the current session ID
   *
   * @returns Session UUID (does not change throughout the session)
   */
  getSessionId(): string {
    return this.state.session_id;
  }

  /**
   * Record a new threat hit and recompute session level + chains
   *
   * @param toolName - Name of the tool that was called
   * @param sourceUrl - URL or search query that was processed
   * @param annotations - Array of threat annotations detected
   * @returns Updated session state
   */
  recordHit(
    toolName: string,
    sourceUrl: string,
    annotations: ThreatAnnotation[]
  ): SessionState {
    // Increment total calls
    this.state.total_calls++;

    // Extract unique threat classes and highest severity
    const classesSet = new Set<ThreatClass>();
    let highestSeverity: ThreatSeverity = 'INFO';

    const severityRank: Record<ThreatSeverity, number> = {
      INFO: 1,
      LOW: 2,
      MEDIUM: 3,
      HIGH: 4,
      CRITICAL: 5,
    };

    for (const annotation of annotations) {
      classesSet.add(annotation.id);
      if (severityRank[annotation.severity] > severityRank[highestSeverity]) {
        highestSeverity = annotation.severity;
      }
    }

    // Create the hit record
    const hit: SessionHit = {
      call_index: this.state.total_calls - 1,
      timestamp: new Date().toISOString(),
      tool_name: toolName,
      source_url: sourceUrl,
      annotations: annotations,
      threat_classes: Array.from(classesSet),
      highest_severity: highestSeverity,
    };

    // Add to hits array
    this.state.hits.push(hit);

    // Compute new threat level using escalation engine
    const escalationInput = {
      hits: this.state.hits,
      chains: this.state.chains,
      newHit: hit,
    };
    const escalationOutput = computeThreatLevel(escalationInput);

    // Append any new chains
    this.state.chains.push(...escalationOutput.newChains);

    // Update current level
    this.state.current_level = escalationOutput.level;

    // Update last_updated
    this.state.last_updated = new Date().toISOString();

    return this.getState();
  }

  /**
   * Record a clean call (no threats detected)
   *
   * @param toolName - Name of the tool that was called
   */
  recordCleanCall(_toolName: string): void {
    this.state.total_calls++;
    // Note: we don't add a hit record for clean calls, but we increment total_calls
    // The current_level remains unchanged unless there are accumulated threats
    this.state.last_updated = new Date().toISOString();
  }

  /**
   * Get current session state (read-only snapshot)
   *
   * @returns Read-only copy of current session state
   */
  getState(): Readonly<SessionState> {
    return {
      ...this.state,
      hits: [...this.state.hits],
      chains: [...this.state.chains],
    } as Readonly<SessionState>;
  }

  /**
   * Get current threat level
   *
   * @returns Current session threat level
   */
  getCurrentLevel(): SessionThreatLevel {
    return this.state.current_level;
  }

  /**
   * Format the SLTA tag string for injection into tool output
   *
   * @returns SLTA tag string (empty for CLEAN level)
   *
   * @example
   * // For HIGH level with 7 hits and 1 chain:
   * '[SLTA:HIGH | session_hits:7 | chains:1]'
   */
  formatSltaTag(): string {
    const level = this.state.current_level;

    if (level === 'CLEAN') {
      return '';
    }

    // Count total annotations across all hits
    const totalHits = this.state.hits.reduce(
      (sum, hit) => sum + hit.annotations.length,
      0
    );

    // Count chains
    const chainsCount = this.state.chains.length;

    // Format based on level
    if (level === 'LOW' || level === 'MEDIUM') {
      return `[SLTA:${level} | session_hits:${totalHits}]`;
    }

    // HIGH, CRITICAL, BLOCKED
    return `[SLTA:${level} | session_hits:${totalHits} | chains:${chainsCount}]`;
  }
}

/**
 * Singleton session store instance
 *
 * @remarks
 * One instance per MCP server process. Session ID is generated on startup.
 */
export const sessionStore = new SessionStoreManager();