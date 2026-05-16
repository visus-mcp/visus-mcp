/**
 * Enterprise Integration — Bridge
 *
 * Helper to wire Visus-MCP tool handler outputs into the enterprise event pipeline.
 * Provides a single function that extracts SecurityEvent fields from sanitization
 * results, session ledger state, and other internal data structures.
 *
 * Security is the priority: every event carries payload_hash (SHA-256 of original),
 * HMAC signature, and normalized severity for SIEM correlation.
 */

import { createHash } from 'crypto';
import type { SecurityEvent, SecurityEventType } from './types.js';
import type { ThreatReport } from '../sanitizer/threat-reporter.js';

/**
 * Build a SecurityEvent from a sanitization pipeline result.
 * This is the primary entry point — called after every fetch/read/scan.
 */
export function buildSecurityEvent(params: {
  eventType: SecurityEventType;
  toolName: string;
  sessionId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
  patterns: string[];
  piiTypes: string[];
  source: string;
  rawPayload?: string;
  threatReport?: ThreatReport | null;
  metadata?: Record<string, unknown>;
}): Omit<SecurityEvent, 'signature' | 'event_id' | 'timestamp'> {
  return {
    tool_name: params.toolName,
    session_id: params.sessionId,
    event_type: params.eventType,
    severity: params.severity,
    risk_score: params.riskScore,
    patterns: params.patterns,
    pii_types: params.piiTypes,
    payload_hash: params.rawPayload ? sha256Hex(params.rawPayload) : '',
    source: params.source,
    metadata: {
      ...params.metadata,
      total_findings: params.threatReport?.total_findings,
      overall_severity: params.threatReport?.overall_severity,
    },
  };
}

/**
 * Determine SecurityEventSeverity from a ThreatReport's overall_severity string.
 */
export function threatSeverityToEventSeverity(
  severity: string
): 'low' | 'medium' | 'high' | 'critical' {
  const s = severity.toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'high';
  if (s === 'MEDIUM') return 'medium';
  return 'low';
}

/**
 * Expose a default metadata tag set for every SIEM event.
 */
export function defaultMetadata(): Record<string, unknown> {
  return {
    visus_version: process.env.npm_package_version || '0.28.0',
    source_env: process.env.VISUS_DEPLOY_ENV || 'local',
  };
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}