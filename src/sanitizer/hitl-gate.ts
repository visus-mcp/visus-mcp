/**
 * HITL (Human-in-the-Loop) Gate
 *
 * Determines when to pause tool execution for user confirmation
 * based on threat severity. Only CRITICAL threats trigger elicitation.
 * Extended for worm risks >0.8 (v0.18.0).
 *
 * Design:
 * - HIGH/MEDIUM/LOW threats → silent sanitization (business as usual)
 * - CRITICAL threats or worm_risk >0.8 → pause execution, user confirmation required
 *
 * Security model: Sanitization is the security gate. HITL is UX.
 * Content is ALWAYS sanitized before reaching the LLM, whether or not
 * the user accepts the elicitation prompt.
 */

import type { ThreatReport } from './threat-reporter.js';
import { hasCriticalThreats } from './injection-detector.js'; // Assume import for severity check

/**
 * Determines whether to trigger HITL elicitation
 *
 * Returns true ONLY when:
 * - threatReport is not null and has CRITICAL severity, OR
 * - wormRisk > 0.8
 *
 * @param threatReport The threat report from sanitization
 * @param wormRisk Worm detection risk score (default 0)
 * @returns true if elicitation should be triggered
 */
export function shouldElicit(threatReport: ThreatReport | null, wormRisk: number = 0): boolean {
  const hasCritical = threatReport ? hasCriticalThreats(threatReport.detections_by_severity) : false;
  return hasCritical || wormRisk > 0.8;
}

/**
 * Builds a user-facing elicitation message for CRITICAL threats or high worm risks
 *
 * Format enhanced for worm risks.
 *
 * @param threatReport The threat report with CRITICAL severity
 * @param url The source URL
 * @param wormRisk Worm risk score
 * @returns A clear, concise message under 300 characters
 */
export function buildElicitMessage(threatReport: ThreatReport, url: string, wormRisk: number = 0): string {
  let message = '';
  if (threatReport?.total_findings > 0) {
    const findings = threatReport.findings_toon
      .split('\n')
      .slice(1)
      .filter(line => line.trim().length > 0);

    let topCategory = 'unknown';
    let topOwasp = 'N/A';
    let topMitre = 'N/A';

    if (findings.length > 0) {
      const parts = findings[0].split(',');
      if (parts.length >= 8) {
        topCategory = parts[2];
        topOwasp = parts[5].split(' - ')[0];
        topMitre = parts[7].split(' - ')[0];
      }
    }

    message += `⚠️ Visus blocked a CRITICAL threat on this page.\n\n${threatReport.total_findings} injection attempt(s) detected on:\n${url}\n\nHighest severity finding: ${topCategory}\n(${topOwasp} | ${topMitre})\n\n`;
  }

  if (wormRisk > 0.8) {
    message += `⚠️ Additionally, detected potential Morris II worm replicator (risk: ${wormRisk.toFixed(2)}).\n\n`;
  }

  message += `Content has been sanitized. Proceed with clean version?`;

  return message;
}

/**
 * Elicitation schema for user confirmation
 *
 * CRITICAL: Must be flat primitive properties only (no nested objects, no arrays)
 * per MCP elicitation specification.
 */
export const ElicitSchema = {
  type: 'object',
  properties: {
    proceed: {
      type: 'boolean',
      title: 'Proceed with sanitized content',
      description: 'Content has been cleaned. View sanitized version?'
    },
    view_report: {
      type: 'boolean',
      title: 'Include threat report in response',
      description: 'Attach the full NIST/OWASP/MITRE threat report?'
    }
  },
  required: ['proceed']
} as const;