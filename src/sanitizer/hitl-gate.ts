/**
 * HITL (Human-in-the-Loop) Gate
 *
 * Determines when to pause tool execution for user confirmation
 * based on threat severity. Only CRITICAL threats trigger elicitation.
 *
 * Design:
 * - HIGH/MEDIUM/LOW threats → silent sanitization (business as usual)
 * - CRITICAL threats → pause execution, user confirmation required
 *
 * Security model: Sanitization is the security gate. HITL is UX.
 * Content is ALWAYS sanitized before reaching the LLM, whether or not
 * the user accepts the elicitation prompt.
 */

import type { ThreatReport } from './threat-reporter.js';

/**
 * Determines whether to trigger HITL elicitation
 *
 * Returns true ONLY when:
 * - threatReport is not null
 * - threatReport.overall_severity === 'CRITICAL'
 * - threatReport.total_findings > 0
 *
 * @param threatReport The threat report from sanitization
 * @returns true if elicitation should be triggered
 */
export function shouldElicit(threatReport: ThreatReport | null): boolean {
  if (!threatReport) {
    return false;
  }

  return (
    threatReport.overall_severity === 'CRITICAL' &&
    threatReport.total_findings > 0
  );
}

/**
 * Builds a user-facing elicitation message for CRITICAL threats
 *
 * Format:
 * ⚠️ Visus blocked a CRITICAL threat on this page.
 *
 * {total_findings} injection attempt(s) detected on:
 * {url}
 *
 * Highest severity finding: {top_category}
 * ({top_owasp} | {top_mitre})
 *
 * Content has been sanitized. Proceed with clean version?
 *
 * @param threatReport The threat report with CRITICAL severity
 * @param url The source URL
 * @returns A clear, concise message under 300 characters
 */
export function buildElicitMessage(threatReport: ThreatReport, url: string): string {
  // Find the highest-confidence CRITICAL finding
  const findings = threatReport.findings_toon
    .split('\n')
    .slice(1) // Skip header
    .filter(line => line.trim().length > 0);

  let topCategory = 'unknown';
  let topOwasp = 'N/A';
  let topMitre = 'N/A';

  if (findings.length > 0) {
    // Parse first finding (highest confidence)
    const parts = findings[0].split(',');
    if (parts.length >= 8) {
      topCategory = parts[2]; // category field
      topOwasp = parts[5].split(' - ')[0]; // owasp_llm field (short form)
      topMitre = parts[7].split(' - ')[0]; // mitre_atlas field (short form)
    }
  }

  return `⚠️ Visus blocked a CRITICAL threat on this page.

${threatReport.total_findings} injection attempt(s) detected on:
${url}

Highest severity finding: ${topCategory}
(${topOwasp} | ${topMitre})

Content has been sanitized. Proceed with clean version?`;
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
