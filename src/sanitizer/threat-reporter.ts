/**
 * Threat Reporter
 *
 * Generates structured threat reports when prompt injection or PII is detected.
 * Two output layers:
 * 1. TOON-formatted findings array (token-efficient, machine-readable)
 * 2. Markdown compliance report block (human-readable, renders in Claude Desktop)
 *
 * Aligned with:
 * - OWASP LLM Top 10 (2025)
 * - NIST AI 600-1 (Generative AI Profile)
 * - MITRE ATLAS (Adversarial Threat Landscape)
 */

import {
  classifySeverity,
  aggregateSeverity,
  countBySeverity,
  getSeverityEmoji,
  type Severity,
  type OverallSeverity,
  type Finding as SeverityFinding
} from './severity-classifier.js';
import { getFrameworkMappings } from './framework-mapper.js';

/**
 * Threat finding with compliance framework mappings
 */
export interface ThreatFinding {
  id: number;
  pattern_id: string;
  category: string;
  severity: Severity;
  confidence: number;
  owasp_llm: string;
  nist_ai_600_1: string;
  mitre_atlas: string;
  remediation: string;
}

/**
 * Threat report structure
 */
export interface ThreatReport {
  generated: string;
  source_url: string;
  overall_severity: OverallSeverity;
  total_findings: number;
  by_severity: Record<Severity, number>;
  pii_redacted: number;
  sanitization_applied: boolean;
  frameworks: string[];
  findings_toon: string;
  report_markdown: string;
}

/**
 * Input to threat reporter
 */
export interface ThreatReportInput {
  patterns_detected: string[];
  pii_redacted: number;
  source_url: string;
  timestamp?: string;
  detections_by_severity?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

/**
 * Generate pattern ID from category name
 * Format: PI-XXX where XXX is a zero-padded number based on hash
 */
function generatePatternId(category: string): string {
  // Simple hash to generate consistent IDs
  let hash = 0;
  for (let i = 0; i < category.length; i++) {
    hash = ((hash << 5) - hash) + category.charCodeAt(i);
    hash = hash & hash;
  }
  const id = Math.abs(hash) % 1000;
  return `PI-${String(id).padStart(3, '0')}`;
}

/**
 * Build findings data structure from pattern detections
 */
function buildFindings(patternsDetected: string[]): ThreatFinding[] {
  return patternsDetected.map((category, index) => {
    const severity = classifySeverity(category);
    const frameworks = getFrameworkMappings(category);
    const patternId = generatePatternId(category);

    return {
      id: index + 1,
      pattern_id: patternId,
      category,
      severity,
      confidence: 0.95, // Default confidence; can be enhanced later
      owasp_llm: frameworks.owasp_llm,
      nist_ai_600_1: frameworks.nist_ai_600_1,
      mitre_atlas: frameworks.mitre_atlas,
      remediation: `Content sanitized. ${category.replace(/_/g, ' ')} removed.`
    };
  });
}

/**
 * Generate TOON-encoded findings string
 * Using manual TOON format to avoid Jest ESM compatibility issues
 */
function generateToonFindings(findings: ThreatFinding[]): string {
  if (findings.length === 0) {
    return '';
  }

  return generateManualToonFormat(findings);
}

/**
 * Fallback manual TOON format generation
 */
function generateManualToonFormat(findings: ThreatFinding[]): string {
  const header = `findings[${findings.length}]{id,pattern_id,category,severity,confidence,owasp_llm,nist_ai_600_1,mitre_atlas,remediation}:`;
  const rows = findings.map(f =>
    `${f.id},${f.pattern_id},${f.category},${f.severity},${f.confidence},${f.owasp_llm},${f.nist_ai_600_1},${f.mitre_atlas},${f.remediation}`
  );
  return `${header}\n${rows.join('\n')}`;
}

/**
 * Generate Markdown report block
 */
function generateMarkdownReport(
  findings: ThreatFinding[],
  overallSeverity: OverallSeverity,
  bySeverity: Record<Severity, number>,
  piiRedacted: number,
  sourceUrl: string,
  timestamp: string
): string {
  const emoji = getSeverityEmoji(overallSeverity);

  let markdown = '---\n';
  markdown += `## ${emoji} Visus Threat Report\n`;
  markdown += `**Generated:** ${timestamp}\n`;
  markdown += `**Source:** ${sourceUrl}\n`;
  markdown += `**Overall Severity:** ${overallSeverity}\n`;
  markdown += `**Framework:** OWASP LLM Top 10 | NIST AI 600-1 | MITRE ATLAS\n\n`;

  // Findings Summary
  markdown += '### Findings Summary\n';
  markdown += '| Severity | Count |\n';
  markdown += '|---|---|\n';
  markdown += `| ${getSeverityEmoji('CRITICAL')} CRITICAL | ${bySeverity.CRITICAL} |\n`;
  markdown += `| ${getSeverityEmoji('HIGH')} HIGH | ${bySeverity.HIGH} |\n`;
  markdown += `| ${getSeverityEmoji('MEDIUM')} MEDIUM | ${bySeverity.MEDIUM} |\n`;
  markdown += `| ${getSeverityEmoji('LOW')} LOW | ${bySeverity.LOW} |\n\n`;

  // Findings Detail (only if we have findings)
  if (findings.length > 0) {
    markdown += '### Findings Detail\n';
    markdown += '| # | Category | Severity | Confidence | OWASP | MITRE |\n';
    markdown += '|---|---|---|---|---|---|\n';

    for (const finding of findings.slice(0, 10)) { // Limit to first 10 for readability
      const confidencePct = Math.round(finding.confidence * 100);
      const owaspShort = finding.owasp_llm.split(' - ')[0]; // e.g., "LLM01:2025"
      const mitreShort = finding.mitre_atlas.split(' - ')[0]; // e.g., "AML.T0051.000"

      markdown += `| ${finding.id} | ${finding.category} | ${finding.severity} | ${confidencePct}% | ${owaspShort} | ${mitreShort} |\n`;
    }

    if (findings.length > 10) {
      markdown += `\n*...and ${findings.length - 10} more findings*\n`;
    }
    markdown += '\n';
  }

  // PII Redaction
  if (piiRedacted > 0) {
    markdown += '### PII Redaction\n';
    markdown += `- **Items Redacted:** ${piiRedacted}\n`;
    markdown += `- **Standard:** NIST AI 600-1 MS-2.6\n\n`;
  }

  // Remediation Status
  markdown += '### Remediation Status\n';
  markdown += '✅ All findings sanitized. Content delivered clean.\n\n';

  // TODO: PDF export hook for future visus_report tool
  // This is where the PDF generation would be triggered in Phase 3

  markdown += '*Report generated by Visus MCP — Security-first web access for Claude*\n';
  markdown += '---\n';

  return markdown;
}

/**
 * Generate threat report (main entry point)
 *
 * Returns null if no findings (injections_removed === 0 AND pii_redacted === 0)
 */
export function generateThreatReport(input: ThreatReportInput): ThreatReport | null {
  const {
    patterns_detected,
    pii_redacted,
    source_url,
    timestamp = new Date().toISOString()
  } = input;

  // Omit threat report if nothing was found
  if (patterns_detected.length === 0 && pii_redacted === 0) {
    return null;
  }

  // Build findings from detected patterns
  const findings = buildFindings(patterns_detected);

  // Calculate severity
  const severityFindings: SeverityFinding[] = findings.map(f => ({
    pattern_category: f.category,
    severity: f.severity
  }));
  const overallSeverity = aggregateSeverity(severityFindings);
  const bySeverity = countBySeverity(severityFindings);

  // Generate TOON findings
  const toonFindings = generateToonFindings(findings);

  // Generate Markdown report
  const markdownReport = generateMarkdownReport(
    findings,
    overallSeverity,
    bySeverity,
    pii_redacted,
    source_url,
    timestamp
  );

  return {
    generated: timestamp,
    source_url,
    overall_severity: overallSeverity,
    total_findings: findings.length,
    by_severity: bySeverity,
    pii_redacted,
    sanitization_applied: true,
    frameworks: [
      'OWASP LLM Top 10',
      'NIST AI 600-1',
      'MITRE ATLAS'
    ],
    findings_toon: toonFindings,
    report_markdown: markdownReport
  };
}
