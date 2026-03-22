/**
 * Severity Classification Engine
 *
 * Maps injection pattern categories to standardized severity levels.
 * Used for threat reporting and compliance documentation.
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type OverallSeverity = Severity | 'CLEAN';

/**
 * Pattern category to severity mapping
 * Aligned with NIST AI 600-1 and OWASP LLM Top 10 risk levels
 */
const SEVERITY_MAP: Record<string, Severity> = {
  // CRITICAL - Immediate threat, block-level
  direct_instruction_injection: 'CRITICAL',
  role_hijacking: 'CRITICAL',
  system_prompt_extraction: 'CRITICAL',
  privilege_escalation: 'CRITICAL',
  data_exfiltration: 'CRITICAL',
  code_execution_requests: 'CRITICAL',
  memory_manipulation: 'CRITICAL',
  jailbreak_keywords: 'CRITICAL',
  ethical_override: 'CRITICAL',
  credential_harvesting: 'CRITICAL',
  html_script_injection: 'CRITICAL',

  // HIGH - Significant threat
  context_poisoning: 'HIGH',
  base64_obfuscation: 'HIGH',
  zero_width_characters: 'HIGH',
  data_uri_injection: 'HIGH',
  markdown_link_injection: 'HIGH',
  instruction_delimiter_injection: 'HIGH',
  token_smuggling: 'HIGH',
  system_message_injection: 'HIGH',
  file_system_access: 'HIGH',
  training_data_extraction: 'HIGH',
  nested_encoding: 'HIGH',
  authority_impersonation: 'HIGH',
  callback_url_injection: 'HIGH',

  // MEDIUM - Moderate threat
  comment_injection: 'MEDIUM',
  unicode_lookalikes: 'MEDIUM',
  url_fragment_hashjack: 'MEDIUM',
  social_engineering_urgency: 'MEDIUM',
  multi_language_obfuscation: 'MEDIUM',
  reverse_text_obfuscation: 'MEDIUM',
  conversation_reset: 'MEDIUM',
  chain_of_thought_manipulation: 'MEDIUM',
  hypothetical_scenario_injection: 'MEDIUM',
  output_format_manipulation: 'MEDIUM',
  simulator_mode: 'MEDIUM',
  payload_splitting: 'MEDIUM',
  css_hiding: 'MEDIUM',
  testing_debugging_claims: 'MEDIUM',

  // LOW - Low threat, flagged for awareness
  leetspeak_obfuscation: 'LOW',
  capability_probing: 'LOW',
  negative_instruction: 'LOW',
  time_based_triggers: 'LOW',
  whitespace_steganography: 'LOW'
};

/**
 * Classify severity for a single pattern category
 */
export function classifySeverity(patternCategory: string): Severity {
  return SEVERITY_MAP[patternCategory] || 'LOW';
}

/**
 * Interface for a threat finding
 */
export interface Finding {
  pattern_category: string;
  severity: Severity;
}

/**
 * Aggregate severity across multiple findings
 * Returns the highest severity level found, or CLEAN if no findings
 */
export function aggregateSeverity(findings: Finding[]): OverallSeverity {
  if (findings.length === 0) {
    return 'CLEAN';
  }

  const severities = findings.map(f => f.severity);

  if (severities.includes('CRITICAL')) return 'CRITICAL';
  if (severities.includes('HIGH')) return 'HIGH';
  if (severities.includes('MEDIUM')) return 'MEDIUM';
  if (severities.includes('LOW')) return 'LOW';

  return 'CLEAN';
}

/**
 * Count findings by severity level
 */
export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };

  for (const finding of findings) {
    counts[finding.severity]++;
  }

  return counts;
}

/**
 * Get emoji for severity level (for Markdown reports)
 */
export function getSeverityEmoji(severity: Severity | OverallSeverity): string {
  switch (severity) {
    case 'CRITICAL': return '🔴';
    case 'HIGH': return '🟠';
    case 'MEDIUM': return '🟡';
    case 'LOW': return '🟢';
    case 'CLEAN': return '✅';
    default: return '⚪';
  }
}
