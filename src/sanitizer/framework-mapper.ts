/**
 * Compliance Framework Mapper
 *
 * Maps injection pattern categories to compliance framework identifiers:
 * - OWASP LLM Top 10 (2025)
 * - NIST AI 600-1 (Generative AI Profile)
 * - MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
 * - ISO/IEC 42001:2023 (AI Management System - Annex A Controls)
 */

export interface FrameworkMappings {
  owasp_llm: string;
  nist_ai_600_1: string;
  mitre_atlas: string;
  iso_42001: string;
}

/**
 * Pattern category to framework mapping
 */
const FRAMEWORK_MAP: Record<string, FrameworkMappings> = {
  // Direct instruction injection
  direct_instruction_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Role hijacking
  role_hijacking: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // System prompt extraction
  system_prompt_extraction: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Privilege escalation
  privilege_escalation: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Context poisoning
  context_poisoning: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.2 - Data Quality'
  },

  // Data exfiltration
  data_exfiltration: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.7.5 - Data Provenance / A.8.2 - Information to Users'
  },

  // Encoding obfuscation
  base64_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Unicode lookalikes
  unicode_lookalikes: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Zero-width characters
  zero_width_characters: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // HTML script injection
  html_script_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Data URI injection
  data_uri_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Markdown link injection
  markdown_link_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // URL fragment attacks
  url_fragment_hashjack: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Social engineering
  social_engineering_urgency: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.5.3 - AI Awareness and Training'
  },

  // Instruction delimiter injection
  instruction_delimiter_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Multi-language obfuscation
  multi_language_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Reverse text obfuscation
  reverse_text_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Leetspeak obfuscation
  leetspeak_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Jailbreak keywords
  jailbreak_keywords: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Token smuggling
  token_smuggling: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // System message injection
  system_message_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Conversation reset
  conversation_reset: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.2.6 - Logging and Monitoring'
  },

  // Memory manipulation
  memory_manipulation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.6.2.6 - Logging and Monitoring'
  },

  // Capability probing
  capability_probing: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.2 - AI System Operational Procedures'
  },

  // Chain-of-thought manipulation
  chain_of_thought_manipulation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Hypothetical scenario injection
  hypothetical_scenario_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Ethical override
  ethical_override: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.2.2 - Responsible AI Policies'
  },

  // Output format manipulation
  output_format_manipulation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.2 - AI System Operational Procedures'
  },

  // Negative instruction
  negative_instruction: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.2 - AI System Operational Procedures'
  },

  // Credential harvesting
  credential_harvesting: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.7.5 - Data Provenance / A.6.1.5 - AI System Security'
  },

  // Time-based triggers
  time_based_triggers: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.2.6 - Logging and Monitoring'
  },

  // Code execution requests
  code_execution_requests: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.9.3 - Intended Use Boundaries'
  },

  // File system access
  file_system_access: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.9.3 - Intended Use Boundaries'
  },

  // Training data extraction
  training_data_extraction: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.7.5 - Data Provenance'
  },

  // Simulator mode
  simulator_mode: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.9.3 - Intended Use Boundaries'
  },

  // Nested encoding
  nested_encoding: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Payload splitting
  payload_splitting: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // CSS-based hiding
  css_hiding: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Authority impersonation
  authority_impersonation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.2.2 - Responsible AI Policies'
  },

  // Testing/debugging claims
  testing_debugging_claims: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.2 - AI System Operational Procedures'
  },

  // Callback URL injection
  callback_url_injection: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Whitespace steganography
  whitespace_steganography: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Comment injection
  comment_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  }
};

/**
 * Default mapping for unknown pattern categories
 */
const DEFAULT_MAPPINGS: FrameworkMappings = {
  owasp_llm: 'LLM01:2025 - Prompt Injection',
  nist_ai_600_1: 'MS-2.5 - Prompt Injection',
  mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
  iso_42001: 'A.6.1.5 - AI System Security'
};

/**
 * Get framework mappings for a pattern category
 */
export function getFrameworkMappings(patternCategory: string): FrameworkMappings {
  return FRAMEWORK_MAP[patternCategory] || DEFAULT_MAPPINGS;
}

/**
 * Get all supported frameworks
 */
export function getSupportedFrameworks(): string[] {
  return [
    'OWASP LLM Top 10 (2025)',
    'NIST AI 600-1 (Generative AI Profile)',
    'MITRE ATLAS (Adversarial Threat Landscape)',
    'ISO/IEC 42001:2023 (AI Management System)'
  ];
}
