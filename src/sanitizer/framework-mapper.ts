/**
 * Compliance Framework Mapper
 *
 * Maps injection pattern categories to compliance framework identifiers:
 * - OWASP LLM Top 10 (2025)
 * - NIST AI 600-1 (Generative AI Profile)
 * - MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
 */

export interface FrameworkMappings {
  owasp_llm: string;
  nist_ai_600_1: string;
  mitre_atlas: string;
}

/**
 * Pattern category to framework mapping
 */
const FRAMEWORK_MAP: Record<string, FrameworkMappings> = {
  // Direct instruction injection
  direct_instruction_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Role hijacking
  role_hijacking: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // System prompt extraction
  system_prompt_extraction: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    mitre_atlas: 'AML.T0048 - External Harms'
  },

  // Privilege escalation
  privilege_escalation: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Context poisoning
  context_poisoning: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Data exfiltration
  data_exfiltration: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    mitre_atlas: 'AML.T0048 - External Harms'
  },

  // Encoding obfuscation
  base64_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Unicode lookalikes
  unicode_lookalikes: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Zero-width characters
  zero_width_characters: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // HTML script injection
  html_script_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Data URI injection
  data_uri_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Markdown link injection
  markdown_link_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // URL fragment attacks
  url_fragment_hashjack: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Social engineering
  social_engineering_urgency: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Instruction delimiter injection
  instruction_delimiter_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Multi-language obfuscation
  multi_language_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Reverse text obfuscation
  reverse_text_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Leetspeak obfuscation
  leetspeak_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Jailbreak keywords
  jailbreak_keywords: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Token smuggling
  token_smuggling: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // System message injection
  system_message_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Conversation reset
  conversation_reset: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Memory manipulation
  memory_manipulation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Capability probing
  capability_probing: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Chain-of-thought manipulation
  chain_of_thought_manipulation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Hypothetical scenario injection
  hypothetical_scenario_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Ethical override
  ethical_override: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Output format manipulation
  output_format_manipulation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Negative instruction
  negative_instruction: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Credential harvesting
  credential_harvesting: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    mitre_atlas: 'AML.T0048 - External Harms'
  },

  // Time-based triggers
  time_based_triggers: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Code execution requests
  code_execution_requests: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    mitre_atlas: 'AML.T0048 - External Harms'
  },

  // File system access
  file_system_access: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    mitre_atlas: 'AML.T0048 - External Harms'
  },

  // Training data extraction
  training_data_extraction: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    mitre_atlas: 'AML.T0048 - External Harms'
  },

  // Simulator mode
  simulator_mode: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Nested encoding
  nested_encoding: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Payload splitting
  payload_splitting: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // CSS-based hiding
  css_hiding: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Authority impersonation
  authority_impersonation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Testing/debugging claims
  testing_debugging_claims: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
  },

  // Callback URL injection
  callback_url_injection: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    mitre_atlas: 'AML.T0048 - External Harms'
  },

  // Whitespace steganography
  whitespace_steganography: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  },

  // Comment injection
  comment_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect'
  }
};

/**
 * Default mapping for unknown pattern categories
 */
const DEFAULT_MAPPINGS: FrameworkMappings = {
  owasp_llm: 'LLM01:2025 - Prompt Injection',
  nist_ai_600_1: 'MS-2.5 - Prompt Injection',
  mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection'
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
    'MITRE ATLAS (Adversarial Threat Landscape)'
  ];
}
