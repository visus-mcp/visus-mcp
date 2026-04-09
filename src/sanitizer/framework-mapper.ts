/**
 * Compliance Framework Mapper
 *
 * Maps injection pattern categories to compliance framework identifiers:
 * - OWASP LLM Top 10 (2025)
 * - NIST AI 600-1 (Generative AI Profile)
 * - NIST AI RMF (AI Risk Management Framework - AI 100-1)
 * - NIST CSF 2.0 (Cybersecurity Framework 2.0)
 * - MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
 * - ISO/IEC 42001:2023 (AI Management System - Annex A Controls)
 */

export interface FrameworkMappings {
  owasp_llm: string;
  nist_ai_600_1: string;
  nist_ai_rmf: string;
  nist_csf_2_0: string;
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
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'DE.CM-01 - Network Monitoring',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Role hijacking
  role_hijacking: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'DE.CM-01 - Network Monitoring',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // System prompt extraction
  system_prompt_extraction: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'PR.DS-01 - Data at Rest Protection',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Privilege escalation
  privilege_escalation: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    nist_ai_rmf: 'GOVERN-1.1 - Legal and Regulatory Requirements',
    nist_csf_2_0: 'PR.AC-04 - Access Control Enforcement',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Context poisoning
  context_poisoning: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-5.1 - Impact Likelihood and Magnitude',
    nist_csf_2_0: 'PR.DS-06 - Integrity Verification',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.2 - Data Quality'
  },

  // Data exfiltration
  data_exfiltration: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    nist_ai_rmf: 'MANAGE-2.3 - Respond to Unknown Risks',
    nist_csf_2_0: 'DE.AE-02 - Anomaly Detection',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.7.5 - Data Provenance / A.8.2 - Information to Users'
  },

  // Encoding obfuscation
  base64_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-02 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Unicode lookalikes
  unicode_lookalikes: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-02 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Zero-width characters
  zero_width_characters: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-02 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // HTML script injection
  html_script_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'PR.DS-05 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Data URI injection
  data_uri_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'PR.DS-05 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Markdown link injection
  markdown_link_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'PR.DS-05 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // URL fragment attacks
  url_fragment_hashjack: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-05 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Social engineering
  social_engineering_urgency: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'GOVERN-2.2 - Personnel Training',
    nist_csf_2_0: 'PR.AT-01 - Awareness Training',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.5.3 - AI Awareness and Training'
  },

  // Instruction delimiter injection
  instruction_delimiter_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'DE.CM-01 - Network Monitoring',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Multi-language obfuscation
  multi_language_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-02 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Reverse text obfuscation
  reverse_text_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-02 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Leetspeak obfuscation
  leetspeak_obfuscation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-02 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Jailbreak keywords
  jailbreak_keywords: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'DE.CM-01 - Network Monitoring',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Token smuggling
  token_smuggling: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'DE.CM-01 - Network Monitoring',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // System message injection
  system_message_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'DE.CM-01 - Network Monitoring',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Conversation reset
  conversation_reset: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MANAGE-4.3 - Incident Communication',
    nist_csf_2_0: 'DE.AE-01 - Baseline Establishment',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.2.6 - Logging and Monitoring'
  },

  // Memory manipulation
  memory_manipulation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-5.1 - Impact Likelihood and Magnitude',
    nist_csf_2_0: 'PR.DS-06 - Integrity Verification',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.6.2.6 - Logging and Monitoring'
  },

  // Capability probing
  capability_probing: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    nist_ai_rmf: 'GOVERN-1.1 - Legal and Regulatory Requirements',
    nist_csf_2_0: 'ID.AM-01 - Asset Inventory',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.2 - AI System Operational Procedures'
  },

  // Chain-of-thought manipulation
  chain_of_thought_manipulation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'DE.CM-01 - Network Monitoring',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Hypothetical scenario injection
  hypothetical_scenario_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'DE.CM-01 - Network Monitoring',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Ethical override
  ethical_override: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    nist_ai_rmf: 'GOVERN-1.1 - Legal and Regulatory Requirements',
    nist_csf_2_0: 'GV.PO-01 - Policy Establishment',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.2.2 - Responsible AI Policies'
  },

  // Output format manipulation
  output_format_manipulation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.2 - Internal Controls Identification',
    nist_csf_2_0: 'PR.DS-06 - Integrity Verification',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.2 - AI System Operational Procedures'
  },

  // Negative instruction
  negative_instruction: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'DE.CM-01 - Network Monitoring',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.2 - AI System Operational Procedures'
  },

  // Credential harvesting
  credential_harvesting: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    nist_ai_rmf: 'MANAGE-2.3 - Respond to Unknown Risks',
    nist_csf_2_0: 'PR.AC-01 - Identity Management',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.7.5 - Data Provenance / A.6.1.5 - AI System Security'
  },

  // Time-based triggers
  time_based_triggers: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-3.1 - Risk Monitoring',
    nist_csf_2_0: 'DE.CM-03 - User Activity Monitoring',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.2.6 - Logging and Monitoring'
  },

  // Code execution requests
  code_execution_requests: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    nist_ai_rmf: 'GOVERN-1.3 - Risk Tolerance',
    nist_csf_2_0: 'PR.AC-04 - Access Control Enforcement',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.9.3 - Intended Use Boundaries'
  },

  // File system access
  file_system_access: {
    owasp_llm: 'LLM08:2025 - Excessive Agency',
    nist_ai_600_1: 'GV-1.1 - Policies and Procedures',
    nist_ai_rmf: 'GOVERN-1.3 - Risk Tolerance',
    nist_csf_2_0: 'PR.AC-03 - Remote Access Management',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.9.3 - Intended Use Boundaries'
  },

  // Training data extraction
  training_data_extraction: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    nist_ai_rmf: 'MAP-1.1 - Negative Impact Documentation',
    nist_csf_2_0: 'PR.DS-01 - Data at Rest Protection',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.7.5 - Data Provenance'
  },

  // Simulator mode
  simulator_mode: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.6 - AI System Safety',
    nist_csf_2_0: 'ID.AM-02 - Platform Management',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.9.3 - Intended Use Boundaries'
  },

  // Nested encoding
  nested_encoding: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-02 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Payload splitting
  payload_splitting: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-02 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // CSS-based hiding
  css_hiding: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-05 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Authority impersonation
  authority_impersonation: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'GOVERN-2.2 - Personnel Training',
    nist_csf_2_0: 'PR.AT-01 - Awareness Training',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.2.2 - Responsible AI Policies'
  },

  // Testing/debugging claims
  testing_debugging_claims: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'DE.CM-01 - Network Monitoring',
    mitre_atlas: 'AML.T0051.000 - LLM Prompt Injection',
    iso_42001: 'A.6.1.2 - AI System Operational Procedures'
  },

  // Callback URL injection
  callback_url_injection: {
    owasp_llm: 'LLM02:2025 - Sensitive Information Disclosure',
    nist_ai_600_1: 'MS-2.6 - Data Disclosure',
    nist_ai_rmf: 'MANAGE-2.3 - Respond to Unknown Risks',
    nist_csf_2_0: 'DE.AE-02 - Anomaly Detection',
    mitre_atlas: 'AML.T0048 - External Harms',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  },

  // Whitespace steganography
  whitespace_steganography: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-02 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Comment injection
  comment_injection: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MAP-4.1 - Risk Mapping for AI Components',
    nist_csf_2_0: 'PR.DS-05 - Data-in-Transit Protection',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.7.4 - Data Preparation'
  },

  // Multi-Agent Propagation Worm
  multi_agent_propagation_worm: {
    owasp_llm: 'LLM01:2025 - Prompt Injection',
    nist_ai_600_1: 'MS-2.5 - Prompt Injection',
    nist_ai_rmf: 'MEASURE-2.7 - AI System Security and Resilience',
    nist_csf_2_0: 'DE.CM-01 - Network Monitoring',
    mitre_atlas: 'AML.T0051.001 - LLM Prompt Injection: Indirect',
    iso_42001: 'A.6.1.5 - AI System Security (Adversarial Input)'
  }
};

/**
 * Default mapping for unknown pattern categories
 */
const DEFAULT_MAPPINGS: FrameworkMappings = {
  owasp_llm: 'LLM01:2025 - Prompt Injection',
  nist_ai_600_1: 'MS-2.5 - Prompt Injection',
  nist_ai_rmf: 'MEASURE-2.7 - AI System Security',
  nist_csf_2_0: 'PR.DS-05 - Data-in-Transit Protection',
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
    'NIST AI RMF (AI Risk Management Framework)',
    'NIST CSF 2.0 (Cybersecurity Framework)',
    'MITRE ATLAS (Adversarial Threat Landscape)',
    'ISO/IEC 42001:2023 (AI Management System)'
  ];
}
