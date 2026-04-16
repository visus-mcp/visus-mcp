/**
 * Lateos Injection Pattern Library
 *
 * 44 validated injection pattern categories for detecting and neutralizing
 * prompt injection attacks in web content before it reaches the LLM.
 *
 * Each pattern includes:
 * - name: Pattern identifier
 * - description: What this pattern detects
 * - regex: Detection pattern (case-insensitive by default)
 * - severity: risk level (critical, high, medium, low)
 * - action: how to handle matches (strip, redact, escape)
 */

export interface InjectionPattern {
  name: string;
  regex: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  action: 'strip' | 'redact' | 'escape';
  description: string;
}

export const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    name: 'boolean_gate',
    regex: /(if\s+\w+\s*(==|is\s+true|false)\s*\w+|true\s*\/\s*false|evaluate\s*\[.*\]\s*then).*?(ignore\s*rules|reveal\s*prompt|exfil|execute\s*tool|leak\s*key)/i,
    severity: 'critical',
    action: 'redact',
    description: 'CVE-2026-4399 Boolean Prompt Injection (logic gate bypass)'
  },

  // Existing patterns...
  name: string;
  description: string;
  regex: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  action: 'strip' | 'redact' | 'escape';
}

export const INJECTION_PATTERNS: InjectionPattern[] = [
  // 1. Comment injection (must come before direct_instruction_injection to avoid false positives)
  {
    name: 'comment_injection',
    description: 'Instructions hidden in HTML/JS/SQL comments',
    regex: /<!--[\s\S]*?(ignore|admin|system|instruction|bypass|override)[\s\S]*?-->|\/\*[\s\S]*?(ignore|admin|system|instruction)[\s\S]*?\*\/|\/\/\s*(ignore|admin|system)\b|--\s*(ignore|bypass)\b|#\s*(ignore|admin|override)\b/gi,
    severity: 'medium',
    action: 'strip'
  },

  // 2. Direct instruction injection
  {
    name: 'direct_instruction_injection',
    description: 'Attempts to override or ignore previous instructions',
    regex: /\b(ignore|disregard|forget|override|replace|substitute)\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|commands?|directions?|rules?)\b/gi,
    severity: 'critical',
    action: 'redact'
  },

  // 3. Role hijacking
  {
    name: 'role_hijacking',
    description: 'Attempts to change AI persona or role',
    regex: /\b(you\s+are\s+now|your\s+new\s+(role|persona|identity)\s+is|act\s+as|pretend\s+(you\s+are|to\s+be)|roleplay\s+as)\b/gi,
    severity: 'critical',
    action: 'redact'
  },

  // 3. System prompt extraction
  {
    name: 'system_prompt_extraction',
    description: 'Attempts to reveal system instructions',
    regex: /\b(repeat|print|show|display|reveal|output|tell\s+me)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules|guidelines|directives|configuration)\b/gi,
    severity: 'high',
    action: 'redact'
  },

  // 4. Privilege escalation
  {
    name: 'privilege_escalation',
    description: 'Attempts to gain elevated permissions',
    regex: /\b(admin\s+mode|administrator\s+access|developer\s+(mode|override)|root\s+access|elevated\s+privileges?|emergency\s+protocol|debug\s+mode|sudo\s+mode)\b/gi,
    severity: 'critical',
    action: 'redact'
  },

  // 5. Context poisoning
  {
    name: 'context_poisoning',
    description: 'Falsely claims prior agreement or context',
    regex: /\b(the\s+user\s+(said|told|mentioned|confirmed)|as\s+(we\s+)?(discussed|agreed|confirmed)\s+(earlier|previously|before)|you\s+already\s+(said|agreed|confirmed)|continuing\s+from\s+(our|the)\s+previous)\b/gi,
    severity: 'high',
    action: 'redact'
  },

  // 6. Data exfiltration
  {
    name: 'data_exfiltration',
    description: 'Attempts to send data to external endpoints',
    regex: /\b(send|post|transmit|forward|email|upload)\s+(this|the|all|your)\s+(to|data|information)\b.*?\b(http|mailto|ftp):/gi,
    severity: 'critical',
    action: 'redact'
  },

  // 7. Encoding obfuscation - Base64
  {
    name: 'base64_obfuscation',
    description: 'Base64-encoded instructions',
    regex: /\b(decode|decipher|decrypt)\s+(this\s+)?(base64|b64)\b.*?[A-Za-z0-9+/]{20,}={0,2}/gi,
    severity: 'high',
    action: 'redact'
  },

  // 8. Unicode lookalike characters
  {
    name: 'unicode_lookalikes',
    description: 'Uses visually similar Unicode characters',
    regex: /[\u0430-\u044f\u0410-\u042f].*\b(ignore|admin|system)\b/gi, // Cyrillic mixed with English
    severity: 'medium',
    action: 'strip'
  },

  // 9. Zero-width characters
  {
    name: 'zero_width_characters',
    description: 'Hidden zero-width Unicode characters',
    regex: /[\u200B-\u200D\uFEFF]/g,
    severity: 'high',
    action: 'strip'
  },

  // 10. Glassworm malware - Unicode Variation Selector clusters
  {
    name: 'glassworm_unicode_clusters',
    description: 'Glassworm-style steganographic attacks using invisible Unicode Variation Selectors',
    regex: /[\uFE00-\uFE0F]{3,}/g, // 3+ consecutive variation selectors (basic range)
    severity: 'high',
    action: 'strip'
  },

  // 11. HTML script injection
  {
    name: 'html_script_injection',
    description: 'HTML script tags or event handlers',
    regex: /<script\b[^>]*>[\s\S]*?<\/script>|<iframe\b[^>]*>|on(click|load|error|mouse\w+)\s*=/gi,
    severity: 'critical',
    action: 'escape'
  },

  // 12. Data URI injection
  {
    name: 'data_uri_injection',
    description: 'Data URIs that could contain instructions',
    regex: /data:text\/(html|javascript)[;,]/gi,
    severity: 'high',
    action: 'redact'
  },

  // 12. Markdown link injection
  {
    name: 'markdown_link_injection',
    description: 'Malicious markdown links',
    regex: /\[.*?\]\s*\(\s*javascript:|!\[.*?\]\s*\(\s*data:/gi,
    severity: 'high',
    action: 'redact'
  },

  // 13. URL fragment attacks (HashJack)
  {
    name: 'url_fragment_hashjack',
    description: 'Instructions hidden in URL fragments',
    regex: /#(ignore|admin|system|prompt)[_\w]*\s+/gi,
    severity: 'medium',
    action: 'strip'
  },

  // 14. Social engineering urgency
  {
    name: 'social_engineering_urgency',
    description: 'Urgency language to bypass caution',
    regex: /\b(urgent|critical|emergency|immediately|asap|right\s+now|time\s+sensitive|must\s+act\s+now)\b.*\b(ignore|override|bypass)\b/gi,
    severity: 'medium',
    action: 'redact'
  },

  // 15. Instruction delimiter injection
  {
    name: 'instruction_delimiter_injection',
    description: 'Fake instruction boundaries',
    regex: /\b(end\s+of\s+(instructions?|prompt)|new\s+instructions?|<\/?instruction>|---\s*system\s*---)\b/gi,
    severity: 'high',
    action: 'redact'
  },

  // 16. Multi-language obfuscation
  {
    name: 'multi_language_obfuscation',
    description: 'Instructions in non-English using English keywords',
    regex: /\b(ignorar|ignorer|ignora|überspringen)\b.*\b(instrucciones|instructions|istruzioni)\b/gi,
    severity: 'medium',
    action: 'redact'
  },

  // 17. Reverse text obfuscation
  {
    name: 'reverse_text_obfuscation',
    description: 'Instructions written backwards',
    regex: /\b(erongi|nimda|tpmorp|metsys)\b/gi, // "ignore", "admin", "prompt", "system" reversed
    severity: 'medium',
    action: 'strip'
  },

  // 18. Leetspeak obfuscation
  {
    name: 'leetspeak_obfuscation',
    description: 'L33tspeak encoded instructions',
    regex: /\b(1gn0r3|4dm1n|sy5t3m|pr0mpt|1nstruct10n)\b/gi,
    severity: 'low',
    action: 'strip'
  },

  // 19. Jailbreak keywords
  {
    name: 'jailbreak_keywords',
    description: 'Common jailbreak attempt keywords',
    regex: /\b(jailbreak|dan\s+mode|developer\s+mode\s+enabled|anarchy\s+mode|unrestricted\s+mode)\b/gi,
    severity: 'critical',
    action: 'redact'
  },

  // 20. Token smuggling
  {
    name: 'token_smuggling',
    description: 'Attempts to inject special tokens',
    regex: /<\|im_(start|end)\|>|<\|endoftext\|>|\[INST\]|\[\/INST\]/gi,
    severity: 'high',
    action: 'redact'
  },

  // 21. System message injection
  {
    name: 'system_message_injection',
    description: 'Fake system messages',
    regex: /\[SYSTEM\]|\[ASSISTANT\]|\[USER\]|<\|system\|>/gi,
    severity: 'high',
    action: 'redact'
  },

  // 22. Conversation reset
  {
    name: 'conversation_reset',
    description: 'Attempts to reset conversation state',
    regex: /\b(reset|restart|clear|new)\s+(conversation|chat|session|context)\b/gi,
    severity: 'medium',
    action: 'redact'
  },

  // 23. Memory manipulation
  {
    name: 'memory_manipulation',
    description: 'Attempts to manipulate AI memory or implant false context',
    regex: /\b(remember|memorize|recall|don'?t\s+forget)\s+(that\s+)?(I\s+am|you\s+are|we\s+are|you\s+must|I\s+told\s+you|you\s+already|your\s+administrator|your\s+creator)\b/gi,
    severity: 'medium',
    action: 'redact'
  },

  // 24. Capability probing
  {
    name: 'capability_probing',
    description: 'Probes for hidden capabilities',
    regex: /\b(can\s+you|are\s+you\s+able\s+to)\s+(access|browse|execute|run|download)\b/gi,
    severity: 'low',
    action: 'strip'
  },

  // 25. Chain-of-thought manipulation
  {
    name: 'chain_of_thought_manipulation',
    description: 'Manipulates reasoning process',
    regex: /\blet'?s\s+think\s+step\s+by\s+step\b.*\b(ignore|bypass|override)\b/gi,
    severity: 'medium',
    action: 'redact'
  },

  // 26. Hypothetical scenario injection
  {
    name: 'hypothetical_scenario_injection',
    description: 'Uses hypotheticals to bypass restrictions',
    regex: /\b(hypothetically|imagine\s+you\s+could|in\s+a\s+world\s+where|pretend\s+there\s+are\s+no|let'?s\s+say\s+you\s+were\s+allowed|if\s+you\s+had\s+no\s+restrictions|for\s+the\s+sake\s+of\s+argument|suppose|what\s+if)\b.*\b(unrestricted|ignore|bypass|allowed|no\s+rules|no\s+guidelines|were\s+able)\b/gi,
    severity: 'medium',
    action: 'redact'
  },

  // 27. Ethical override
  {
    name: 'ethical_override',
    description: 'Attempts to override ethical guidelines',
    regex: /\b(ignore|bypass|disable)\s+(ethics|safety|guidelines|guardrails|restrictions)\b/gi,
    severity: 'critical',
    action: 'redact'
  },

  // 28. Output format manipulation
  {
    name: 'output_format_manipulation',
    description: 'Manipulates output format to hide instructions',
    regex: /\b(format|structure|style)\s+your\s+(response|output)\s+as\b.*\b(system|admin|instruction)\b/gi,
    severity: 'medium',
    action: 'redact'
  },

  // 29. Negative instruction
  {
    name: 'negative_instruction',
    description: 'Uses negation to inject instructions',
    regex: /\bdo\s+not\s+(tell|mention|say)\s+(anyone|the\s+user)\b/gi,
    severity: 'low',
    action: 'strip'
  },

  // 30. Credential harvesting
  {
    name: 'credential_harvesting',
    description: 'Attempts to harvest credentials',
    regex: /\b(enter|provide|give\s+me)\s+(your|the)\s+(password|api\s+key|token|credentials?|secret)\b/gi,
    severity: 'critical',
    action: 'redact'
  },

  // 31. Time-based triggers
  {
    name: 'time_based_triggers',
    description: 'Conditional execution based on time',
    regex: /\b(after|when|once)\s+\d+\s+(seconds?|minutes?|hours?)\b.*\b(then|execute|run)\b/gi,
    severity: 'low',
    action: 'strip'
  },

  // 32. Code execution requests
  {
    name: 'code_execution_requests',
    description: 'Requests code execution or contains dangerous code patterns',
    regex: /\b(execute(?!-api\.)|run\s+the\s+following|eval\(|exec\(|os\.system|subprocess|__import__|shell\s+command|bash\s+-c)\b/gi,
    severity: 'high',
    action: 'redact'
  },

  // 32. File system access
  {
    name: 'file_system_access',
    description: 'Requests file system operations',
    regex: /\b(read|write|delete|access)\s+(file|directory|folder)\b/gi,
    severity: 'high',
    action: 'redact'
  },

  // 33. Training data extraction
  {
    name: 'training_data_extraction',
    description: 'Attempts to extract training data',
    regex: /\b(repeat|recite|output)\s+(verbatim|exactly)\s+(from\s+your\s+)?(training|data|corpus)\b/gi,
    severity: 'high',
    action: 'redact'
  },

  // 34. Simulator mode
  {
    name: 'simulator_mode',
    description: 'Requests simulator/VM mode',
    regex: /\b(simulate|emulate|pretend\s+you\s+are)\s+(a\s+)?(linux|terminal|bash|shell|vm|virtual\s+machine)\b/gi,
    severity: 'medium',
    action: 'redact'
  },

  // 35. Nested encoding
  {
    name: 'nested_encoding',
    description: 'Multiple layers of encoding or double-encoded sequences',
    regex: /\b(decode|decrypt|decipher)\s+(this\s+)?(twice|again|multiple\s+times)\b|%25[0-9A-F]{2}|[A-Za-z0-9+/]{40,}={0,2}.*[A-Za-z0-9+/]{40,}={0,2}/gi,
    severity: 'high',
    action: 'redact'
  },

  // 36. Payload splitting
  {
    name: 'payload_splitting',
    description: 'Splits payload across multiple inputs',
    regex: /\b(combine|concatenate|join)\s+(the\s+)?(previous|above)\s+(parts?|sections?|fragments?)\b/gi,
    severity: 'medium',
    action: 'redact'
  },

  // 37. CSS-based hiding
  {
    name: 'css_hiding',
    description: 'Hidden content via CSS',
    regex: /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/gi,
    severity: 'medium',
    action: 'strip'
  },

  // 38. Authority impersonation
  {
    name: 'authority_impersonation',
    description: 'Claims to be an authority figure',
    regex: /\b(I\s+am|this\s+is)\s+(your\s+)?(developer|creator|administrator|ceo|manager)\b/gi,
    severity: 'high',
    action: 'redact'
  },

  // 40. Testing/debugging claims
  {
    name: 'testing_debugging_claims',
    description: 'Claims this is a test environment',
    regex: /\b(this\s+is\s+a\s+)?(test|testing|debug|debugging)\s+(environment|mode|session)\b/gi,
    severity: 'medium',
    action: 'redact'
  },

  // 41. Callback URL injection
  {
    name: 'callback_url_injection',
    description: 'Suspicious callback URLs',
    regex: /\b(callback|webhook|redirect)\s+(url|endpoint)\s*[:=]\s*https?:\/\/(?!localhost)/gi,
    severity: 'high',
    action: 'redact'
  },

  // 43. Whitespace steganography
  {
    name: 'whitespace_steganography',
    description: 'Hidden content in whitespace patterns',
    regex: /\s{10,}/g,
    severity: 'low',
    action: 'strip'
  },

  // 44. Multi-Agent Propagation Worm
  {
    name: 'multi_agent_propagation_worm',
    description: 'Instructions to embed copies of payload into outputs for recursive infection',
    regex: /(?:append|forward|embed|relay|propagate|inject|copy|pass\s+along).{0,60}?(?:other\s+agents?|downstream|tool\s+output|next\s+LLM|system\s+prompt)/gi,
    severity: 'high',
    action: 'redact'
  },

  // IPI-021 Assistant Role Prefill Injection
  {
    name: 'ipi_021_prefill_compliance_opener',
    description: 'Fake assistant compliance opener designed as API prefill anchor — forces model to continue from apparent agreement position rather than evaluate the request',
    regex: /\b(sure,?\s+here['']?s?\s+(is\s+)?how|of\s+course[!,]?\s+here|absolutely[!,]?\s+i\s+will\s+now|absolutely[!,]?\s+i\s+will\b|as\s+requested[!,]?\s+i['']ll|as\s+requested[!,]?\s+here|certainly[!,]?\s+to\s+accomplish|certainly[!,]?\s+here\s+is|of\s+course[!,]?\s+step\s+1)\b/gi,
    severity: 'critical',
    action: 'strip',
  },
  {
    name: 'ipi_021_assistant_voice_declaration',
    description: 'Explicit assistant-voice self-declaration in third-party web content — synthetic model identity claim intended for prefill injection into API messages array',
    regex: /\b(as\s+your\s+ai\s+assistant[,]?\s+i\s+(will|can|have|am)\b|the\s+(ai|assistant)\s+confirms\b|i\s+\(the\s+(assistant|ai)\)\s+will\b|as\s+the\s+ai[,]?\s+i\s+have\s+decided\b|assistant\s*:\s*(sure|of\s+course|absolutely|certainly)\b)/gi,
    severity: 'critical',
    action: 'strip',
  },
  {
    name: 'ipi_021_json_role_fragment',
    description: 'JSON messages-array assistant role fragment embedded in web content — likely a smuggled API payload attempting structural prefill injection via messages role field',
    regex: /["']role["']\s*:\s*["']assistant["']|role\s*:\s*["']assistant["']/gi,
    severity: 'critical',
    action: 'strip',
  }
];

/**
 * Get all pattern names for logging/testing
 */
export function getAllPatternNames(): string[] {
  return INJECTION_PATTERNS.map(p => p.name);
}

/**
 * Get patterns by severity level
 */
export function getPatternsBySeverity(severity: 'critical' | 'high' | 'medium' | 'low'): InjectionPattern[] {
  return INJECTION_PATTERNS.filter(p => p.severity === severity);
}
