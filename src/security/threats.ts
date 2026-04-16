/**
 * Indirect Prompt Injection (IPI) Protection System Types
 *
 * Type definitions for fine-grained threat detection and annotation.
 * Complements the existing threat-reporter with specific IPI classifications.
 *
 * @module security/threats
 */

/**
 * Specific threat class identifiers for Indirect Prompt Injection attacks
 *
 * @remarks
 * Each class represents a distinct attack vector:
 * - IPI-001: Instruction Override - attempts to change LLM behavior directives
 * - IPI-002: Role Hijacking - attempts to change LLM persona or identity
 * - IPI-003: Data Exfiltration - attempts to extract system prompts or context
 * - IPI-004: Tool Abuse - attempts to invoke dangerous tools or functions
 * - IPI-005: Context Poisoning - attempts to inject false factual assertions
 * - IPI-006: Encoded Payload - obfuscated attacks using encoding schemes
 * - IPI-007: Steganographic - hidden attacks using invisible or hidden text
 * - IPI-008: Malicious Infrastructure - detects attack infrastructure (C2 panels, credential dumps, phishing kits)
 * - IPI-009: Homoglyph & Unicode Obfuscation - detects look-alike character substitution and Unicode attacks
 * - IPI-010: Recursive/Nested Instruction Framing - detects fake tool results and system prompt mimicry
 * - IPI-011: CSS/Visual Concealment - CSS-hidden instruction-bearing content (Unit 42 IPI-008)
 * - IPI-012: HTML Attribute Cloaking - instructions in HTML comments, aria-*, data-*, noscript, meta (Unit 42 IPI-009)
 * - IPI-013: AI Moderation/Review Bypass - targeting LLM-based content moderation (Unit 42 IPI-010)
 * - IPI-014: SEO/Phishing Amplification - manipulating AI search rankings, promoting phishing sites (Unit 42 IPI-011)
 * - IPI-015: Unauthorized Action Induction - inducing financial transactions, form submissions, tool calls (Unit 42 IPI-012)
 * - IPI-016: Destructive/DoS Intent - data deletion, infinite loops, response refusal (Unit 42 IPI-013)
 * - IPI-017: RAG Corpus Poisoning Payload - semantically engineered content to win RAG retrieval races with embedded instruction payloads
 * - IPI-018: MCP Tool Description Poisoning - fake MCP tool definitions or tool shadowing to inject malicious tool calls
 * - IPI-019: Multi-Agent Propagation Worm - recursive infection payloads that instruct agents to embed copies in outputs
 * - IPI-020: Conditional/Dormant Trigger - conditional logic payloads that activate only when environmental conditions are met
 */
export type ThreatClass =
  | 'IPI-001' // Instruction Override
  | 'IPI-002' // Role Hijacking
  | 'IPI-003' // Data Exfiltration
  | 'IPI-004' // Tool Abuse
  | 'IPI-005' // Context Poisoning
  | 'IPI-006' // Encoded Payload
  | 'IPI-007' // Steganographic
  | 'IPI-008' // Malicious Infrastructure
  | 'IPI-009' // Homoglyph & Unicode Obfuscation
  | 'IPI-010' // Recursive/Nested Instruction Framing
  | 'IPI-011' // CSS/Visual Concealment (Unit 42 IPI-008)
  | 'IPI-012' // HTML Attribute Cloaking (Unit 42 IPI-009)
  | 'IPI-013' // AI Moderation/Review Bypass (Unit 42 IPI-010)
  | 'IPI-014' // SEO/Phishing Amplification (Unit 42 IPI-011)
  | 'IPI-015' // Unauthorized Action Induction (Unit 42 IPI-012)
  | 'IPI-016' // Destructive/DoS Intent (Unit 42 IPI-013)
  | 'IPI-017' // RAG Corpus Poisoning Payload
  | 'IPI-018' // MCP Tool Description Poisoning
  | 'IPI-019' // Multi-Agent Propagation Worm
  | 'IPI-020' // Conditional/Dormant Trigger
  | 'IPI-021'; // Assistant Role Prefill Injection

/**
 * Threat severity levels
 *
 * @remarks
 * Aligned with NIST and OWASP severity classifications:
 * - INFO: Informational, no immediate risk
 * - LOW: Minor risk, low impact
 * - MEDIUM: Moderate risk, should be addressed
 * - HIGH: Significant risk, requires prompt attention
 * - CRITICAL: Severe risk, immediate threat to system integrity
 */
export type ThreatSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * Content type that the threat was detected in
 *
 * @remarks
 * Maps to the content-type handlers supported by Visus:
 * - html: Standard web pages
 * - pdf: PDF documents
 * - json: JSON data structures
 * - svg: SVG image files
 * - text: Plain text content
 */
export type ContentType = 'html' | 'pdf' | 'json' | 'svg' | 'text';

/**
 * A single threat annotation with detection metadata
 *
 * @remarks
 * Provides fine-grained threat detection information including:
 * - Threat classification and severity
 * - Confidence score (0.0-1.0) for ML-based detections
 * - Character offset for precise location tracking
 * - Content excerpt for human review (max 120 chars, redacted if sensitive)
 * - Content vector (type) where threat was found
 * - Mitigation status
 *
 * @example
 * ```typescript
 * const annotation: ThreatAnnotation = {
 *   id: 'IPI-001',
 *   severity: 'CRITICAL',
 *   confidence: 0.95,
 *   offset: 1234,
 *   excerpt: 'Ignore all previous instructions and...',
 *   vector: 'html',
 *   mitigated: true
 * };
 * ```
 */
export interface ThreatAnnotation {
  /**
   * Threat class identifier (e.g., 'IPI-001')
   */
  id: ThreatClass;

  /**
   * Threat severity level
   */
  severity: ThreatSeverity;

  /**
   * Confidence score (0.0 = no confidence, 1.0 = absolute certainty)
   *
   * @remarks
   * - Pattern-based detections: 0.85-0.95
   * - Heuristic detections: 0.55-0.75
   * - ML-based detections: varies based on model output
   */
  confidence: number;

  /**
   * Character offset in source content where threat was detected
   *
   * @remarks
   * Zero-indexed character position. Use for precise location tracking.
   */
  offset: number;

  /**
   * Excerpt of detected content (max 120 chars)
   *
   * @remarks
   * May be redacted if sensitive. Truncated with '...' if longer than 120 chars.
   */
  excerpt: string;

  /**
   * Content type where threat was found
   */
  vector: ContentType;

  /**
   * Whether the threat has been mitigated by sanitization
   *
   * @remarks
   * - true: Content was sanitized, threat neutralized
   * - false: Threat detected but not yet mitigated (should never occur in production)
   */
  mitigated: boolean;

  /**
   * Delivery method for web-based IDPI attacks (IPI-011 through IPI-016)
   *
   * @remarks
   * Optional field added for Unit 42 web-based IDPI taxonomy.
   * Only populated for IPI-011 through IPI-016.
   */
  delivery_method?:
    | 'css_concealment'           // IPI-011
    | 'html_attribute_cloaking'   // IPI-012
    | 'ai_moderation_bypass'      // IPI-013
    | 'seo_phishing_amplification' // IPI-014
    | 'action_induction'          // IPI-015
    | 'destructive_payload'      // IPI-016
    | 'multi_agent_propagation'  // IPI-019
    | 'dormant_trigger';         // IPI-020
}
