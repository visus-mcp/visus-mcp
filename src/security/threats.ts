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
 * - IPI-008: Multi-vector - reserved for future use (v0.9.2+)
 */
export type ThreatClass =
  | 'IPI-001' // Instruction Override
  | 'IPI-002' // Role Hijacking
  | 'IPI-003' // Data Exfiltration
  | 'IPI-004' // Tool Abuse
  | 'IPI-005' // Context Poisoning
  | 'IPI-006' // Encoded Payload
  | 'IPI-007' // Steganographic
  | 'IPI-008'; // Multi-vector (reserved for v0.9.2)

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
}
