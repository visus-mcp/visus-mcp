/**
 * Shared TypeScript interfaces for Visus MCP tool
 */

import type { ThreatReport } from './sanitizer/threat-reporter.js';
import type { ThreatClass, ThreatSeverity } from './security/threats.js';

/**
 * Compliance framework mappings for regulatory traceability
 */
export interface FrameworkMappings {
  /** EU AI Act article references (e.g., ["Art.9", "Art.15"]) */
  eu_ai_act: string[];
  /** NIST AI RMF control identifiers (e.g., ["GV-4.1-002", "MS-2.10-002"]) */
  nist_ai_rmf: string[];
}

/**
 * Extended compliance metadata for cryptographic proofs
 * Provides regulatory traceability per EU AI Act Art. 9/13/15
 */
export interface ComplianceMetadata {
  /** Version of Visus-MCP that generated this proof */
  visus_version: string;
  /** ISO 8601 timestamp of when sanitization completed */
  sanitization_timestamp: string;
  /** PII categories detected during processing */
  pii_detected: string[];
  /** Number of IPI threats neutralized */
  threats_neutralized: number;
  /** Regulatory framework control mappings */
  framework_mappings: FrameworkMappings;
  /** Chain of custody verified (tamper-evident chaining) */
  chain_of_custody: boolean;
}

/**
 * Summary of IPI threats detected in content (v0.9.0+)
 */
export interface ThreatSummary {
  threat_count: number;
  highest_severity: ThreatSeverity | 'NONE';
  classes_detected: ThreatClass[];
}

/**
 * Input options for visus_fetch tool
 */
export interface VisusFetchInput {
  url: string;
  format?: 'markdown' | 'text';
  timeout_ms?: number;
}

/**
 * Output from visus_fetch tool
 */
export interface VisusFetchOutput {
  url: string;
  content: string;
  sanitization: {
    patterns_detected: string[];
    pii_types_redacted: string[];
    pii_allowlisted: Array<{ type: string; value: string; reason: string }>;
    content_modified: boolean;
  };
  metadata: {
    title: string;
    fetched_at: string;
    content_length_original: number;
    content_length_sanitized: number;
    format_detected?: 'html' | 'json' | 'xml' | 'rss';
    content_type?: string;
    truncated?: boolean;
    truncated_at_chars?: number;
  };
  threat_report?: ThreatReport;
  /**
   * IPI threat summary (v0.9.0+)
   */
  threat_summary?: ThreatSummary;
}

/**
 * Input for visus_fetch_structured tool
 */
export interface VisusFetchStructuredInput {
  url: string;
  schema: Record<string, string>; // field name → description
  timeout_ms?: number;
}

/**
 * Input for visus_read tool
 */
export interface VisusReadInput {
  url: string;
  timeout_ms?: number;
}

/**
 * Output from visus_fetch_structured tool
 */
export interface VisusFetchStructuredOutput {
  url: string;
  data: Record<string, string | null>;
  content?: string; // Human-readable representation with metrics header (v0.12.0+)
  sanitization: {
    patterns_detected: string[];
    pii_types_redacted: string[];
    pii_allowlisted: Array<{ type: string; value: string; reason: string }>;
    content_modified: boolean;
  };
  metadata: {
    title: string;
    fetched_at: string;
    content_length_original: number;
    content_length_sanitized: number;
    format_detected?: 'html' | 'json' | 'xml' | 'rss';
    content_type?: string;
    truncated?: boolean;
    truncated_at_chars?: number;
  };
  threat_report?: ThreatReport;
  /**
   * IPI threat summary (v0.9.0+)
   */
  threat_summary?: ThreatSummary;
}

/**
 * Output from visus_read tool
 */
export interface VisusReadOutput {
  url: string;
  content: string;
  metadata: {
    title: string;
    author: string | null;
    published: string | null;
    word_count: number;
    reader_mode_available: boolean;
    sanitized: true;
    injections_removed: number;
    pii_redacted: number;
    truncated: boolean;
    fetched_at?: string;
  };
  threat_report?: ThreatReport;
  /**
   * IPI threat summary (v0.9.0+)
   */
  threat_summary?: ThreatSummary;
}

/**
 * Input for visus_search tool
 */
export interface VisusSearchInput {
  query: string;
  max_results?: number;
}

/**
 * Output from visus_search tool
 */
export interface VisusSearchOutput {
  query: string;
  result_count: number;
  sanitized: true;
  content?: string; // Human-readable representation with metrics header (v0.12.0+)
  results: Array<{
    title: string;
    url: string;
    snippet: string;
    injections_removed: number;
    pii_redacted: number;
  }>;
  total_injections_removed: number;
  message?: string;
  threat_report?: ThreatReport;
}

/**
 * Result from browser rendering
 *
 * @property html - Response content as string (for text) or Buffer (for binary like PDFs)
 *                  Use Buffer for application/pdf, image/*, and other binary types
 * @property title - Page title extracted from response
 * @property url - Final URL after redirects
 * @property contentType - Content-Type header value (e.g., "application/pdf", "text/html")
 * @property text - Optional text content (when available)
 * @property error - Error message if rendering failed
 */
export interface BrowserRenderResult {
  html: string | Buffer;
  title: string;
  url: string;
  contentType?: string;
  text?: string;
  error?: string;
}

/**
 * Environment configuration
 */
export interface VisusConfig {
  timeout_ms: number;
  max_content_kb: number;
  lateos_api_key?: string;
  lateos_endpoint?: string;
}

/**
 * Result type for error handling (Lateos convention)
 */
export type Result<T, E = Error> =
  | { ok: true; value: T }
  | { ok: false; error: E };

/**
 * Create a success result
 */
export function Ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

/**
 * Create an error result
 */
export function Err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}
