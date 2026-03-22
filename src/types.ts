/**
 * Shared TypeScript interfaces for Visus MCP tool
 */

import type { ThreatReport } from './sanitizer/threat-reporter.js';

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
    truncated?: boolean;
    truncated_at_chars?: number;
  };
  threat_report?: ThreatReport;
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
    truncated?: boolean;
    truncated_at_chars?: number;
  };
  threat_report?: ThreatReport;
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
 */
export interface BrowserRenderResult {
  html: string;
  title: string;
  url: string;
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
