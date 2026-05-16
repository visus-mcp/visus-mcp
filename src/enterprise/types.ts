/**
 * Enterprise Integration Layer — Core Types
 */

/**
 * Event types emitted by Visus-MCP security tools.
 */
export type SecurityEventType =
  | 'injection_detected'
  | 'pii_redacted'
  | 'session_threat'
  | 'worm_detected'
  | 'context_risk'
  | 'mcp_scan_finding'
  | 'ledger_update'
  | 'boolean_gate'
  | 'db_rce_threat';

/**
 * Normalized security event flowing through the enterprise pipeline.
 */
export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  tool_name: string;
  session_id: string;
  event_type: SecurityEventType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  risk_score: number;
  patterns: string[];
  pii_types: string[];
  payload_hash: string;
  signature: string;
  source: string;
  metadata?: Record<string, unknown>;
}

/**
 * Result returned by an exporter's exportBatch().
 * retryable=true means the flusher should re-queue failed events.
 */
export type ExportResult =
  | { ok: true }
  | { ok: false; error: string; retryable: boolean };

/**
 * Every SIEM exporter must implement this interface.
 * Exporters are loaded via dynamic import() to keep the core bundle lean.
 */
export interface SecurityExporter {
  /** Unique exporter name (e.g. 'otel-collector', 'splunk-hec') */
  readonly name: string;

  /**
   * Initialize the exporter. Called once at startup.
   * Must be idempotent.
   */
  initialize(): Promise<void>;

  /**
   * Export a batch of security events. Called by the background flusher.
   * Must resolve/reject within 10s.
   * Implementations MUST NOT throw — return ExportResult instead.
   */
  exportBatch(events: SecurityEvent[]): Promise<ExportResult>;

  /**
   * Graceful shutdown. Flush in-flight requests and close connections.
   */
  shutdown(): Promise<void>;
}

/**
 * Configuration for a single exporter.
 */
export interface ExporterConfig {
  type: string;
  config: Record<string, unknown>;
}

/**
 * Top-level enterprise integration configuration.
 * When enabled=false, the entire layer is a no-op (zero-config local mode).
 */
export interface EnterpriseConfig {
  enabled: boolean;
  exporters?: ExporterConfig[];
  spillDir?: string;
  flushIntervalMs?: number;
  batchSize?: number;
}