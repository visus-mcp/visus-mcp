/**
 * Enterprise Integration — OpenTelemetry Collector Exporter
 *
 * Built-in exporter (~2KB) that sends security events to any OTLP HTTP endpoint.
 * No OpenTelemetry SDK required — emits raw OTLP JSON over fetch().
 *
 * This exporter is always bundled with visus-mcp because it has zero
 * external dependencies (just fetch(), available in Node.js 18+).
 *
 * Activates when VISUS_SIEM_ENDPOINT env var is set.
 */

import type { SecurityExporter, SecurityEvent, ExportResult } from '../types.js';

interface OTelCollectorConfig {
  endpoint: string;
  headers?: Record<string, string>;
  serviceName?: string;
}

export class OTelCollectorExporter implements SecurityExporter {
  readonly name = 'otel-collector';

  private endpoint = '';
  private headers: Record<string, string> = {};
  private serviceName = 'visus-mcp';

  async initialize(): Promise<void> {
    // Config is passed through static state (set before initialize)
    // This approach avoids storing config in the instance while keeping
    // the interface clean for dynamic import()
  }

  configure(config: OTelCollectorConfig): void {
    this.endpoint = config.endpoint || 'http://localhost:4318/v1/traces';
    this.headers = config.headers || {};
    this.serviceName = config.serviceName || 'visus-mcp';
  }

  async exportBatch(events: SecurityEvent[]): Promise<ExportResult> {
    try {
      const payload = this.buildOtelPayload(events);

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);

      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.headers,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) {
        return {
          ok: false,
          error: `HTTP ${response.status}: ${response.statusText}`,
          retryable: response.status >= 500,
        };
      }

      return { ok: true };
    } catch (err: any) {
      if (err?.name === 'AbortError') {
        return { ok: false, error: 'request timed out', retryable: true };
      }
      return {
        ok: false,
        error: err?.message || String(err),
        retryable: true,
      };
    }
  }

  async shutdown(): Promise<void> {
    // No persistent connections to close with fetch-based HTTP
  }

  private buildOtelPayload(events: SecurityEvent[]): unknown {
    const nowNanos = (BigInt(Date.now()) * BigInt(1_000_000)).toString();

    return {
      resourceSpans: [
        {
          resource: {
            attributes: [
              { key: 'service.name', value: { stringValue: this.serviceName } },
              { key: 'service.version', value: { stringValue: process.env.npm_package_version || '0.28.0' } },
              { key: 'telemetry.sdk.name', value: { stringValue: 'visus-mcp' } },
              { key: 'telemetry.sdk.language', value: { stringValue: 'typescript' } },
            ],
          },
          scopeSpans: [
            {
              scope: { name: 'visus-mcp.security' },
              spans: events.map((e) => ({
                traceId: generateHexId(32),
                spanId: generateHexId(16),
                name: `visus.${e.event_type}`,
                kind: 1, // INTERNAL
                startTimeUnixNano: nanosFromIso(e.timestamp) || nowNanos,
                endTimeUnixNano: nanosFromIso(e.timestamp) || nowNanos,
                attributes: [
                  { key: 'event_id', value: { stringValue: e.event_id } },
                  { key: 'security.event_type', value: { stringValue: e.event_type } },
                  { key: 'security.severity', value: { stringValue: e.severity } },
                  { key: 'security.risk_score', value: { doubleValue: e.risk_score } },
                  { key: 'security.patterns', value: { arrayValue: { values: e.patterns.map(p => ({ stringValue: p })) } } },
                  { key: 'security.pii_types', value: { arrayValue: { values: e.pii_types.map(p => ({ stringValue: p })) } } },
                  { key: 'security.payload_hash', value: { stringValue: e.payload_hash } },
                  { key: 'security.signature', value: { stringValue: e.signature } },
                  { key: 'security.source', value: { stringValue: e.source } },
                  { key: 'tool.name', value: { stringValue: e.tool_name } },
                  { key: 'session.id', value: { stringValue: e.session_id } },
                ],
                status: { code: 1 }, // StatusOk
              })),
            },
          ],
        },
      ],
    };
  }
}

function generateHexId(length: number): string {
  const chars = '0123456789abcdef';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * 16)];
  }
  return result;
}

function nanosFromIso(iso: string): string | null {
  try {
    const ms = new Date(iso).getTime();
    if (Number.isNaN(ms)) return null;
    return (BigInt(ms) * BigInt(1_000_000)).toString();
  } catch {
    return null;
  }
}



