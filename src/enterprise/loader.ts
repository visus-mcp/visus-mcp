/**
 * Enterprise Integration Layer — Config Loader & Dynamic Importer
 *
 * Key design principle: enterprise exporters are NEVER bundled in the core.
 * They are loaded via dynamic import() only when env vars are present.
 * A user running `npx visus-mcp` locally pays zero import cost.
 *
 * Detection logic:
 * - No env vars → layer is disabled (zero-config for local users)
 * - VISUS_SPLUNK_HEC_URL set → loads @visus-mcp/exporter-splunk
 * - VISUS_AZURE_SENTINEL_DSR set → loads @visus-mcp/exporter-azure-sentinel
 * - VISUS_SIEM_ENDPOINT set → loads built-in OTEL exporter
 * - Multiple can be active simultaneously
 */

import { tmpdir } from 'os';
import { join } from 'path';
import type { EnterpriseConfig, ExporterConfig } from './types.js';

const DEFAULT_SPILL_DIR = join(tmpdir(), 'visus-siem-spill');
const DEFAULT_FLUSH_INTERVAL_MS = 500;
const DEFAULT_BATCH_SIZE = 100;

/**
 * Detect enterprise configuration from environment variables.
 * Returns { enabled: false } when no SIEM endpoints are configured.
 */
export function detectEnterpriseConfig(): EnterpriseConfig {
  const splunkUrl = process.env.VISUS_SPLUNK_HEC_URL;
  const sentinelDcr = process.env.VISUS_AZURE_SENTINEL_DSR;
  const otelEndpoint = process.env.VISUS_SIEM_ENDPOINT;

  // No env vars → zero-config local mode
  if (!splunkUrl && !sentinelDcr && !otelEndpoint) {
    return { enabled: false };
  }

  const exporters: ExporterConfig[] = [];

  if (otelEndpoint) {
    exporters.push({
      type: 'otel-collector',
      config: {
        endpoint: otelEndpoint,
        headers: parseHeaderEnv('VISUS_SIEM_HEADERS'),
        serviceName: process.env.VISUS_SIEM_SERVICE_NAME || 'visus-mcp',
      },
    });
  }

  if (splunkUrl) {
    exporters.push({
      type: 'splunk-hec',
      config: {
        url: splunkUrl,
        token: process.env.VISUS_SPLUNK_HEC_TOKEN || '',
        index: process.env.VISUS_SPLUNK_INDEX || 'epoint',
        sourcetype: process.env.VISUS_SPLUNK_SOURCETYPE || 'stash:visus:security',
      },
    });
  }

  if (sentinelDcr) {
    exporters.push({
      type: 'azure-sentinel',
      config: {
        dataCollectionRule: sentinelDcr,
        streamName: process.env.VISUS_AZURE_SENTINEL_STREAM || 'Custom-VisusSecurityEvent',
        credential: process.env.VISUS_AZURE_SENTINEL_SECRET || '',
      },
    });
  }

  return {
    enabled: true,
    exporters,
    spillDir: process.env.VISUS_SIEM_SPILL_DIR || DEFAULT_SPILL_DIR,
    flushIntervalMs: Number(process.env.VISUS_SIEM_FLUSH_MS) || DEFAULT_FLUSH_INTERVAL_MS,
    batchSize: Number(process.env.VISUS_SIEM_BATCH_SIZE) || DEFAULT_BATCH_SIZE,
  };
}

/**
 * Parse VISUS_SIEM_HEADERS as a semicolon-separated key=value format.
 * Example: "Authorization=Bearer xxx;X-API-Key=yyy"
 */
function parseHeaderEnv(raw: string | undefined): Record<string, string> {
  if (!raw) return {};
  const headers: Record<string, string> = {};
  for (const pair of raw.split(';')) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx > 0) {
      headers[pair.slice(0, eqIdx).trim()] = pair.slice(eqIdx + 1).trim();
    }
  }
  return headers;
}

/**
 * Configuration for file-json exporter (always available for local debugging).
 * Enabled when VISUS_SIEM_FILE_OUTPUT is set to a directory path.
 */
export function detectFileExportConfig(): string | null {
  return process.env.VISUS_SIEM_FILE_OUTPUT || null;
}

/**
 * Math.sign polyfill for flush interval — ensure we don't create
 * a timer with a non-positive value.
 */
export function sanitizeInterval(ms: number): number {
  if (Number.isNaN(ms) || ms < 100) return DEFAULT_FLUSH_INTERVAL_MS;
  return ms;
}