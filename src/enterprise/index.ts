/**
 * Enterprise Integration Layer — Public API
 *
 * Usage in src/index.ts:
 *
 *   import { initializeEnterprise, getEnterpriseRegistry } from './enterprise/index.js';
 *
 *   // During server startup:
 *   const registry = initializeEnterprise();
 *   registry?.start();
 *
 *   // After sanitization in tool handler:
 *   enterpriseRegistry?.emit({
 *     event_type: 'injection_detected',
 *     tool_name: 'visus_fetch',
 *     ...
 *   });
 *
 *   // On shutdown:
 *   await enterpriseRegistry?.shutdown();
 */

import { ExporterRegistry } from './exporter-registry.js';
import { detectEnterpriseConfig, detectFileExportConfig } from './loader.js';

let _registry: ExporterRegistry | null = null;

/**
 * Initialize the enterprise integration layer.
 * Returns null if no SIEM endpoints are configured (zero-config local mode).
 *
 * Safe to call multiple times — returns the existing singleton on re-invocation.
 */
export function initializeEnterprise(): ExporterRegistry | null {
  if (_registry) return _registry;

  const config = detectEnterpriseConfig();

  if (!config.enabled) {
    // Check for file export (always available for local debugging)
    const fileOutput = detectFileExportConfig();
    if (!fileOutput) return null;

    // File-only mode: create registry with just the file exporter
    _registry = new ExporterRegistry({
      enabled: true,
      spillDir: config.spillDir,
      flushIntervalMs: config.flushIntervalMs || 500,
      batchSize: config.batchSize || 100,
    });
    _registry.registerFileExporter(fileOutput);
    return _registry;
  }

  _registry = new ExporterRegistry(config);

  // Register configured exporters
  if (config.exporters) {
    for (const ec of config.exporters) {
      switch (ec.type) {
        case 'otel-collector': {
          const { endpoint, headers, serviceName } = ec.config as any;
          _registry.registerOtelCollector(endpoint, headers, serviceName);
          break;
        }
        case 'splunk-hec':
          // Lazy-loaded: @visus-mcp/exporter-splunk
          // Deliberately not bundled in core — user installs separately
          console.error(JSON.stringify({
            event: 'enterprise_exporter_skipped',
            type: 'splunk-hec',
            message: 'Install @visus-mcp/exporter-splunk to enable Splunk HEC export',
          }));
          break;
        case 'azure-sentinel':
          // Lazy-loaded: @visus-mcp/exporter-azure-sentinel
          console.error(JSON.stringify({
            event: 'enterprise_exporter_skipped',
            type: 'azure-sentinel',
            message: 'Install @visus-mcp/exporter-azure-sentinel to enable Azure Sentinel export',
          }));
          break;
        default:
          console.error(JSON.stringify({
            event: 'enterprise_exporter_unknown',
            type: ec.type,
          }));
      }
    }
  }

  // Also enable file export if configured
  const fileOutput = detectFileExportConfig();
  if (fileOutput) {
    _registry.registerFileExporter(fileOutput);
  }

  return _registry;
}

/**
 * Get the existing registry singleton, or null if not initialized.
 */
export function getEnterpriseRegistry(): ExporterRegistry | null {
  return _registry;
}

export { ExporterRegistry } from './exporter-registry.js';
export type {
  SecurityEvent,
  SecurityEventType,
  SecurityExporter,
  ExportResult,
  ExporterConfig,
  EnterpriseConfig,
} from './types.js';
export { buildSecurityEvent, threatSeverityToEventSeverity } from './bridge.js';
export { FileJsonExporter } from './exporters/file-json.js';
export { OTelCollectorExporter } from './exporters/otel-collector.js';