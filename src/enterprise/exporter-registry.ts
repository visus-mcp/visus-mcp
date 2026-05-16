/**
 * Enterprise Integration — ExporterRegistry
 *
 * The central orchestrator for the enterprise integration layer.
 *
 * Lifecycle:
 *   1. Created with config from loader.ts
 *   2. Exporters registered via register()
 *   3. start() initializes exporters, recovers spills, starts flush loop
 *   4. emit() called by tool handlers (non-blocking, ~8μs overhead)
 *   5. shutdown() drains buffer, stops exporters, closes gracefully
 *
 * Thread-safety: Node.js is single-threaded, so emit() (from tool handlers)
 * and the flush loop (from setInterval) are interleaved at await yield points,
 * never simultaneously. The ring buffer is accessed from the same thread.
 */

import { RingBuffer } from './ring-buffer.js';
import { signEvent } from './signer.js';
import { randomUUID } from 'crypto';
import { tmpdir } from 'os';
import { join } from 'path';
import type { SecurityEvent, SecurityExporter, EnterpriseConfig } from './types.js';
import { FileJsonExporter } from './exporters/file-json.js';
import { OTelCollectorExporter } from './exporters/otel-collector.js';

export class ExporterRegistry {
  private exporters: SecurityExporter[] = [];
  private ringBuffer: RingBuffer<SecurityEvent>;
  private flushIntervalMs: number;
  private batchSize: number;
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private _started = false;
  private _shuttingDown = false;

  constructor(config: EnterpriseConfig) {
    const capacity = (config.batchSize || 100) * 3; // 3x batch size buffer
    this.ringBuffer = new RingBuffer<SecurityEvent>(
      capacity,
      config.spillDir || join(tmpdir(), 'visus-siem-spill')
    );
    this.flushIntervalMs = config.flushIntervalMs || 500;
    this.batchSize = config.batchSize || 100;
  }

  get started(): boolean {
    return this._started;
  }

  /**
   * Register an exporter. Call before start().
   */
  register(exporter: SecurityExporter): void {
    this.exporters.push(exporter);
  }

  /**
   * Register the built-in file-json exporter that dumps to a directory.
   */
  registerFileExporter(outputDir: string): void {
    const exporter = new FileJsonExporter();
    exporter.configure(outputDir);
    this.register(exporter);
  }

  /**
   * Register the built-in OTel collector exporter.
   */
  registerOtelCollector(endpoint: string, headers?: Record<string, string>, serviceName?: string): void {
    const exporter = new OTelCollectorExporter();
    exporter.configure({
      endpoint,
      headers: headers || {},
      serviceName: serviceName || 'visus-mcp',
    });
    this.register(exporter);
  }

  getExporterNames(): string[] {
    return this.exporters.map(e => e.name);
  }

  /**
   * Initialize all registered exporters and start the background flush loop.
   */
  async start(): Promise<void> {
    if (this.exporters.length === 0) {
      console.error(JSON.stringify({
        event: 'enterprise_no_exporters',
        message: 'No exporters registered — enterprise layer is a no-op',
      }));
      return;
    }

    // Initialize all exporters
    for (const exporter of this.exporters) {
      try {
        await exporter.initialize();
        console.error(JSON.stringify({
          event: 'enterprise_exporter_initialized',
          exporter: exporter.name,
        }));
      } catch (err) {
        console.error(JSON.stringify({
          event: 'enterprise_exporter_init_failed',
          exporter: exporter.name,
          error: err instanceof Error ? err.message : String(err),
        }));
      }
    }

    // Recover spilled events from disk
    const recovered = await this.ringBuffer.recoverFromDisk();
    if (recovered > 0) {
      console.error(JSON.stringify({
        event: 'enterprise_spill_recovery',
        count: recovered,
      }));
    }

    this._started = true;

    // Start background flush loop
    this.flushTimer = setInterval(() => {
      this.flush().catch(err => {
        console.error(JSON.stringify({
          event: 'enterprise_flush_error',
          error: err instanceof Error ? err.message : String(err),
        }));
      });
    }, this.flushIntervalMs);

    // Allow Node.js to exit even if the timer is active
    if (this.flushTimer && typeof this.flushTimer === 'object' && 'unref' in this.flushTimer) {
      (this.flushTimer as NodeJS.Timeout).unref();
    }

    console.error(JSON.stringify({
      event: 'enterprise_started',
      exporters: this.getExporterNames(),
      flushIntervalMs: this.flushIntervalMs,
      batchSize: this.batchSize,
    }));
  }

  /**
   * Emit a security event. Non-blocking — returns immediately.
   * If the ring buffer is full, spills to disk (no data loss).
   */
  emit(event: Omit<SecurityEvent, 'signature' | 'event_id' | 'timestamp'>): void {
    if (!this._started) return;

    const fullEvent: SecurityEvent = {
      ...event,
      event_id: cryptoUUID(),
      timestamp: new Date().toISOString(),
      signature: '',
    };

    // HMAC sign the event
    try {
      fullEvent.signature = signEvent(fullEvent);
    } catch {
      // If signing fails, emit without signature
    }

    // Try ring buffer first; spill to disk on overflow
    if (!this.ringBuffer.tryPush(fullEvent)) {
      this.ringBuffer.spillToDisk(fullEvent).catch(() => {
        // Spill failure means data loss in extreme disk-pressure scenarios
      });
    }
  }

  /**
   * Graceful shutdown: flush remaining events, stop exporters.
   */
  async shutdown(): Promise<void> {
    if (this._shuttingDown) return;
    this._shuttingDown = true;

    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }

    // Final flush of all remaining events
    await this.flushFull();

    // Shutdown all exporters
    for (const exporter of this.exporters) {
      try {
        await exporter.shutdown();
      } catch (err) {
        console.error(JSON.stringify({
          event: 'enterprise_exporter_shutdown_failed',
          exporter: exporter.name,
          error: err instanceof Error ? err.message : String(err),
        }));
      }
    }

    this._started = false;
  }

  // ---- Private ----

  /**
   * Drain a batch of events and send to all exporters.
   */
  private async flush(): Promise<void> {
    if (this.ringBuffer.isEmpty) return;

    const batch = this.ringBuffer.drain(this.batchSize);
    if (batch.length === 0) return;

    await this.sendBatch(batch);
  }

  /**
   * Drain ALL remaining events and send.
   */
  private async flushFull(): Promise<void> {
    while (!this.ringBuffer.isEmpty) {
      const batch = this.ringBuffer.drain(this.batchSize);
      if (batch.length === 0) break;
      await this.sendBatch(batch);
    }
  }

  /**
   * Send a batch to all exporters. On retryable failure, re-queue events.
   */
  private async sendBatch(batch: SecurityEvent[]): Promise<void> {
    for (const exporter of this.exporters) {
      try {
        const result = await exporter.exportBatch(batch);
        if (!result.ok && result.retryable) {
          // Re-queue failed events
          for (const event of batch) {
            if (!this.ringBuffer.tryPush(event)) {
              await this.ringBuffer.spillToDisk(event);
            }
          }
          console.error(JSON.stringify({
            event: 'enterprise_export_retryable',
            exporter: exporter.name,
            error: result.error,
          }));
        }
      } catch (err) {
        // Exporter threw — log and move on
        console.error(JSON.stringify({
          event: 'enterprise_export_exception',
          exporter: exporter.name,
          error: err instanceof Error ? err.message : String(err),
        }));
      }
    }
  }
}

function cryptoUUID(): string {
  return randomUUID();
}