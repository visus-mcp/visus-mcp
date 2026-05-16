/**
 * Enterprise Integration — File JSONL Exporter
 *
 * Dumps security events to a local JSONL file for debugging.
 * Activated when VISUS_SIEM_FILE_OUTPUT is set to a directory path.
 *
 * No external dependencies — uses Node.js fs promises only.
 * Auto-creates the output directory if it doesn't exist.
 * Rotates files daily to prevent unbounded single-file growth.
 */

import { appendFile, mkdir } from 'fs/promises';
import { join } from 'path';
import type { SecurityExporter, SecurityEvent, ExportResult } from '../types.js';

const MAX_FILE_BYTES = 100 * 1024 * 1024; // 100MB rotation threshold

export class FileJsonExporter implements SecurityExporter {
  readonly name = 'file-json';

  private outputDir = '';
  private currentDate = '';
  private fileSize = 0;
  private ready = false;

  configure(outputDir: string): void {
    this.outputDir = outputDir;
  }

  async initialize(): Promise<void> {
    if (!this.outputDir) {
      this.outputDir = process.env.VISUS_SIEM_FILE_OUTPUT || './visus-events';
    }
    await mkdir(this.outputDir, { recursive: true });
    this.ready = true;
  }

  async exportBatch(events: SecurityEvent[]): Promise<ExportResult> {
    if (!this.ready) {
      return { ok: false, error: 'not initialized', retryable: true };
    }

    try {
      const filepath = this.getCurrentFilepath();

      const lines = events
        .map(e => JSON.stringify(e))
        .join('\n') + '\n';

      await appendFile(filepath, lines, 'utf8');

      this.fileSize += Buffer.byteLength(lines, 'utf8');

      return { ok: true };
    } catch (err: any) {
      return {
        ok: false,
        error: err?.message || String(err),
        retryable: true,
      };
    }
  }

  async shutdown(): Promise<void> {
    this.ready = false;
  }

  private getCurrentFilepath(): string {
    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

    if (today !== this.currentDate || this.fileSize > MAX_FILE_BYTES) {
      this.currentDate = today;
      this.fileSize = 0;
    }

    const seq = this.fileSize > MAX_FILE_BYTES ? '.part2' : '';
    return join(this.outputDir, `visus-events-${today}${seq}.jsonl`);
  }
}



