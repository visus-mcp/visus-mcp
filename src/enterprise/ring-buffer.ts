/**
 * Enterprise Integration Layer — Bounded Ring Buffer with Disk Spill
 *
 * Fixed-capacity circular buffer that spills to disk on overflow.
 * All operations are O(1) and non-blocking (no async in push/pop).
 *
 * Memory: bounded to `capacity` entries regardless of traffic spikes.
 * Data loss prevention: overflow spills to tmpdir, recovered on restart.
 */

import { writeFile, readdir, readFile, unlink, mkdir } from 'fs/promises';
import { join } from 'path';

export class RingBuffer<T> {
  private buffer: (T | null)[];
  private writeIndex = 0;
  private _count = 0;
  readonly capacity: number;
  readonly spillDir: string;

  constructor(capacity: number, spillDir: string) {
    this.capacity = capacity;
    this.buffer = new Array(capacity).fill(null);
    this.spillDir = spillDir;
  }

  get count(): number {
    return this._count;
  }

  get isFull(): boolean {
    return this._count >= this.capacity;
  }

  get isEmpty(): boolean {
    return this._count === 0;
  }

  /**
   * Attempt to push an item into the buffer.
   * Returns true if added, false if full (caller should spill).
   */
  tryPush(item: T): boolean {
    if (this.isFull) return false;
    this.buffer[this.writeIndex] = item;
    this.writeIndex = (this.writeIndex + 1) % this.capacity;
    this._count++;
    return true;
  }

  /**
   * Pop the oldest item. Returns null if empty.
   */
  pop(): T | null {
    if (this.isEmpty) return null;
    const readIndex = (this.writeIndex - this._count + this.capacity) % this.capacity;
    const item = this.buffer[readIndex];
    this.buffer[readIndex] = null;
    this._count--;
    return item;
  }

  /**
   * Drain up to maxItems from the buffer into an array (FIFO).
   */
  drain(maxItems: number): T[] {
    const items: T[] = [];
    for (let i = 0; i < maxItems; i++) {
      const item = this.pop();
      if (item === null) break;
      items.push(item);
    }
    return items;
  }

  /**
   * Spill a single item to a JSONL file on disk.
   * Called when the ring buffer is full.
   */
  async spillToDisk(item: T): Promise<void> {
    try {
      await mkdir(this.spillDir, { recursive: true });
      const id = (item as any)?.event_id || Date.now().toString();
      const filename = `spill-${Date.now()}-${id}.jsonl`;
      const filepath = join(this.spillDir, filename);
      await writeFile(filepath, JSON.stringify(item) + '\n', 'utf8');
    } catch (err) {
      console.error(JSON.stringify({
        event: 'enterprise_spill_failed',
        error: err instanceof Error ? err.message : String(err),
      }));
    }
  }

  /**
   * Recover spilled events from disk into the buffer.
   * Call on startup after initializing exporters.
   */
  async recoverFromDisk(): Promise<number> {
    let recovered = 0;
    try {
      await mkdir(this.spillDir, { recursive: true });
      const files = await readdir(this.spillDir);

      for (const file of files) {
        if (!file.endsWith('.jsonl')) continue;
        const filepath = join(this.spillDir, file);

        try {
          const content = await readFile(filepath, 'utf8');
          const lines = content.trim().split('\n');

          for (const line of lines) {
            if (!line) continue;
            try {
              const parsed = JSON.parse(line) as T;
              if (!this.tryPush(parsed)) {
                // Buffer full — stop recovering
                return recovered;
              }
              recovered++;
            } catch {
              // Malformed JSON line — skip
            }
          }

          await unlink(filepath);
        } catch {
          // Can't read this file — skip and try next
        }
      }
    } catch {
      // Spill dir doesn't exist yet — nothing to recover
    }
    return recovered;
  }
}