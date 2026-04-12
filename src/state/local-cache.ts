/**
 * Local JSON Cache for Stateful Scans
 * Stores hashed primed entities per session in ~/.visus-cache-{sessionId}.json
 * TTL: 30min inactivity
 */

import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

import type { PrimedEntity } from '../types.js';

const CACHE_DIR = process.env.HOME ? path.join(process.env.HOME, '.visus-cache') : './.visus-cache';
const TTL_MINUTES = 30;  // 30 minutes TTL

class LocalCache {
  private cacheDir: string;

  constructor() {
    this.cacheDir = CACHE_DIR;
    fs.mkdir(this.cacheDir, { recursive: true }).catch(() => {});  // Ignore if exists
  }

  private getCacheFile(sessionId: string): string {
    return path.join(this.cacheDir, `cache-${sessionId}.json`);
  }

  private isExpired(cached: { timestamp?: string }): boolean {
    if (!cached.timestamp) return true;
    const now = Date.now();
    const then = new Date(cached.timestamp).getTime();
    return (now - then) > (TTL_MINUTES * 60 * 1000);
  }

  async getPrimed(sessionId: string): Promise<PrimedEntity[]> {
    const file = this.getCacheFile(sessionId);
    try {
      const data = await fs.readFile(file, 'utf8');
      const parsed = JSON.parse(data);
      if (this.isExpired(parsed)) {
        await this.clear(sessionId);
        return [];
      }
      return parsed.entities || [];
    } catch (error) {
      // File missing, invalid JSON, or other error: return empty
      return [];
    }
  }

  async setPrimed(sessionId: string, entities: PrimedEntity[]): Promise<void> {
    const file = this.getCacheFile(sessionId);
    const toSave = {
      entities,
      timestamp: new Date().toISOString()
    };
    await fs.writeFile(file, JSON.stringify(toSave, null, 2), 'utf8');
  }

  async clear(sessionId: string): Promise<void> {
    const file = this.getCacheFile(sessionId);
    try {
      await fs.unlink(file);
    } catch (error) {
      // Ignore if file doesn't exist
    }
  }
}

export const cacheManager = new LocalCache();
