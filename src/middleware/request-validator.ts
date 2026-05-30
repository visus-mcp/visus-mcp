interface RateLimitEntry {
  second: { count: number; window: number };
  day: { count: number; window: number };
}

const rateLimitStore = new Map<string, RateLimitEntry>();

const CLEANUP_INTERVAL_MS = 3600_000;
let lastCleanup = Date.now();

function cleanupStaleEntries(): void {
  const now = Date.now();
  if (now - lastCleanup < CLEANUP_INTERVAL_MS) return;
  lastCleanup = now;
  const currentSecond = Math.floor(now / 1000);
  const currentDay = Math.floor(now / 86400_000);
  for (const [key, entry] of rateLimitStore) {
    if (entry.second.window !== currentSecond && entry.day.window !== currentDay) {
      rateLimitStore.delete(key);
    }
  }
}

export function validateHostHeader(host: string | undefined | null, allowlist: string[]): boolean {
  if (!host) return false;
  return allowlist.includes(host);
}

export function validateOrigin(origin: string | undefined, patterns: RegExp[]): boolean {
  if (origin === undefined) return true;
  return patterns.some((p) => p.test(origin));
}

export function enforceRateLimit(apiKey: string | undefined, limits: { rps: number; rpd: number }): boolean {
  if (!apiKey) return true;

  cleanupStaleEntries();

  const now = Date.now();
  const currentSecond = Math.floor(now / 1000);
  const currentDay = Math.floor(now / 86400_000);

  let entry = rateLimitStore.get(apiKey);
  if (!entry) {
    entry = { second: { count: 0, window: currentSecond }, day: { count: 0, window: currentDay } };
    rateLimitStore.set(apiKey, entry);
  }

  if (entry.second.window !== currentSecond) {
    entry.second = { count: 0, window: currentSecond };
  }
  if (entry.day.window !== currentDay) {
    entry.day = { count: 0, window: currentDay };
  }

  entry.second.count += 1;
  entry.day.count += 1;

  if (entry.second.count > limits.rps) return false;
  if (entry.day.count > limits.rpd) return false;

  return true;
}

export function _resetRateLimitStoreForTest(): void {
  rateLimitStore.clear();
}
