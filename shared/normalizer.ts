import { contentHash, verifyContentHash } from './crypto.js';
import { getHashableFields, VisusEventInput } from './schemas/validate.js';
import { jsonLog, StructuredError } from './errors.js';

export interface NormalizerInput {
  org_id: string;
  network_id: string;
  source: 'meraki_poll' | 'meraki_webhook' | 'catalyst_poll';
  source_url: string;
  event_type: string;
  pipeline_version: string;
  items: Record<string, unknown>[];
}

export interface NormalizerResult {
  written: number;
  skipped: number;
  failed: number;
  total: number;
}

export function generateEventId(sourceUrl: string, orgId: string, item: Record<string, unknown>): string {
  const hash = contentHash({ source_url: sourceUrl, org_id: orgId, item });
  return hash.substring(7, 23);
}

export function buildNormalizedEvent(
  input: NormalizerInput,
  item: Record<string, unknown>,
  sourceUrl: string,
  eventType: string,
): VisusEventInput {
  const event_id = generateEventId(sourceUrl, input.org_id, item);
  const now = Date.now();
  const harvestTimestamp = new Date().toISOString();

  const event: VisusEventInput = {
    event_id,
    schema_version: 'v1',
    org_id: input.org_id,
    network_id: input.network_id,
    source: input.source,
    event_type: eventType,
    event_payload: item,
    source_url: sourceUrl,
    harvest_timestamp: harvestTimestamp,
    pipeline_version: input.pipeline_version,
    content_hash: '',
    ttl: Math.floor(now / 1000) + 90 * 24 * 60 * 60,
  };

  const hashableFields = getHashableFields(event);
  event.content_hash = contentHash(hashableFields);

  return event;
}

export interface WriteEventResult {
  event: VisusEventInput;
  status: 'written' | 'skipped' | 'failed';
  error?: string;
}

export function normalizeEvents(input: NormalizerInput): {
  events: VisusEventInput[];
  result: NormalizerResult;
  writeResults: WriteEventResult[];
} {
  if (!input.pipeline_version) {
    throw new StructuredError(
      'pipeline_version is required',
      'MISSING_PIPELINE_VERSION',
      400,
    );
  }

  jsonLog('INFO', 'Normalizing events', {
    org_id: input.org_id,
    network_id: input.network_id,
    source: input.source,
    item_count: input.items.length,
  });

  let written = 0;
  let skipped = 0;
  let failed = 0;
  const events: VisusEventInput[] = [];
  const writeResults: WriteEventResult[] = [];

  for (const item of input.items) {
    try {
      const event = buildNormalizedEvent(input, item, input.source_url, input.event_type);
      events.push(event);
      writeResults.push({ event, status: 'written' });
      written++;
    } catch (error) {
      jsonLog('ERROR', 'Failed to normalize item', {
        error: (error as Error).message,
      });
      failed++;
    }
  }

  jsonLog('INFO', 'Normalization complete', {
    org_id: input.org_id,
    written,
    skipped,
    failed,
    total: input.items.length,
  });

  return {
    events,
    writeResults,
    result: { written, skipped, failed, total: input.items.length },
  };
}

export function verifyEventHash(event: VisusEventInput): void {
  const hashableFields = getHashableFields(event);
  verifyContentHash(hashableFields, event.content_hash);
}
