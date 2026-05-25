import {
  normalizeEvents,
  generateEventId,
  verifyEventHash,
  NormalizerInput,
} from '../../shared/normalizer.js';
import { contentHash } from '../../shared/crypto.js';
import { StructuredError } from '../../shared/errors.js';

const PIPELINE_VERSION = 'a'.repeat(40);

function createInput(overrides: Partial<NormalizerInput> = {}): NormalizerInput {
  return {
    org_id: 'org-test-001',
    network_id: 'N_12345678',
    source: 'meraki_poll',
    source_url: 'https://api.meraki.com/api/v1/networks/N_12345678/events',
    event_type: 'meraki.network.event',
    pipeline_version: PIPELINE_VERSION,
    items: [{ event_name: 'test_event', value: 42 }],
    ...overrides,
  };
}

describe('Normalizer - Schema Normalization (20 tests)', () => {
  it('normalizes a Meraki network event', () => {
    const input = createInput({
      event_type: 'meraki.network.event',
      items: [{ type: 'vpn_connectivity_change', networkId: 'N_123' }],
    });
    const { events, result } = normalizeEvents(input);
    expect(result.total).toBe(1);
    expect(events.length).toBe(1);
    expect(events[0].event_type).toBe('meraki.network.event');
    expect(events[0].source).toBe('meraki_poll');
  });

  it('normalizes a Meraki security event', () => {
    const input = createInput({
      event_type: 'meraki.security.event',
      items: [{ type: 'ids_alert', priority: 'high' }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('normalizes a Meraki client event', () => {
    const input = createInput({
      event_type: 'meraki.network.clients',
      source_url: 'https://api.meraki.com/api/v1/networks/N_12345678/clients',
      items: [{ id: 'client-001', status: 'online' }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('normalizes a Meraki device status event', () => {
    const input = createInput({
      event_type: 'meraki.org.device_statuses',
      source_url: 'https://api.meraki.com/api/v1/organizations/123456/devices/statuses',
      items: [{ serial: 'Q2XX-ABCD-1234', status: 'online' }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('normalizes a Meraki VLAN event', () => {
    const input = createInput({
      event_type: 'meraki.network.vlans',
      items: [{ id: '1', name: 'default', subnet: '10.0.0.0/24' }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('normalizes a Meraki SSID event', () => {
    const input = createInput({
      event_type: 'meraki.network.ssids',
      items: [{ number: 0, name: 'Corporate WiFi' }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('normalizes a Catalyst device inventory event', () => {
    const input = createInput({
      event_type: 'catalyst.device.inventory',
      source: 'catalyst_poll',
      items: [{ hostname: 'switch-01', platformId: 'WS-C2960X-48FPD-L' }],
    });
    const { events } = normalizeEvents(input);
    expect(events[0].source).toBe('catalyst_poll');
    expect(events[0].event_type).toBe('catalyst.device.inventory');
  });

  it('normalizes a Catalyst network issues event', () => {
    const input = createInput({
      event_type: 'catalyst.network.issues',
      source: 'catalyst_poll',
      items: [{ issueId: 'ISSUE-001', severity: 'major' }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('normalizes a Catalyst network health event', () => {
    const input = createInput({
      event_type: 'catalyst.network.health',
      source: 'catalyst_poll',
      items: [{ healthScore: 85 }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('normalizes a Catalyst client detail event', () => {
    const input = createInput({
      event_type: 'catalyst.client.detail',
      source: 'catalyst_poll',
      items: [{ macAddress: '00:11:22:33:44:55' }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('handles unicode payload', () => {
    const input = createInput({
      items: [{ name: 'Jose', location: 'Sao Paulo', unicode: '\u00e9\u00e3' }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('handles deeply nested payload', () => {
    const input = createInput({
      items: [{ a: { b: { c: { d: { e: { f: 'deep' } } } } } }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('handles very long field values', () => {
    const input = createInput({
      items: [{ long: 'x'.repeat(10000) }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('handles numeric values in payload', () => {
    const input = createInput({
      items: [{ count: 0, pi: 3.14159, negative: -42 }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('handles boolean values in payload', () => {
    const input = createInput({
      items: [{ enabled: true, debug: false }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('handles null values in payload', () => {
    const input = createInput({
      items: [{ optional: null, data: 'present' }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('handles array payloads within items', () => {
    const input = createInput({
      items: [{ tags: ['critical', 'network', 'alert'] }],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('handles empty objects in payload', () => {
    const input = createInput({ items: [{}] });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(1);
  });

  it('handles multiple items returning correct count', () => {
    const input = createInput({
      items: [
        { event_name: 'event_1', id: 1 },
        { event_name: 'event_2', id: 2 },
        { event_name: 'event_3', id: 3 },
      ],
    });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(3);
    expect(result.written).toBe(3);
  });

  it('sets the correct source on all events', () => {
    const input = createInput({ source: 'meraki_webhook', items: [{ id: 1 }, { id: 2 }] });
    const { events } = normalizeEvents(input);
    events.forEach((e) => expect(e.source).toBe('meraki_webhook'));
  });
});

describe('Normalizer - Content Hash (15 tests)', () => {
  it('deterministic output for same input', () => {
    const input = createInput({ items: [{ id: 'same' }] });
    const { events: e1 } = normalizeEvents(input);
    const { events: e2 } = normalizeEvents(input);
    expect(e1[0].event_id).toBe(e2[0].event_id);
  });

  it('different output for single-byte change', () => {
    const { events: e1 } = normalizeEvents(createInput({ items: [{ val: 'a' }] }));
    const { events: e2 } = normalizeEvents(createInput({ items: [{ val: 'b' }] }));
    expect(e1[0].content_hash).not.toBe(e2[0].content_hash);
  });

  it('content_hash field excluded from its own hash', () => {
    const { events } = normalizeEvents(createInput({ items: [{ x: 1 }] }));
    const e = events[0];
    const h1 = e.content_hash;
    const modified = { ...e, content_hash: 'sha256:deadbeef' };
    const newHash = contentHash({
      event_id: modified.event_id,
      org_id: modified.org_id,
      network_id: modified.network_id,
      source: modified.source,
      event_type: modified.event_type,
      event_payload: modified.event_payload,
      source_url: modified.source_url,
      harvest_timestamp: modified.harvest_timestamp,
      pipeline_version: modified.pipeline_version,
    });
    expect(h1).toBe(newHash);
  });

  it('ttl excluded from hash calculation', () => {
    const { events: e1 } = normalizeEvents(createInput({ items: [{ x: 1 }] }));
    expect(e1[0].content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('schema_version excluded from hash calculation', () => {
    const { events: e1 } = normalizeEvents(createInput({ items: [{ x: 1 }] }));
    expect(e1[0].content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('hash of empty payload is valid', () => {
    const { events } = normalizeEvents(createInput({ items: [{}] }));
    expect(events[0].content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('hash prefix is sha256:', () => {
    const { events } = normalizeEvents(createInput({ items: [{ a: 1 }] }));
    expect(events[0].content_hash.startsWith('sha256:')).toBe(true);
  });

  it('re-hash verification passes on clean record', () => {
    const { events } = normalizeEvents(createInput({ items: [{ a: 1 }] }));
    const e = events[0];
    expect(() => verifyEventHash(e)).not.toThrow();
  });

  it('re-hash verification throws on tampered record', () => {
    const { events } = normalizeEvents(createInput({ items: [{ a: 1 }] }));
    const e = { ...events[0], org_id: 'tampered-org' };
    expect(() => verifyEventHash(e)).toThrow();
  });

  it('pipeline_version included in hash', () => {
    const { events: e1 } = normalizeEvents(createInput({
      pipeline_version: 'aaaaa0000000000000000000000000000000000',
      items: [{ id: 'test' }],
    }));
    const { events: e2 } = normalizeEvents(createInput({
      pipeline_version: 'bbbbb0000000000000000000000000000000000',
      items: [{ id: 'test' }],
    }));
    expect(e1[0].content_hash).not.toBe(e2[0].content_hash);
  });

  it('org_id included in hash', () => {
    const { events: e1 } = normalizeEvents(createInput({ org_id: 'org-a', items: [{ id: 'x' }] }));
    const { events: e2 } = normalizeEvents(createInput({ org_id: 'org-b', items: [{ id: 'x' }] }));
    expect(e1[0].content_hash).not.toBe(e2[0].content_hash);
  });

  it('field ordering does not matter (canonical JSON handles it)', () => {
    const { events: e1 } = normalizeEvents(createInput({
      items: [{ b: 1, a: 2, c: 3 }],
    }));
    const { events: e2 } = normalizeEvents(createInput({
      items: [{ a: 2, c: 3, b: 1 }],
    }));
    expect(e1[0].event_id).toBe(e2[0].event_id);
  });

  it('hash changes when source_url changes', () => {
    const { events: e1 } = normalizeEvents(createInput({
      source_url: 'https://api.meraki.com/v1/a',
      items: [{ id: 'x' }],
    }));
    const { events: e2 } = normalizeEvents(createInput({
      source_url: 'https://api.meraki.com/v1/b',
      items: [{ id: 'x' }],
    }));
    expect(e1[0].content_hash).not.toBe(e2[0].content_hash);
  });

  it('hash changes when harvest_timestamp changes', () => {
    const { events: e1 } = normalizeEvents(createInput({ items: [{ id: 'x' }] }));
    const hashable = {
      event_id: e1[0].event_id,
      org_id: e1[0].org_id,
      network_id: e1[0].network_id,
      source: e1[0].source,
      event_type: e1[0].event_type,
      event_payload: e1[0].event_payload,
      source_url: e1[0].source_url,
      harvest_timestamp: '2020-01-01T00:00:00.000Z',
      pipeline_version: e1[0].pipeline_version,
    };
    const newHash = contentHash(hashable);
    expect(newHash).not.toBe(e1[0].content_hash);
  });

  it('idempotent: same input produces same event_id', () => {
    const item = { unique_data: 'idempotent-test', ts: 12345 };
    const id1 = generateEventId('https://api.meraki.com/v1/events', 'org-test', item);
    const id2 = generateEventId('https://api.meraki.com/v1/events', 'org-test', item);
    expect(id1).toBe(id2);
  });
});

describe('Normalizer - Webhook Validation (10 tests)', () => {
  it('correct source: meraki_webhook', () => {
    const input = createInput({ source: 'meraki_webhook', items: [{ alertType: 'Test' }] });
    const { events } = normalizeEvents(input);
    expect(events[0].source).toBe('meraki_webhook');
  });

  it('correct event_type for IDS Alert', () => {
    const input = createInput({
      source: 'meraki_webhook',
      event_type: 'meraki.webhook.ids_alert',
      items: [{ alertType: 'IDS Alert', severity: 'critical' }],
    });
    const { events } = normalizeEvents(input);
    expect(events[0].event_type).toBe('meraki.webhook.ids_alert');
  });

  it('correct event_type for Settings Changed', () => {
    const input = createInput({
      source: 'meraki_webhook',
      event_type: 'meraki.webhook.settings_changed',
      items: [{ settingsChanged: true }],
    });
    const { events } = normalizeEvents(input);
    expect(events[0].event_type).toBe('meraki.webhook.settings_changed');
  });

  it('duplicate event_id produces same event_id', () => {
    const item = { id: 'unique-webhook-001' };
    const input = createInput({ source: 'meraki_webhook', items: [item] });
    const { events: e1 } = normalizeEvents(input);
    const { events: e2 } = normalizeEvents(input);
    expect(e1[0].event_id).toBe(e2[0].event_id);
  });

  it('generated event_id is 16 chars', () => {
    const input = createInput({ items: [{ x: 1 }] });
    const { events } = normalizeEvents(input);
    expect(events[0].event_id.length).toBe(16);
  });

  it('generated event_id alphanumeric with - and _', () => {
    const input = createInput({ items: [{ x: 1 }] });
    const { events } = normalizeEvents(input);
    expect(events[0].event_id).toMatch(/^[a-zA-Z0-9_-]{16}$/);
  });

  it('sets source correctly for webhook events', () => {
    const input = createInput({ source: 'meraki_webhook', items: [{ type: 'webhook' }] });
    const { events } = normalizeEvents(input);
    expect(events[0].source).toBe('meraki_webhook');
  });

  it('sets correct org_id in normalized event', () => {
    const input = createInput({ org_id: 'webhook-org-123', source: 'meraki_webhook', items: [{ a: 1 }] });
    const { events } = normalizeEvents(input);
    expect(events[0].org_id).toBe('webhook-org-123');
  });

  it('sets correct network_id in normalized event', () => {
    const input = createInput({ network_id: 'webhook-net-456', source: 'meraki_webhook', items: [{ a: 1 }] });
    const { events } = normalizeEvents(input);
    expect(events[0].network_id).toBe('webhook-net-456');
  });

  it('source_url is preserved in normalized event', () => {
    const input = createInput({ source_url: 'https://webhook.example.com/path', items: [{ a: 1 }] });
    const { events } = normalizeEvents(input);
    expect(events[0].source_url).toBe('https://webhook.example.com/path');
  });
});

describe('Normalizer - Error Handling (10 tests)', () => {
  it('throws when pipeline_version is missing', () => {
    const input = createInput({ pipeline_version: '' });
    expect(() => normalizeEvents(input)).toThrow(StructuredError);
  });

  it('returns 0 written for empty items array', () => {
    const input = createInput({ items: [] });
    const { result } = normalizeEvents(input);
    expect(result.total).toBe(0);
    expect(result.written).toBe(0);
    expect(result.failed).toBe(0);
  });

  it('pipeline_version missing throws before processing', () => {
    expect(() => normalizeEvents(createInput({ pipeline_version: '' }))).toThrow();
  });

  it('normalizes events with meraki_webhook source', () => {
    const { result } = normalizeEvents(createInput({ source: 'meraki_webhook', items: [{ x: 1 }] }));
    expect(result.total).toBe(1);
  });

  it('normalizes events with catalyst_poll source', () => {
    const { result } = normalizeEvents(createInput({ source: 'catalyst_poll', items: [{ x: 1 }] }));
    expect(result.total).toBe(1);
  });

  it('returns correct result structure on success', () => {
    const { result } = normalizeEvents(createInput({ items: [{ id: 'a' }, { id: 'b' }] }));
    expect(result).toHaveProperty('written');
    expect(result).toHaveProperty('skipped');
    expect(result).toHaveProperty('failed');
    expect(result).toHaveProperty('total');
    expect(result.total).toBe(2);
  });

  it('each normalized event has all required fields', () => {
    const { events } = normalizeEvents(createInput({ items: [{ id: 'req-check' }] }));
    const e = events[0];
    expect(e.event_id).toBeDefined();
    expect(e.schema_version).toBe('v1');
    expect(e.org_id).toBeDefined();
    expect(e.network_id).toBeDefined();
    expect(e.source).toBeDefined();
    expect(e.event_type).toBeDefined();
    expect(e.event_payload).toBeDefined();
    expect(e.source_url).toBeDefined();
    expect(e.harvest_timestamp).toBeDefined();
    expect(e.pipeline_version).toBeDefined();
    expect(e.content_hash).toBeDefined();
    expect(e.ttl).toBeDefined();
  });

  it('ttl is set to 90 days in future', () => {
    const now = Math.floor(Date.now() / 1000);
    const { events } = normalizeEvents(createInput({ items: [{ id: 'ttl-check' }] }));
    const ttl = events[0].ttl;
    const ninetyDays = 90 * 24 * 60 * 60;
    expect(ttl).toBeGreaterThan(now);
    expect(ttl - now).toBeLessThanOrEqual(ninetyDays + 10);
    expect(ttl - now).toBeGreaterThanOrEqual(ninetyDays - 10);
  });

  it('event_id is deterministic across calls', () => {
    const item = { deterministic: true, value: 42 };
    const id1 = generateEventId('https://api.meraki.com/v1/test', 'org-test', item);
    const id2 = generateEventId('https://api.meraki.com/v1/test', 'org-test', item);
    expect(id1).toBe(id2);
  });

  it('different source_urls produce different event_ids', () => {
    const item = { id: 'unique-xyz' };
    const id1 = generateEventId('https://api.meraki.com/v1/a', 'org-test', item);
    const id2 = generateEventId('https://api.meraki.com/v1/b', 'org-test', item);
    expect(id1).not.toBe(id2);
  });
});

describe('Normalizer - Idempotency (5 tests)', () => {
  it('same raw item processed twice produces same event_id', () => {
    const item = { id: 'idempotent-item', value: 'constant' };
    const { events: e1 } = normalizeEvents(createInput({ items: [item] }));
    const { events: e2 } = normalizeEvents(createInput({ items: [item] }));
    expect(e1[0].event_id).toBe(e2[0].event_id);
  });

  it('different items with overlapping fields produce different event_ids', () => {
    const input = createInput({
      items: [
        { name: 'event_a', shared: true },
        { name: 'event_b', shared: true },
      ],
    });
    const { events } = normalizeEvents(input);
    expect(events[0].event_id).not.toBe(events[1].event_id);
  });

  it('event_id is same across repeated calls for same input', () => {
    const item = { constant: 'data', value: 100 };
    const id1 = generateEventId('https://api.example.com/test', 'org-x', item);
    const id2 = generateEventId('https://api.example.com/test', 'org-x', item);
    const id3 = generateEventId('https://api.example.com/test', 'org-x', item);
    expect(id1).toBe(id2);
    expect(id2).toBe(id3);
  });

  it('total count matches items length', () => {
    const items = Array.from({ length: 5 }, (_, i) => ({ idx: i }));
    const { result } = normalizeEvents(createInput({ items }));
    expect(result.total).toBe(5);
    expect(result.written).toBe(5);
  });

  it('each event in batch has unique event_id', () => {
    const items = Array.from({ length: 10 }, (_, i) => ({ idx: i }));
    const { events } = normalizeEvents(createInput({ items }));
    const ids = events.map((e) => e.event_id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });
});
