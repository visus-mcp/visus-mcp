import { contentHash } from '../../shared/crypto.js';
import { getHashableFields, VisusEvent } from '../../shared/schemas/validate.js';

describe('content hash properties', () => {
  function createEvent(overrides: Partial<VisusEvent> = {}): VisusEvent {
    const base: VisusEvent = {
      event_id: 'evt-test-hash-001',
      schema_version: 'v1',
      org_id: 'org-hash-test',
      network_id: 'N_TEST_HASH',
      source: 'meraki_poll',
      event_type: 'meraki.network.event',
      event_payload: { event_name: 'test_event', details: { ip: '10.0.0.1' } },
      source_url: 'https://api.meraki.com/api/v1/networks/N_TEST_HASH/events',
      harvest_timestamp: '2026-05-24T12:00:00.000Z',
      pipeline_version: 'a'.repeat(40),
      content_hash: '',
      ttl: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60,
    };
    const merged = { ...base, ...overrides };
    const hashable = getHashableFields(merged);
    merged.content_hash = contentHash(hashable);
    return merged;
  }

  it('deterministic output for same input', () => {
    const e1 = createEvent();
    const e2 = createEvent({ event_id: e1.event_id });
    expect(e1.content_hash).toBe(e2.content_hash);
  });

  it('different output for single-byte change in event_payload', () => {
    const e1 = createEvent();
    const e2 = createEvent({
      event_id: e1.event_id,
      event_payload: { ...e1.event_payload, x: 'y' },
    });
    expect(e1.content_hash).not.toBe(e2.content_hash);
  });

  it('content_hash field excluded from its own hash', () => {
    const event = createEvent();
    const hashable = getHashableFields(event);
    expect(Object.keys(hashable)).not.toContain('content_hash');
    expect(Object.keys(hashable)).not.toContain('ttl');
    expect(Object.keys(hashable)).not.toContain('schema_version');
  });

  it('hash of empty payload is valid', () => {
    const event = createEvent({ event_payload: {} });
    expect(event.content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('hash prefix is sha256:', () => {
    const event = createEvent();
    expect(event.content_hash.startsWith('sha256:')).toBe(true);
  });

  it('pipeline_version included in hash', () => {
    const e1 = createEvent({ pipeline_version: 'a'.repeat(40) });
    const e2 = createEvent({ pipeline_version: 'b'.repeat(40), event_id: e1.event_id });
    expect(e1.content_hash).not.toBe(e2.content_hash);
  });

  it('org_id included in hash', () => {
    const e1 = createEvent({ org_id: 'org-a' });
    const e2 = createEvent({ org_id: 'org-b', event_id: e1.event_id });
    expect(e1.content_hash).not.toBe(e2.content_hash);
  });

  it('hash changes when source_url changes', () => {
    const e1 = createEvent();
    const e2 = createEvent({
      event_id: e1.event_id,
      source_url: 'https://different.url/api/v1/events',
    });
    expect(e1.content_hash).not.toBe(e2.content_hash);
  });

  it('hash changes when harvest_timestamp changes', () => {
    const e1 = createEvent({ harvest_timestamp: '2026-05-24T12:00:00.000Z' });
    const e2 = createEvent({
      event_id: e1.event_id,
      harvest_timestamp: '2026-05-24T13:00:00.000Z',
    });
    expect(e1.content_hash).not.toBe(e2.content_hash);
  });

  it('field ordering does not matter for hash (canonical JSON)', () => {
    const payload1 = { b: 1, a: 2 };
    const payload2 = { a: 2, b: 1 };
    const e1 = createEvent({ event_payload: payload1 });
    const e2 = createEvent({ event_id: e1.event_id, event_payload: payload2 });
    expect(e1.content_hash).toBe(e2.content_hash);
  });

  it('hash changes when network_id changes', () => {
    const e1 = createEvent({ network_id: 'N_A' });
    const e2 = createEvent({ network_id: 'N_B', event_id: e1.event_id });
    expect(e1.content_hash).not.toBe(e2.content_hash);
  });

  it('hash changes when source changes', () => {
    const e1 = createEvent({ source: 'meraki_poll' });
    const e2 = createEvent({ source: 'meraki_webhook', event_id: e1.event_id });
    expect(e1.content_hash).not.toBe(e2.content_hash);
  });

  it('hash changes when event_type changes', () => {
    const e1 = createEvent({ event_type: 'meraki.network.event' });
    const e2 = createEvent({ event_type: 'meraki.security.event', event_id: e1.event_id });
    expect(e1.content_hash).not.toBe(e2.content_hash);
  });

  it('ttl change does NOT affect hash', () => {
    const e1 = createEvent({ ttl: 100 });
    const e2 = createEvent({ ttl: 999, event_id: e1.event_id });
    expect(e1.content_hash).toBe(e2.content_hash);
  });

  it('schema_version change does NOT affect hash', () => {
    const e1 = createEvent();
    const e2 = createEvent({ event_id: e1.event_id, schema_version: 'v1' });
    expect(e1.content_hash).toBe(e2.content_hash);
  });
});
