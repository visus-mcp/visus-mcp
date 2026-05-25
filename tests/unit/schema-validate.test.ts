import { validateEvent, validateEventBatch, getHashableFields, VisusEvent } from '../../shared/schemas/validate.js';
import { contentHash } from '../../shared/crypto.js';
import { ValidationError } from '../../shared/errors.js';

function createValidEvent(overrides: Partial<VisusEvent> = {}): VisusEvent {
  const base: VisusEvent = {
    event_id: `evt-${Math.random().toString(36).substring(2, 10)}`,
    schema_version: 'v1',
    org_id: 'org-test-123',
    network_id: 'N_12345678',
    source: 'meraki_poll',
    event_type: 'meraki.network.event',
    event_payload: { key: 'value' },
    source_url: 'https://api.meraki.com/api/v1/networks/N_12345678/events',
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

describe('validateEvent', () => {
  it('validates a well-formed event successfully', () => {
    const event = createValidEvent();
    const result = validateEvent(event);
    expect(result.event_id).toBe(event.event_id);
    expect(result.schema_version).toBe('v1');
  });

  it('rejects event with missing event_id', () => {
    const event = createValidEvent();
    delete (event as unknown as Record<string, unknown>).event_id;
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with missing schema_version', () => {
    const event = createValidEvent();
    delete (event as unknown as Record<string, unknown>).schema_version;
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with invalid schema_version', () => {
    const event = createValidEvent({ schema_version: 'v2' as 'v1' });
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with empty org_id', () => {
    const event = createValidEvent({ org_id: '' });
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with invalid source enum value', () => {
    const event = createValidEvent({ source: 'invalid_source' as 'meraki_poll' });
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with missing event_payload', () => {
    const event = createValidEvent();
    delete (event as unknown as Record<string, unknown>).event_payload;
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with invalid source_url format', () => {
    const event = createValidEvent({ source_url: 'not-a-url' });
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with invalid harvest_timestamp format', () => {
    const event = createValidEvent({ harvest_timestamp: 'not-a-date' });
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with invalid pipeline_version format', () => {
    const event = createValidEvent({ pipeline_version: 'short' });
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with content_hash mismatch', () => {
    const event = createValidEvent();
    event.content_hash = 'sha256:' + '0'.repeat(64);
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with missing content_hash', () => {
    const event = createValidEvent();
    delete (event as unknown as Record<string, unknown>).content_hash;
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with additional properties', () => {
    const event = createValidEvent();
    (event as unknown as Record<string, unknown>).extra_field = 'should not be here';
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event with null event_payload', () => {
    const event = createValidEvent({ event_payload: null as unknown as Record<string, unknown> });
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('accepts meraki_webhook source', () => {
    const event = createValidEvent({ source: 'meraki_webhook' });
    const result = validateEvent(event);
    expect(result.source).toBe('meraki_webhook');
  });

  it('accepts catalyst_poll source', () => {
    const event = createValidEvent({ source: 'catalyst_poll' });
    const result = validateEvent(event);
    expect(result.source).toBe('catalyst_poll');
  });

  it('rejects event with ttl less than 1', () => {
    const event = createValidEvent({ ttl: 0 });
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('accepts event_id with hyphens and underscores', () => {
    const event = createValidEvent({ event_id: 'evt_test-id-123' });
    const result = validateEvent(event);
    expect(result.event_id).toBe('evt_test-id-123');
  });

  it('rejects event_id that is too short', () => {
    const event = createValidEvent({ event_id: 'short' });
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });

  it('rejects event_id that is too long', () => {
    const event = createValidEvent({ event_id: 'a'.repeat(65) });
    expect(() => validateEvent(event)).toThrow(ValidationError);
  });
});

describe('validateEventBatch', () => {
  it('returns all valid events', () => {
    const events = [createValidEvent(), createValidEvent(), createValidEvent()];
    const result = validateEventBatch(events);
    expect(result.valid.length).toBe(3);
    expect(result.errors.length).toBe(0);
  });

  it('separates valid from invalid events', () => {
    const valid1 = createValidEvent();
    const invalid = createValidEvent({ event_id: 'xx' });
    const valid2 = createValidEvent();

    const result = validateEventBatch([valid1, invalid, valid2]);
    expect(result.valid.length).toBe(2);
    expect(result.errors.length).toBe(1);
    expect(result.errors[0].index).toBe(1);
  });

  it('handles empty input array', () => {
    const result = validateEventBatch([]);
    expect(result.valid.length).toBe(0);
    expect(result.errors.length).toBe(0);
  });

  it('returns all errors when all events are invalid', () => {
    const events = [
      createValidEvent({ event_id: 'xx' }),
      createValidEvent({ event_id: 'yy' }),
    ];
    const result = validateEventBatch(events);
    expect(result.valid.length).toBe(0);
    expect(result.errors.length).toBe(2);
  });
});

describe('getHashableFields', () => {
  it('excludes content_hash from hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable).not.toHaveProperty('content_hash');
  });

  it('excludes ttl from hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable).not.toHaveProperty('ttl');
  });

  it('excludes schema_version from hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable).not.toHaveProperty('schema_version');
  });

  it('includes event_id in hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable.event_id).toBe(event.event_id);
  });

  it('includes org_id in hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable.org_id).toBe(event.org_id);
  });

  it('includes network_id in hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable.network_id).toBe(event.network_id);
  });

  it('includes source in hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable.source).toBe(event.source);
  });

  it('includes event_type in hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable.event_type).toBe(event.event_type);
  });

  it('includes event_payload in hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable.event_payload).toEqual(event.event_payload);
  });

  it('includes source_url in hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable.source_url).toBe(event.source_url);
  });

  it('includes harvest_timestamp in hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable.harvest_timestamp).toBe(event.harvest_timestamp);
  });

  it('includes pipeline_version in hashable fields', () => {
    const event = createValidEvent();
    const hashable = getHashableFields(event);
    expect(hashable.pipeline_version).toBe(event.pipeline_version);
  });
});
