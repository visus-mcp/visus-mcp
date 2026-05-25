import Ajv, { ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import { verifyContentHash } from '../crypto.js';
import { ValidationError, jsonLog } from '../errors.js';

const eventSchema = {
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://lateos.ai/schemas/visus-event/v1",
  "title": "VisusEvent",
  "type": "object",
  "required": [
    "event_id",
    "schema_version",
    "org_id",
    "network_id",
    "source",
    "event_type",
    "event_payload",
    "source_url",
    "harvest_timestamp",
    "pipeline_version",
    "content_hash",
    "ttl"
  ],
  "additionalProperties": false,
  "properties": {
    "event_id": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9_-]{8,64}$"
    },
    "schema_version": {
      "type": "string",
      "const": "v1"
    },
    "org_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128
    },
    "network_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128
    },
    "source": {
      "type": "string",
      "enum": ["meraki_poll", "meraki_webhook", "catalyst_poll"]
    },
    "event_type": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128
    },
    "event_payload": {
      "type": "object"
    },
    "source_url": {
      "type": "string",
      "format": "uri"
    },
    "harvest_timestamp": {
      "type": "string",
      "format": "date-time"
    },
    "pipeline_version": {
      "type": "string",
      "pattern": "^[a-f0-9]{40}$"
    },
    "content_hash": {
      "type": "string",
      "pattern": "^sha256:[a-f0-9]{64}$"
    },
    "ttl": {
      "type": "integer",
      "minimum": 1
    }
  }
} as const;

export interface VisusEvent {
  event_id: string;
  schema_version: 'v1';
  org_id: string;
  network_id: string;
  source: 'meraki_poll' | 'meraki_webhook' | 'catalyst_poll';
  event_type: string;
  event_payload: Record<string, unknown>;
  source_url: string;
  harvest_timestamp: string;
  pipeline_version: string;
  content_hash: string;
  ttl: number;
}

export interface VisusEventInput {
  event_id: string;
  schema_version: 'v1';
  org_id: string;
  network_id: string;
  source: 'meraki_poll' | 'meraki_webhook' | 'catalyst_poll';
  event_type: string;
  event_payload: Record<string, unknown>;
  source_url: string;
  harvest_timestamp: string;
  pipeline_version: string;
  content_hash: string;
  ttl: number;
}

export interface HashableFields {
  event_id: string;
  org_id: string;
  network_id: string;
  source: string;
  event_type: string;
  event_payload: Record<string, unknown>;
  source_url: string;
  harvest_timestamp: string;
  pipeline_version: string;
}

export function getHashableFields(event: VisusEventInput): HashableFields {
  return {
    event_id: event.event_id,
    org_id: event.org_id,
    network_id: event.network_id,
    source: event.source,
    event_type: event.event_type,
    event_payload: event.event_payload,
    source_url: event.source_url,
    harvest_timestamp: event.harvest_timestamp,
    pipeline_version: event.pipeline_version,
  };
}

let validateFn: ValidateFunction | null = null;

function getValidator(): ValidateFunction {
  if (!validateFn) {
    const ajv = new Ajv({ strict: true, allErrors: true });
    addFormats(ajv);
    validateFn = ajv.compile(eventSchema);
  }
  return validateFn;
}

export function validateEvent(record: unknown): VisusEvent {
  const validator = getValidator();
  const valid = validator(record);

  if (!valid) {
    const errors = validator.errors || [];
    const fieldPaths = errors.map((e) => `${e.instancePath}: ${e.message}`).join('; ');
    jsonLog('ERROR', 'Schema validation failed', {
      fieldPaths,
      errorCount: errors.length,
    });
    throw new ValidationError(
      `Event schema validation failed: ${fieldPaths}`,
      errors[0]?.instancePath || '',
    );
  }

  const event = record as VisusEvent;

  try {
    const hashableFields = getHashableFields(event);
    verifyContentHash(hashableFields, event.content_hash);
  } catch (error) {
    jsonLog('CRITICAL', 'Content hash verification failed', {
      event_id: event.event_id,
      org_id: event.org_id,
    });
    throw new ValidationError(
      `Content hash verification failed: ${(error as Error).message}`,
      'content_hash',
    );
  }

  return event;
}

export function validateEventBatch(records: unknown[]): { valid: VisusEvent[]; errors: { index: number; error: Error }[] } {
  const valid: VisusEvent[] = [];
  const errors: { index: number; error: Error }[] = [];

  for (let i = 0; i < records.length; i++) {
    try {
      const event = validateEvent(records[i]);
      valid.push(event);
    } catch (error) {
      errors.push({ index: i, error: error as Error });
    }
  }

  return { valid, errors };
}
