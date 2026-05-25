import { Handler, APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import { jsonLog, StructuredError, formatLambdaError } from '../../shared/errors.js';
import { processAndStore, NormalizerInput } from '../ingest-normalizer/handler.js';

const PIPELINE_VERSION = process.env.PIPELINE_VERSION || '';

interface WebhookEvent {
  networkId?: string;
  organizationId?: string;
  sharedSecret?: string;
  alertData?: Record<string, unknown>;
  [key: string]: unknown;
}

const recentEventIds = new Map<string, number>();
const MAX_CACHE_SIZE = 10000;
const CACHE_TTL_MS = 5 * 60 * 1000;

function isDuplicate(eventId: string): boolean {
  const now = Date.now();
  const cached = recentEventIds.get(eventId);

  if (cached && now - cached < CACHE_TTL_MS) {
    return true;
  }

  recentEventIds.set(eventId, now);

  if (recentEventIds.size > MAX_CACHE_SIZE) {
    const oldestKey = recentEventIds.keys().next().value;
    if (oldestKey) {
      recentEventIds.delete(oldestKey);
    }
  }

  return false;
}

function determineEventType(body: WebhookEvent): string {
  if (body.alertData) {
    return 'meraki.webhook.ids_alert';
  }
  if (body.sharedSecret !== undefined) {
    return 'meraki.webhook.settings_changed';
  }
  return 'meraki.webhook.event';
}

export const handler: Handler<APIGatewayProxyEventV2, APIGatewayProxyResultV2> = async (event) => {
  const startTime = Date.now();

  if (!PIPELINE_VERSION) {
    jsonLog('ERROR', 'PIPELINE_VERSION environment variable not set');
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Server configuration error', code: 'INTERNAL_ERROR' }),
    };
  }

  if (!event.body) {
    jsonLog('WARN', 'Webhook received with empty body');
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing request body', code: 'INVALID_INPUT' }),
    };
  }

  let body: WebhookEvent;
  try {
    body = JSON.parse(event.body);
  } catch {
    jsonLog('WARN', 'Webhook received with malformed JSON body');
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Malformed JSON body', code: 'INVALID_INPUT' }),
    };
  }

  const eventBodyStr = JSON.stringify(body);
  if (Buffer.byteLength(eventBodyStr, 'utf8') > 1_000_000) {
    jsonLog('WARN', 'Webhook body exceeds 1MB limit');
    return {
      statusCode: 413,
      body: JSON.stringify({ error: 'Request body too large', code: 'PAYLOAD_TOO_LARGE' }),
    };
  }

  const sharedSecret = event.headers?.['x-cisco-meraki-network-secret'];
  if (!sharedSecret) {
    jsonLog('WARN', 'Webhook missing shared secret header');
    return {
      statusCode: 401,
      body: JSON.stringify({ error: 'Missing shared secret', code: 'UNAUTHORIZED' }),
    };
  }

  const networkId = body.networkId || 'unknown';
  const orgId = body.organizationId || 'unknown';

  const eventType = determineEventType(body);

  try {
    const normalizerInput: NormalizerInput = {
      org_id: orgId,
      network_id: networkId,
      source: 'meraki_webhook',
      source_url: event.rawPath || '/webhooks/meraki',
      event_type: eventType,
      pipeline_version: PIPELINE_VERSION,
      items: [body as Record<string, unknown>],
    };

    const result = await processAndStore(normalizerInput);

    const durationMs = Date.now() - startTime;
    jsonLog('INFO', 'Webhook processed', {
      network_id: networkId,
      org_id: orgId,
      event_type: eventType,
      duration_ms: durationMs,
      written: result.written,
      skipped: result.skipped,
    });

    return {
      statusCode: 200,
      body: JSON.stringify({ status: 'accepted' }),
    };
  } catch (error) {
    jsonLog('ERROR', 'Webhook processing failed', {
      network_id: networkId,
      error: (error as Error).message,
    });
    return {
      statusCode: 500,
      body: JSON.stringify(formatLambdaError(error)),
    };
  }
};
