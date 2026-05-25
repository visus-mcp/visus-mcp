import { Handler, EventBridgeEvent } from 'aws-lambda';
import { jsonLog, StructuredError } from '../../shared/errors.js';

interface CatalystPollEvent {
  org_id: string;
  catalyst_url: string;
  catalyst_username: string;
  catalyst_password: string;
  pipeline_version: string;
}

interface CatalystEndpointDef {
  path: string;
  eventType: string;
}

const CATALYST_ENDPOINTS: CatalystEndpointDef[] = [
  { path: '/dna/intent/api/v1/network-device', eventType: 'catalyst.device.inventory' },
  { path: '/dna/intent/api/v1/issues', eventType: 'catalyst.network.issues' },
  { path: '/dna/intent/api/v1/topology/network-health', eventType: 'catalyst.network.health' },
  { path: '/dna/intent/api/v1/client-detail', eventType: 'catalyst.client.detail' },
];

interface TokenCache {
  token: string;
  expiresAt: number;
}

const tokenCache: Map<string, TokenCache> = new Map();

async function getToken(
  orgId: string,
  catalystUrl: string,
  username: string,
  password: string,
): Promise<string> {
  const cached = tokenCache.get(orgId);
  if (cached && Date.now() < cached.expiresAt - 5 * 60 * 1000) {
    return cached.token;
  }

  const authUrl = `${catalystUrl}/dna/system/api/v1/auth/token`;
  const credentials = Buffer.from(`${username}:${password}`).toString('base64');

  const response = await fetch(authUrl, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/json',
    },
  });

  if (response.status === 401) {
    jsonLog('ERROR', 'Catalyst authentication failed');
    throw new StructuredError(
      'Catalyst Center authentication failed',
      'CATALYST_AUTH_FAILURE',
      500,
    );
  }

  if (!response.ok) {
    throw new StructuredError(
      `Catalyst auth token request failed: ${response.status} ${response.statusText}`,
      'CATALYST_AUTH_ERROR',
      500,
    );
  }

  const data = (await response.json()) as { Token?: string };
  if (!data.Token) {
    throw new StructuredError('No token in Catalyst auth response', 'CATALYST_AUTH_ERROR', 500);
  }

  tokenCache.set(orgId, {
    token: data.Token,
    expiresAt: Date.now() + 55 * 60 * 1000,
  });

  jsonLog('INFO', 'Catalyst token refreshed', {
    org_id: orgId,
    token_refresh: true,
  });

  return data.Token;
}

export const handler: Handler<EventBridgeEvent<'Scheduled Event', CatalystPollEvent>, void> = async (event) => {
  const detail = event.detail;
  const { org_id, catalyst_url, catalyst_username, catalyst_password, pipeline_version } = detail;

  if (!pipeline_version) {
    throw new StructuredError('pipeline_version is required', 'MISSING_PIPELINE_VERSION', 400);
  }

  jsonLog('INFO', 'Catalyst poll cycle started', {
    org_id,
    catalyst_url: catalyst_url.replace(/\/\/.*@/, '//***:***@'),
  });

  let totalEvents = 0;

  for (const endpoint of CATALYST_ENDPOINTS) {
    const startTime = Date.now();

    try {
      const token = await getToken(org_id, catalyst_url, catalyst_username, catalyst_password);
      const url = `${catalyst_url}${endpoint.path}`;

      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'X-Auth-Token': token,
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
      });

      if (response.status === 401) {
        jsonLog('WARN', 'Catalyst token expired mid-execution, refreshing', { org_id });
        const newToken = await getToken(org_id, catalyst_url, catalyst_username, catalyst_password);

        const retryResponse = await fetch(url, {
          method: 'GET',
          headers: {
            'X-Auth-Token': newToken,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
          },
        });

        if (retryResponse.status === 401) {
          jsonLog('ERROR', 'Catalyst auth failure after token refresh', { org_id });
          continue;
        }

        const retryData = await retryResponse.json();
        const retryItems: Record<string, unknown>[] = Array.isArray(retryData)
          ? retryData
          : [retryData];
        totalEvents += retryItems.length;

        const durationMs = Date.now() - startTime;
        jsonLog('INFO', 'Catalyst endpoint polled (after retry)', {
          org_id,
          endpoint: endpoint.eventType,
          event_count: retryItems.length,
          duration_ms: durationMs,
        });
        continue;
      }

      if (!response.ok) {
        jsonLog('ERROR', 'Catalyst API error', {
          org_id,
          endpoint: endpoint.eventType,
          status: response.status,
        });
        continue;
      }

      const data = await response.json();
      const items: Record<string, unknown>[] = Array.isArray(data) ? data : [data];
      totalEvents += items.length;

      const durationMs = Date.now() - startTime;
      jsonLog('INFO', 'Catalyst endpoint polled', {
        org_id,
        endpoint: endpoint.eventType,
        event_count: items.length,
        duration_ms: durationMs,
      });
    } catch (error) {
      jsonLog('ERROR', 'Catalyst API call failed', {
        org_id,
        endpoint: endpoint.eventType,
        error: (error as Error).message,
      });
    }
  }

  jsonLog('INFO', 'Catalyst poll cycle completed', {
    org_id,
    total_events_harvested: totalEvents,
  });
};
