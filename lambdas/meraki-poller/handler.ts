import { Handler, EventBridgeEvent } from 'aws-lambda';
import { jsonLog, StructuredError } from '../../shared/errors.js';

interface OrgConfig {
  org_id: string;
  meraki_api_key: string;
  meraki_org_id: string;
  network_ids: string[];
}

interface MerakiEndpointDef {
  id: string;
  path: (ids: { orgId: string; networkId: string }) => string;
  eventType: string;
  params: Record<string, unknown>;
}

const MERAKI_BASE_URL = 'https://api.meraki.com/api/v1';

const MERAKI_ENDPOINTS: readonly MerakiEndpointDef[] = [
  {
    id: 'network_events',
    path: (ids) => `/networks/${ids.networkId}/events`,
    eventType: 'meraki.network.event',
    params: { perPage: 1000 },
  },
  {
    id: 'security_events',
    path: (ids) => `/organizations/${ids.orgId}/appliance/security/events`,
    eventType: 'meraki.security.event',
    params: { perPage: 1000 },
  },
  {
    id: 'clients',
    path: (ids) => `/networks/${ids.networkId}/clients`,
    eventType: 'meraki.network.clients',
    params: { perPage: 1000, timespan: 86400 },
  },
  {
    id: 'device_statuses',
    path: (ids) => `/organizations/${ids.orgId}/devices/statuses`,
    eventType: 'meraki.org.device_statuses',
    params: {},
  },
  {
    id: 'vlans',
    path: (ids) => `/networks/${ids.networkId}/appliance/vlans`,
    eventType: 'meraki.network.vlans',
    params: {},
  },
  {
    id: 'ssids',
    path: (ids) => `/networks/${ids.networkId}/wireless/ssids`,
    eventType: 'meraki.network.ssids',
    params: {},
  },
] as const;

interface PollEvent {
  org_id: string;
  meraki_api_key: string;
  meraki_org_id: string;
  network_ids: string[];
  pipeline_version: string;
}

async function callMerakiApi(
  apiKey: string,
  path: string,
  params: Record<string, unknown>,
): Promise<{ data: unknown; status: number; headers: Record<string, string> }> {
  const queryParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      queryParams.append(key, String(value));
    }
  }

  const queryString = queryParams.toString();
  const url = `${MERAKI_BASE_URL}${path}${queryString ? '?' + queryString : ''}`;

  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'X-Cisco-Meraki-API-Key': apiKey,
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
  });

  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  let data: unknown;
  const contentType = headers['content-type'] || '';
  if (contentType.includes('application/json')) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  return { data, status: response.status, headers };
}

export const handler: Handler<EventBridgeEvent<'Scheduled Event', PollEvent>, void> = async (event) => {
  const detail = event.detail;
  const { org_id, meraki_api_key, meraki_org_id, network_ids, pipeline_version } = detail;

  if (!pipeline_version) {
    throw new StructuredError('pipeline_version is required in event detail', 'MISSING_PIPELINE_VERSION', 400);
  }

  jsonLog('INFO', 'Meraki poll cycle started', {
    org_id,
    meraki_org_id,
    network_count: network_ids.length,
  });

  let totalEvents = 0;
  const consecutive429s: Record<string, number> = {};

  for (const networkId of network_ids) {
    for (const endpoint of MERAKI_ENDPOINTS) {
      const startTime = Date.now();

      try {
        const path = endpoint.path({ orgId: meraki_org_id, networkId });
        const { data, status, headers } = await callMerakiApi(
          meraki_api_key,
          path,
          endpoint.params,
        );

        if (status === 429) {
          consecutive429s[endpoint.id] = (consecutive429s[endpoint.id] || 0) + 1;
          const retryAfter = parseInt(headers['retry-after'] || '1', 10);
          jsonLog('WARN', 'Meraki API rate limited (429)', {
            org_id,
            network_id: networkId,
            endpoint: endpoint.id,
            consecutive_429_count: consecutive429s[endpoint.id],
            retry_after_seconds: retryAfter,
          });

          if (consecutive429s[endpoint.id] >= 5) {
            jsonLog('CRITICAL', 'Meraki API consecutive 429 threshold reached', {
              org_id,
              network_id: networkId,
              endpoint: endpoint.id,
              consecutive_429_count: consecutive429s[endpoint.id],
            });
          }

          await new Promise((resolve) => setTimeout(resolve, retryAfter * 1000));
          continue;
        }

        if (status >= 400 && status !== 429) {
          jsonLog('ERROR', 'Meraki API non-retryable error', {
            org_id,
            network_id: networkId,
            endpoint: endpoint.id,
            status,
          });
          continue;
        }

        consecutive429s[endpoint.id] = 0;

        const items: Record<string, unknown>[] = Array.isArray(data) ? data : [data];
        totalEvents += items.length;

        const durationMs = Date.now() - startTime;
        jsonLog('INFO', 'Meraki endpoint polled', {
          org_id,
          network_id: networkId,
          endpoint: endpoint.id,
          event_count: items.length,
          duration_ms: durationMs,
        });
      } catch (error) {
        jsonLog('ERROR', 'Meraki API call failed', {
          org_id,
          network_id: networkId,
          endpoint: endpoint.id,
          error: (error as Error).message,
        });
      }
    }
  }

  jsonLog('INFO', 'Meraki poll cycle completed', {
    org_id,
    total_events_harvested: totalEvents,
  });
};
