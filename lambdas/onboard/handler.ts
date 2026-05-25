import { Handler, APIGatewayProxyEventV2, APIGatewayProxyResultV2 } from 'aws-lambda';
import {
  SecretsManagerClient,
  PutSecretValueCommand,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import {
  DynamoDBClient,
  PutItemCommand,
} from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import { jsonLog, StructuredError, formatLambdaError } from '../../shared/errors.js';

interface OnboardRequest {
  meraki_api_key: string;
  meraki_org_id: string;
  meraki_network_ids: string[];
  meraki_webhook_secret: string;
  catalyst_url?: string;
  catalyst_username?: string;
  catalyst_password?: string;
}

const MAX_NETWORK_IDS = 50;

const secretsClient = new SecretsManagerClient({ region: process.env.AWS_REGION || 'us-east-1' });
const dynamoClient = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
const ORGS_TABLE = process.env.ORGS_TABLE || 'visus-orgs';

export const handler: Handler<APIGatewayProxyEventV2, APIGatewayProxyResultV2> = async (event) => {
  const startTime = Date.now();

  const claims = event.requestContext?.authorizer?.jwt?.claims;
  const org_id = claims?.['custom:org_id'] || claims?.sub;
  if (!org_id || typeof org_id !== 'string') {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: 'Authentication required', code: 'UNAUTHORIZED' }),
    };
  }

  if (!event.body) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing request body', code: 'INVALID_INPUT' }),
    };
  }

  let body: OnboardRequest;
  try {
    body = JSON.parse(event.body);
  } catch {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Malformed JSON body', code: 'INVALID_INPUT' }),
    };
  }

  if (!body.meraki_api_key) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'meraki_api_key is required', code: 'INVALID_INPUT' }),
    };
  }

  if (!body.meraki_org_id) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'meraki_org_id is required', code: 'INVALID_INPUT' }),
    };
  }

  if (!body.meraki_network_ids || !Array.isArray(body.meraki_network_ids) || body.meraki_network_ids.length === 0) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'meraki_network_ids must be a non-empty array', code: 'INVALID_INPUT' }),
    };
  }

  if (body.meraki_network_ids.length > MAX_NETWORK_IDS) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: `meraki_network_ids must contain at most ${MAX_NETWORK_IDS} items`, code: 'INVALID_INPUT' }),
    };
  }

  if (!body.meraki_webhook_secret) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'meraki_webhook_secret is required', code: 'INVALID_INPUT' }),
    };
  }

  const hasCatalyst = !!(body.catalyst_url && body.catalyst_username && body.catalyst_password);
  if (body.catalyst_url && (!body.catalyst_username || !body.catalyst_password)) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'catalyst_username and catalyst_password are required when catalyst_url is provided', code: 'INVALID_INPUT' }),
    };
  }

  jsonLog('INFO', 'Onboarding request received', {
    org_id,
    meraki_org_id: body.meraki_org_id,
    network_count: body.meraki_network_ids.length,
    has_catalyst: hasCatalyst,
  });

  try {
    const merakiResponse = await fetch('https://api.meraki.com/api/v1/organizations', {
      headers: {
        'X-Cisco-Meraki-API-Key': body.meraki_api_key,
        'Accept': 'application/json',
      },
    });

    if (!merakiResponse.ok) {
      jsonLog('WARN', 'Meraki API key validation failed', { org_id, status: merakiResponse.status });
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Invalid Meraki API key', code: 'INVALID_MERAKI_KEY' }),
      };
    }

    const orgs = (await merakiResponse.json()) as Array<{ id: string }>;
    const orgExists = orgs.some((org) => org.id === body.meraki_org_id);
    if (!orgExists) {
      jsonLog('WARN', 'Meraki org ID not accessible with provided key', { org_id, meraki_org_id: body.meraki_org_id });
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Meraki organization not accessible with provided API key', code: 'INVALID_MERAKI_ORG' }),
      };
    }

    if (hasCatalyst) {
      const authUrl = `${body.catalyst_url}/dna/system/api/v1/auth/token`;
      const credentials = Buffer.from(`${body.catalyst_username}:${body.catalyst_password}`).toString('base64');

      const catalystResponse = await fetch(authUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${credentials}`,
          'Content-Type': 'application/json',
        },
      });

      if (!catalystResponse.ok) {
        jsonLog('WARN', 'Catalyst credential validation failed', { org_id, status: catalystResponse.status });
        return {
          statusCode: 400,
          body: JSON.stringify({ error: 'Invalid Catalyst credentials', code: 'INVALID_CATALYST_CREDS' }),
        };
      }
    }

    const ciscoCreds: Record<string, unknown> = {
      meraki_api_key: body.meraki_api_key,
      meraki_org_id: body.meraki_org_id,
      meraki_network_ids: body.meraki_network_ids,
    };

    if (hasCatalyst) {
      ciscoCreds.catalyst_url = body.catalyst_url;
      ciscoCreds.catalyst_username = body.catalyst_username;
      ciscoCreds.catalyst_password = body.catalyst_password;
    }

    await secretsClient.send(
      new PutSecretValueCommand({
        SecretId: `visus/customers/${org_id}/cisco-creds`,
        SecretString: JSON.stringify(ciscoCreds),
      }),
    );

    await secretsClient.send(
      new PutSecretValueCommand({
        SecretId: `visus/customers/${org_id}/meraki-webhook-secret`,
        SecretString: body.meraki_webhook_secret,
      }),
    );

    await dynamoClient.send(
      new PutItemCommand({
        TableName: ORGS_TABLE,
        Item: marshall(
          {
            org_id,
            meraki_org_id: body.meraki_org_id,
            network_ids: body.meraki_network_ids,
            onboarded_at: new Date().toISOString(),
            active: true,
            frameworks: [],
          },
          { removeUndefinedValues: true },
        ),
      }),
    );

    const durationMs = Date.now() - startTime;
    jsonLog('INFO', 'Onboarding completed', {
      org_id,
      meraki_org_id: body.meraki_org_id,
      network_count: body.meraki_network_ids.length,
      has_catalyst: hasCatalyst,
      duration_ms: durationMs,
    });

    return {
      statusCode: 200,
      body: JSON.stringify({
        status: 'onboarded',
        first_poll_eta_seconds: 30,
        webhook_url: 'https://api.visus.lateos.ai/production/webhooks/meraki',
      }),
    };
  } catch (error) {
    jsonLog('ERROR', 'Onboarding failed', {
      org_id,
      error: (error as Error).message,
    });
    return {
      statusCode: 500,
      body: JSON.stringify(formatLambdaError(error)),
    };
  }
};
