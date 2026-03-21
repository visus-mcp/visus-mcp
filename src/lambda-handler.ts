/**
 * AWS Lambda Handler - Phase 2 Hosted Tier
 *
 * Provides RESTful API endpoint for Visus sanitization service
 * Invoked via API Gateway → Lambda → DynamoDB audit logging
 *
 * SECURITY RULES (from CLAUDE.md):
 * - No secrets in code (use Secrets Manager)
 * - No wildcard IAM permissions
 * - All user input sanitized
 * - No cross-user data access
 * - Reserved concurrent executions set
 * - No plaintext logging of tokens/PII
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { visusFetch } from './tools/fetch.js';
import { visusFetchStructured } from './tools/fetch-structured.js';
import { closeBrowser } from './browser/playwright-renderer.js';

/**
 * API request body for visus_fetch
 */
interface FetchRequest {
  url: string;
  format?: 'markdown' | 'text';
  timeout_ms?: number;
}

/**
 * API request body for visus_fetch_structured
 */
interface FetchStructuredRequest {
  url: string;
  schema: Record<string, string>;
  timeout_ms?: number;
}

/**
 * Lambda handler for Visus API
 *
 * Routes:
 * - POST /fetch → visus_fetch
 * - POST /fetch-structured → visus_fetch_structured
 *
 * @param event API Gateway event
 * @param context Lambda context
 * @returns API Gateway response
 */
export async function handler(
  event: APIGatewayProxyEvent,
  context: Context
): Promise<APIGatewayProxyResult> {
  const requestId = context.awsRequestId;

  // Log request to stderr
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: 'lambda_invocation',
    request_id: requestId,
    path: event.path,
    method: event.httpMethod,
    source_ip: event.requestContext.identity.sourceIp,
    user_agent: event.headers['User-Agent'] || event.headers['user-agent'],
  }));

  try {
    // CORS headers for all responses
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*', // Phase 2: Open. Phase 3: Restrict to Lateos domains
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Content-Type': 'application/json',
    };

    // Handle preflight OPTIONS request
    if (event.httpMethod === 'OPTIONS') {
      return {
        statusCode: 200,
        headers: corsHeaders,
        body: '',
      };
    }

    // Only allow POST requests
    if (event.httpMethod !== 'POST') {
      return {
        statusCode: 405,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Method not allowed. Use POST.' }),
      };
    }

    // Parse request body
    let body: FetchRequest | FetchStructuredRequest;
    try {
      body = JSON.parse(event.body || '{}');
    } catch (error) {
      return {
        statusCode: 400,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Invalid JSON in request body' }),
      };
    }

    // Route based on path
    if (event.path === '/fetch' || event.path === '/prod/fetch') {
      const fetchReq = body as FetchRequest;

      // Validate request
      if (!fetchReq.url || typeof fetchReq.url !== 'string') {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Missing or invalid "url" field' }),
        };
      }

      // Call visus_fetch
      const result = await visusFetch(fetchReq);

      if (!result.ok) {
        return {
          statusCode: 500,
          headers: corsHeaders,
          body: JSON.stringify({ error: result.error.message }),
        };
      }

      return {
        statusCode: 200,
        headers: corsHeaders,
        body: JSON.stringify(result.value),
      };
    }

    if (event.path === '/fetch-structured' || event.path === '/prod/fetch-structured') {
      const fetchReq = body as FetchStructuredRequest;

      // Validate request
      if (!fetchReq.url || typeof fetchReq.url !== 'string') {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Missing or invalid "url" field' }),
        };
      }

      if (!fetchReq.schema || typeof fetchReq.schema !== 'object') {
        return {
          statusCode: 400,
          headers: corsHeaders,
          body: JSON.stringify({ error: 'Missing or invalid "schema" field' }),
        };
      }

      // Call visus_fetch_structured
      const result = await visusFetchStructured(fetchReq);

      if (!result.ok) {
        return {
          statusCode: 500,
          headers: corsHeaders,
          body: JSON.stringify({ error: result.error.message }),
        };
      }

      return {
        statusCode: 200,
        headers: corsHeaders,
        body: JSON.stringify(result.value),
      };
    }

    // Unknown path
    return {
      statusCode: 404,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Not found. Use /fetch or /fetch-structured' }),
    };

  } catch (error) {
    // Log error to stderr (CloudWatch Logs)
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'lambda_error',
      request_id: requestId,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    }));

    return {
      statusCode: 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  } finally {
    // Close browser to free resources
    // Lambda containers are reused, but we clean up after each invocation
    await closeBrowser();
  }
}

/**
 * Health check handler
 *
 * @returns API Gateway response
 */
export async function healthCheck(): Promise<APIGatewayProxyResult> {
  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      status: 'healthy',
      service: 'visus-mcp',
      version: '0.2.0',
      timestamp: new Date().toISOString(),
    }),
  };
}
