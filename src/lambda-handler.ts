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
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { visusFetch } from './tools/fetch.js';
import { visusFetchStructured } from './tools/fetch-structured.js';
import { closeBrowser } from './browser/playwright-renderer.js';

// Initialize DynamoDB client
const ddbClient = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(ddbClient);

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
 * Fire-and-forget audit logging to DynamoDB
 *
 * Logs request metadata without blocking the response.
 * Errors are logged but do not affect the API response.
 *
 * @param userId User ID from Cognito JWT
 * @param requestId AWS request ID
 * @param url URL being fetched
 * @param endpoint API endpoint (/fetch or /fetch-structured)
 * @param patternsDetected Sanitization patterns detected
 * @param piiRedacted PII types redacted
 */
function logAuditEvent(
  userId: string,
  requestId: string,
  url: string,
  endpoint: string,
  patternsDetected: string[],
  piiRedacted: string[]
): void {
  const tableName = process.env.AUDIT_TABLE_NAME;

  if (!tableName) {
    console.error('AUDIT_TABLE_NAME not set - skipping audit logging');
    return;
  }

  const now = new Date();
  const ttl = Math.floor(now.getTime() / 1000) + (90 * 24 * 60 * 60); // 90 days from now (EU AI Act Code of Practice)

  const item = {
    user_id: userId,
    timestamp: now.toISOString(),
    request_id: requestId,
    url,
    endpoint,
    patterns_detected: patternsDetected,
    pii_redacted: piiRedacted,
    ttl, // Auto-delete after 30 days
  };

  // Fire-and-forget: do not await
  docClient.send(new PutCommand({
    TableName: tableName,
    Item: item,
  })).catch((error: unknown) => {
    // Log error but do not throw (fire-and-forget pattern)
    console.error(JSON.stringify({
      timestamp: now.toISOString(),
      event: 'audit_logging_failed',
      error: error instanceof Error ? error.message : String(error),
      request_id: requestId,
    }));
  });
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
    // CORS headers for all responses (environment-variable-driven allowlist)
    const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',');
    const origin = event.headers.origin || event.headers.Origin || '';
    const allowOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0] || '*';

    const corsHeaders = {
      'Access-Control-Allow-Origin': allowOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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

    // Health check endpoint (no auth required, allows GET and POST)
    // SECURITY FIX (FINDING 2): Moved before POST-only validation to support standard GET health checks
    if (event.path === '/health' || event.path === '/dev/health' || event.path === '/prod/health') {
      return {
        statusCode: 200,
        headers: corsHeaders,
        body: JSON.stringify({
          status: 'healthy',
          service: 'visus-mcp',
          version: '0.3.1',
          timestamp: new Date().toISOString(),
        }),
      };
    }

    // Only allow POST requests for protected endpoints
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

    // SECURITY FIX (FINDING 1): Application-level authentication enforcement
    // Extract user ID from Cognito authorizer
    const userId = event.requestContext.authorizer?.claims?.sub;

    // Require authentication for all protected endpoints (not already handled above)
    if (!userId) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        event: 'auth_required',
        request_id: requestId,
        path: event.path,
        reason: 'Missing Cognito authorizer context - Lambda must be invoked via API Gateway',
      }));

      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({
          error: 'Unauthorized: Authentication required. This Lambda must be invoked via API Gateway with Cognito authorizer.',
        }),
      };
    }

    // Route based on path
    if (event.path === '/fetch' || event.path === '/dev/fetch' || event.path === '/prod/fetch') {
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

      // Fire-and-forget audit logging
      logAuditEvent(
        userId,
        requestId,
        fetchReq.url,
        '/fetch',
        result.value.sanitization.patterns_detected,
        result.value.sanitization.pii_types_redacted
      );

      return {
        statusCode: 200,
        headers: corsHeaders,
        body: JSON.stringify(result.value),
      };
    }

    if (event.path === '/fetch-structured' || event.path === '/dev/fetch-structured' || event.path === '/prod/fetch-structured') {
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

      // Fire-and-forget audit logging
      logAuditEvent(
        userId,
        requestId,
        fetchReq.url,
        '/fetch-structured',
        result.value.sanitization.patterns_detected,
        result.value.sanitization.pii_types_redacted
      );

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
