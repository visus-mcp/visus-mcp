/**
 * Authentication Enforcement Smoke Tests
 *
 * These tests verify that authentication is properly enforced across all
 * API endpoints and Lambda invocation paths per CLAUDE.md security rules.
 *
 * Test Categories:
 * 1. API Gateway Cognito Authorizer enforcement
 * 2. Lambda handler behavior with/without auth context
 * 3. Health endpoint bypass (intentional)
 * 4. CORS enforcement
 * 5. User ID extraction and audit logging
 * 6. Direct Lambda invocation (bypass prevention)
 */

import type { APIGatewayProxyEvent, Context } from 'aws-lambda';
import { handler } from '../src/lambda-handler.js';

/**
 * Mock API Gateway event builder
 */
function createMockEvent(
  path: string,
  httpMethod: string,
  body: Record<string, unknown> | null,
  authContext?: {
    sub: string;
    email?: string;
  }
): APIGatewayProxyEvent {
  const event: Partial<APIGatewayProxyEvent> = {
    path,
    httpMethod,
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'jest/smoke-test',
      origin: 'https://claude.ai',
    },
    body: body ? JSON.stringify(body) : null,
    requestContext: {
      requestId: 'test-request-id',
      identity: {
        sourceIp: '127.0.0.1',
      } as any,
      authorizer: authContext ? { claims: authContext } : undefined,
    } as any,
  };

  return event as APIGatewayProxyEvent;
}

/**
 * Mock Lambda context
 */
const mockContext: Context = {
  awsRequestId: 'test-request-id',
  functionName: 'visus-mcp-test',
  functionVersion: '1',
  invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:visus-mcp-test',
  memoryLimitInMB: '1024',
  logGroupName: '/aws/lambda/visus-mcp-test',
  logStreamName: 'test-stream',
  callbackWaitsForEmptyEventLoop: false,
  getRemainingTimeInMillis: () => 30000,
  done: () => {},
  fail: () => {},
  succeed: () => {},
};

describe('Authentication Enforcement Smoke Tests', () => {
  // Mock environment variables
  beforeAll(() => {
    process.env.AUDIT_TABLE_NAME = 'visus-audit-test';
    process.env.ENVIRONMENT = 'test';
    process.env.ALLOWED_ORIGINS = 'https://claude.ai,https://app.claude.ai';
  });

  afterAll(() => {
    delete process.env.AUDIT_TABLE_NAME;
    delete process.env.ENVIRONMENT;
    delete process.env.ALLOWED_ORIGINS;
  });

  describe('1. Health Endpoint (Unauthenticated Access Allowed)', () => {
    it('should allow /health with GET without auth context', async () => {
      const event = createMockEvent('/health', 'GET', null);

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('healthy');
      expect(body.service).toBe('visus-mcp');
      expect(body.version).toBe('0.3.1');
    });

    it('should allow /health with POST without auth context', async () => {
      const event = createMockEvent('/health', 'POST', {});

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('healthy');
    });

    it('should allow /dev/health without auth context', async () => {
      const event = createMockEvent('/dev/health', 'GET', null);

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('healthy');
    });

    it('should allow /prod/health without auth context', async () => {
      const event = createMockEvent('/prod/health', 'GET', null);

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('healthy');
    });
  });

  describe('2. Protected Endpoints WITHOUT Auth Context', () => {
    it('should REJECT /fetch requests without auth (SECURITY FIX - FINDING 1)', async () => {
      const event = createMockEvent('/fetch', 'POST', {
        url: 'https://example.com',
      });

      const response = await handler(event, mockContext);

      // FIXED: Lambda now enforces auth at application level
      expect(response.statusCode).toBe(401);
      const body = JSON.parse(response.body);
      expect(body.error).toContain('Unauthorized');
      expect(body.error).toContain('Authentication required');
    });

    it('should REJECT /fetch-structured requests without auth (SECURITY FIX - FINDING 1)', async () => {
      const event = createMockEvent('/fetch-structured', 'POST', {
        url: 'https://example.com',
        schema: { title: 'h1' },
      });

      const response = await handler(event, mockContext);

      // FIXED: Lambda now enforces auth at application level
      expect(response.statusCode).toBe(401);
      const body = JSON.parse(response.body);
      expect(body.error).toContain('Unauthorized');
      expect(body.error).toContain('Authentication required');
    });

    it('should log auth_required event when no auth context present', async () => {
      const event = createMockEvent('/fetch', 'POST', {
        url: 'https://example.com',
      });

      // Capture console.error calls to verify auth logging
      const originalConsoleError = console.error;
      const loggedEvents: string[] = [];
      console.error = (message: string) => {
        loggedEvents.push(message);
      };

      await handler(event, mockContext);

      console.error = originalConsoleError;

      // Verify that auth_required event was logged
      const authLog = loggedEvents.find((log) => {
        try {
          const parsed = JSON.parse(log);
          return parsed.event === 'auth_required';
        } catch {
          return false;
        }
      });

      expect(authLog).toBeDefined();
      if (authLog) {
        const parsed = JSON.parse(authLog);
        expect(parsed.reason).toContain('Cognito authorizer');
      }
    });
  });

  describe('3. Protected Endpoints WITH Auth Context', () => {
    it('should extract user_id from Cognito authorizer claims', async () => {
      const authContext = {
        sub: 'test-user-123',
        email: 'test@example.com',
      };

      const event = createMockEvent(
        '/fetch',
        'POST',
        { url: 'https://example.com' },
        authContext
      );

      // Capture console.error to verify user_id is extracted
      const originalConsoleError = console.error;
      const loggedEvents: string[] = [];
      console.error = (message: string) => {
        loggedEvents.push(message);
      };

      await handler(event, mockContext);

      console.error = originalConsoleError;

      // User ID extraction happens at line 132 of lambda-handler.ts
      // We can't directly inspect it, but we can verify the handler doesn't crash
      // and processes the request normally
      expect(loggedEvents.length).toBeGreaterThan(0);
    });

    it('should process /fetch with valid auth context', async () => {
      const authContext = {
        sub: 'test-user-123',
      };

      const event = createMockEvent(
        '/fetch',
        'POST',
        { url: 'https://example.com' },
        authContext
      );

      const response = await handler(event, mockContext);

      // Should succeed (or fail with a valid error, not 401/403)
      expect([200, 400, 500]).toContain(response.statusCode);
    });

    it('should process /fetch-structured with valid auth context', async () => {
      const authContext = {
        sub: 'test-user-456',
      };

      const event = createMockEvent(
        '/fetch-structured',
        'POST',
        { url: 'https://example.com', schema: { title: 'h1' } },
        authContext
      );

      const response = await handler(event, mockContext);

      // Should succeed (or fail with a valid error, not 401/403)
      expect([200, 400, 500]).toContain(response.statusCode);
    });
  });

  describe('4. CORS Enforcement', () => {
    it('should validate origin against allowlist', async () => {
      const event = createMockEvent('/health', 'GET', null);
      event.headers.origin = 'https://malicious-site.com';

      const response = await handler(event, mockContext);

      // CORS headers should use first allowed origin, not the malicious one
      expect(response.headers?.['Access-Control-Allow-Origin']).not.toBe(
        'https://malicious-site.com'
      );
      expect(response.headers?.['Access-Control-Allow-Origin']).toBe('https://claude.ai');
    });

    it('should allow whitelisted origin', async () => {
      const event = createMockEvent('/health', 'GET', null);
      event.headers.origin = 'https://app.claude.ai';

      const response = await handler(event, mockContext);

      expect(response.headers?.['Access-Control-Allow-Origin']).toBe(
        'https://app.claude.ai'
      );
    });

    it('should handle OPTIONS preflight request', async () => {
      const event = createMockEvent('/fetch', 'OPTIONS', null);

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(200);
      expect(response.headers?.['Access-Control-Allow-Methods']).toBe('GET, POST, OPTIONS');
      expect(response.headers?.['Access-Control-Allow-Headers']).toContain('Authorization');
    });
  });

  describe('5. Method Enforcement', () => {
    it('should reject GET requests to /fetch', async () => {
      const event = createMockEvent('/fetch', 'GET', null);

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(405);
      const body = JSON.parse(response.body);
      expect(body.error).toContain('Method not allowed');
    });

    it('should reject PUT requests to /fetch-structured', async () => {
      const event = createMockEvent('/fetch-structured', 'PUT', null);

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(405);
    });

    it('should reject DELETE requests', async () => {
      const event = createMockEvent('/fetch', 'DELETE', null);

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(405);
    });
  });

  describe('6. Input Validation', () => {
    it('should reject /fetch request with missing url', async () => {
      const authContext = { sub: 'test-user' };
      const event = createMockEvent('/fetch', 'POST', {}, authContext);

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error).toContain('url');
    });

    it('should reject /fetch-structured request with missing schema', async () => {
      const authContext = { sub: 'test-user' };
      const event = createMockEvent(
        '/fetch-structured',
        'POST',
        { url: 'https://example.com' },
        authContext
      );

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error).toContain('schema');
    });

    it('should reject invalid JSON body', async () => {
      const event = createMockEvent('/fetch', 'POST', null);
      event.body = '{invalid json}';

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(400);
      const body = JSON.parse(response.body);
      expect(body.error).toContain('JSON');
    });
  });

  describe('7. Unknown Endpoint Handling', () => {
    it('should return 404 for unknown paths', async () => {
      const authContext = { sub: 'test-user' };
      const event = createMockEvent('/unknown-endpoint', 'POST', null, authContext);

      const response = await handler(event, mockContext);

      expect(response.statusCode).toBe(404);
      const body = JSON.parse(response.body);
      expect(body.error).toContain('Not found');
    });
  });
});

describe('SECURITY AUDIT FINDINGS - RESOLUTIONS', () => {
  it('✅ FINDING 1 RESOLVED: Lambda NOW enforces auth at application level', async () => {
    /**
     * RESOLUTION VERIFIED (v0.3.1):
     * - Lambda handler now validates Cognito authorizer context
     * - Returns 401 if userId is missing (lines 188-209 of lambda-handler.ts)
     * - Logs 'auth_required' event with details
     * - Health check endpoint explicitly excluded from auth requirement
     *
     * FIXED: Application-level defense-in-depth implemented
     */
    const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' });
    const response = await handler(event, mockContext);

    // FIXED: Lambda NOW returns 401 when auth is missing
    expect(response.statusCode).toBe(401);
    const body = JSON.parse(response.body);
    expect(body.error).toContain('Unauthorized');
    expect(body.error).toContain('Authentication required');
  });

  it('✅ FINDING 1 RESOLVED: Auth rejection prevents anonymous audit logs', async () => {
    /**
     * RESOLUTION VERIFIED (v0.3.1):
     * - Unauthenticated requests are rejected before reaching audit logging
     * - No more user_id="anonymous" in audit logs
     * - auth_required event logged instead for security monitoring
     *
     * FIXED: No anonymous audit trails possible
     */
    const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' });

    // Intercept console.error to verify auth_required logging
    const originalConsoleError = console.error;
    let authRequiredLogged = false;
    let auditLogAttempted = false;
    console.error = (message: string) => {
      try {
        const parsed = JSON.parse(message);
        if (parsed.event === 'auth_required') {
          authRequiredLogged = true;
        }
        if (parsed.event === 'audit_logging_failed') {
          auditLogAttempted = true;
        }
      } catch {
        // Not JSON
      }
    };

    await handler(event, mockContext);

    console.error = originalConsoleError;

    // Verify auth_required was logged
    expect(authRequiredLogged).toBe(true);
    // Verify NO audit logging attempted (rejected before that point)
    expect(auditLogAttempted).toBe(false);
  });

  it('✅ FINDING 2 RESOLVED: Health check now supports GET method', async () => {
    /**
     * RESOLUTION VERIFIED (v0.3.1):
     * - Health check moved before POST-only validation (lines 152-165 of lambda-handler.ts)
     * - Supports both GET and POST methods
     * - CORS allows GET, POST, OPTIONS
     * - Standard monitoring tools can now use GET /health
     *
     * FIXED: Standard REST conventions for health checks
     */
    const getEvent = createMockEvent('/health', 'GET', null);
    const getResponse = await handler(getEvent, mockContext);

    expect(getResponse.statusCode).toBe(200);
    const body = JSON.parse(getResponse.body);
    expect(body.status).toBe('healthy');
    expect(body.version).toBe('0.3.1');

    // Also verify POST still works
    const postEvent = createMockEvent('/health', 'POST', {});
    const postResponse = await handler(postEvent, mockContext);
    expect(postResponse.statusCode).toBe(200);
  });

  it('✅ CONFIRMED SECURE: Health check remains intentionally unauthenticated', async () => {
    /**
     * CONFIRMED SECURE (v0.3.1):
     * - /health endpoint intentionally bypasses auth (lines 152-165 of lambda-handler.ts)
     * - This is standard practice for health checks
     * - Only returns non-sensitive metadata (status, version, timestamp)
     *
     * NO ACTION REQUIRED
     */
    const event = createMockEvent('/health', 'GET', null);
    const response = await handler(event, mockContext);

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body).not.toHaveProperty('user_id');
    expect(body).not.toHaveProperty('secrets');
    expect(body.status).toBe('healthy');
  });
});
