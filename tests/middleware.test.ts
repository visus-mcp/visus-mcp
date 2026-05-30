import {
  validateHostHeader,
  validateOrigin,
  enforceRateLimit,
  _resetRateLimitStoreForTest,
} from '../src/middleware/request-validator.js';

import type { APIGatewayProxyEvent, Context } from 'aws-lambda';
import { handler } from '../src/lambda-handler.js';

const ALLOWED_HOSTS = ['wyomy29zd7.execute-api.us-east-1.amazonaws.com'];
const ALLOWED_ORIGIN_PATTERNS = [/^https:\/\/claude\.ai$/, /^http:\/\/localhost/];
const RATE_LIMITS = { rps: 10, rpd: 1000 };

function createMockEvent(
  path: string,
  httpMethod: string,
  body: Record<string, unknown> | null,
  overrides?: {
    host?: string;
    origin?: string;
    authSub?: string;
  },
): APIGatewayProxyEvent {
  const event: Partial<APIGatewayProxyEvent> = {
    path,
    httpMethod,
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'jest/middleware-test',
      Host: overrides?.host ?? ALLOWED_HOSTS[0],
      Origin: overrides?.origin ?? 'https://claude.ai',
    },
    body: body ? JSON.stringify(body) : null,
    requestContext: {
      requestId: 'test-request-id',
      identity: { sourceIp: '127.0.0.1' } as any,
      authorizer: overrides?.authSub
        ? { claims: { sub: overrides.authSub } }
        : { claims: { sub: 'test-user' } },
    } as any,
  };
  return event as APIGatewayProxyEvent;
}

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

beforeEach(() => {
  _resetRateLimitStoreForTest();
  process.env.AUDIT_TABLE_NAME = 'visus-audit-test';
  process.env.ENVIRONMENT = 'test';
});

afterEach(() => {
  delete process.env.AUDIT_TABLE_NAME;
  delete process.env.ENVIRONMENT;
});

describe('validateHostHeader', () => {
  it('should accept matching host', () => {
    expect(validateHostHeader('wyomy29zd7.execute-api.us-east-1.amazonaws.com', ALLOWED_HOSTS)).toBe(true);
  });

  it('should reject spoofed host', () => {
    expect(validateHostHeader('attacker.com', ALLOWED_HOSTS)).toBe(false);
  });

  it('should reject null/undefined host', () => {
    expect(validateHostHeader(null, ALLOWED_HOSTS)).toBe(false);
    expect(validateHostHeader(undefined, ALLOWED_HOSTS)).toBe(false);
  });

  it('should reject empty string host', () => {
    expect(validateHostHeader('', ALLOWED_HOSTS)).toBe(false);
  });
});

describe('validateOrigin', () => {
  it('should accept valid origin', () => {
    expect(validateOrigin('https://claude.ai', ALLOWED_ORIGIN_PATTERNS)).toBe(true);
  });

  it('should accept localhost origin with port', () => {
    expect(validateOrigin('http://localhost:3000', ALLOWED_ORIGIN_PATTERNS)).toBe(true);
  });

  it('should reject invalid origin', () => {
    expect(validateOrigin('https://evil.com', ALLOWED_ORIGIN_PATTERNS)).toBe(false);
  });

  it('should allow undefined origin (CLI/preflight)', () => {
    expect(validateOrigin(undefined, ALLOWED_ORIGIN_PATTERNS)).toBe(true);
  });

  it('should reject origin with query params', () => {
    expect(validateOrigin('https://claude.ai?token=abc', ALLOWED_ORIGIN_PATTERNS)).toBe(false);
  });

  it('should accept multiple valid origins', () => {
    expect(validateOrigin('https://claude.ai', ALLOWED_ORIGIN_PATTERNS)).toBe(true);
    expect(validateOrigin('http://localhost', ALLOWED_ORIGIN_PATTERNS)).toBe(true);
    expect(validateOrigin('http://localhost:8080', ALLOWED_ORIGIN_PATTERNS)).toBe(true);
  });
});

describe('enforceRateLimit', () => {
  it('should allow requests within rate limit', () => {
    for (let i = 0; i < 10; i++) {
      expect(enforceRateLimit('user-1', RATE_LIMITS)).toBe(true);
    }
  });

  it('should block 11th request per second', () => {
    for (let i = 0; i < 10; i++) {
      enforceRateLimit('user-2', RATE_LIMITS);
    }
    expect(enforceRateLimit('user-2', RATE_LIMITS)).toBe(false);
  });

  it('should allow requests across different apiKeys independently', () => {
    for (let i = 0; i < 10; i++) {
      enforceRateLimit('user-a', RATE_LIMITS);
    }
    expect(enforceRateLimit('user-b', RATE_LIMITS)).toBe(true);
  });

  it('should return true when apiKey is undefined', () => {
    expect(enforceRateLimit(undefined, RATE_LIMITS)).toBe(true);
  });
});

describe('Handler-level validation chain (Host → Origin → Rate Limit → Auth)', () => {
  it('✅ Valid Host + valid Origin → proceeds to auth', async () => {
    const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' });
    const response = await handler(event, mockContext);
    expect(response.statusCode).not.toBe(400);
    expect(response.statusCode).not.toBe(403);
    expect(response.statusCode).not.toBe(429);
  });

  it('❌ Spoofed Host (attacker.com) → 400', async () => {
    const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' }, { host: 'attacker.com' });
    const response = await handler(event, mockContext);
    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error).toBe('Invalid Host header');
  });

  it('❌ Missing Host → 400', async () => {
    const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' }, { host: '' });
    const response = await handler(event, mockContext);
    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error).toBe('Invalid Host header');
  });

  it('❌ Invalid Origin → 403', async () => {
    const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' }, { origin: 'https://evil.com' });
    const response = await handler(event, mockContext);
    expect(response.statusCode).toBe(403);
    const body = JSON.parse(response.body);
    expect(body.error).toBe('CORS policy violation');
  });

  it('✅ Undefined Origin (CLI) → allowed', async () => {
    const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' }, { origin: undefined });
    const response = await handler(event, mockContext);
    expect(response.statusCode).not.toBe(403);
  });

  it('❌ Rate limit: 10/sec exceeded → 429', async () => {
    const authSub = 'rate-test-user';
    for (let i = 0; i < 10; i++) {
      const ev = createMockEvent('/fetch', 'POST', { url: 'https://example.com' }, { authSub });
      await handler(ev, mockContext);
    }
    const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' }, { authSub });
    const response = await handler(event, mockContext);
    expect(response.statusCode).toBe(429);
    const body = JSON.parse(response.body);
    expect(body.error).toBe('Too Many Requests');
  });

  it('❌ Rate limit: 1000/day exceeded → 429', () => {
    _resetRateLimitStoreForTest();
    for (let i = 0; i < 1000; i++) {
      enforceRateLimit('day-limit-user', { rps: 10000, rpd: 1000 });
    }
    expect(enforceRateLimit('day-limit-user', { rps: 10000, rpd: 1000 })).toBe(false);
  });

  it('✅ Rate limit within bounds → proceeds', async () => {
    const authSub = 'within-bounds-user';
    for (let i = 0; i < 5; i++) {
      const ev = createMockEvent('/fetch', 'POST', { url: 'https://example.com' }, { authSub });
      await handler(ev, mockContext);
    }
    const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' }, { authSub });
    const response = await handler(event, mockContext);
    expect(response.statusCode).not.toBe(429);
  });

  it('✅ Multiple valid origins pass', async () => {
    const origins = ['https://claude.ai', 'http://localhost', 'http://localhost:3000'];
    for (const origin of origins) {
      _resetRateLimitStoreForTest();
      const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' }, { origin });
      const response = await handler(event, mockContext);
      expect(response.statusCode).not.toBe(403);
    }
  });

  it('❌ Origin with query params → rejected', async () => {
    const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' }, { origin: 'https://claude.ai?token=abc' });
    const response = await handler(event, mockContext);
    expect(response.statusCode).toBe(403);
    const body = JSON.parse(response.body);
    expect(body.error).toBe('CORS policy violation');
  });

  it('✅ localhost:* wildcard works', async () => {
    _resetRateLimitStoreForTest();
    const event = createMockEvent('/fetch', 'POST', { url: 'https://example.com' }, { origin: 'http://localhost:8080' });
    const response = await handler(event, mockContext);
    expect(response.statusCode).not.toBe(403);
  });
});
