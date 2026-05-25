import { StructuredError, ValidationError, NotFoundError, UnauthorizedError, SecretsManagerError, formatLambdaError, jsonLog } from '../../shared/errors.js';

describe('StructuredError', () => {
  it('creates with message, code, and statusCode', () => {
    const error = new StructuredError('test message', 'TEST_CODE', 400);
    expect(error.message).toBe('test message');
    expect(error.code).toBe('TEST_CODE');
    expect(error.statusCode).toBe(400);
    expect(error.name).toBe('StructuredError');
  });

  it('default statusCode is 500', () => {
    const error = new StructuredError('server error', 'INTERNAL', undefined, { detail: 'x' });
    expect(error.statusCode).toBe(500);
  });

  it('toResponse returns error and code', () => {
    const error = new StructuredError('bad request', 'BAD_INPUT', 400);
    expect(error.toResponse()).toEqual({ error: 'bad request', code: 'BAD_INPUT' });
  });

  it('stores details as context', () => {
    const error = new StructuredError('something', 'ERR', 500, { field: 'email' });
    expect(error.details).toEqual({ field: 'email' });
  });
});

describe('ValidationError', () => {
  it('creates with field path', () => {
    const error = new ValidationError('invalid email', 'email');
    expect(error.code).toBe('VALIDATION_ERROR');
    expect(error.statusCode).toBe(400);
    expect(error.fieldPath).toBe('email');
  });
});

describe('NotFoundError', () => {
  it('has status 404', () => {
    const error = new NotFoundError('not found');
    expect(error.statusCode).toBe(404);
    expect(error.code).toBe('NOT_FOUND');
  });
});

describe('UnauthorizedError', () => {
  it('has status 401', () => {
    const error = new UnauthorizedError('unauthorized');
    expect(error.statusCode).toBe(401);
    expect(error.code).toBe('UNAUTHORIZED');
  });
});

describe('SecretsManagerError', () => {
  it('has status 500', () => {
    const error = new SecretsManagerError('secret not found');
    expect(error.statusCode).toBe(500);
    expect(error.code).toBe('SECRETS_MANAGER_ERROR');
  });
});

describe('formatLambdaError', () => {
  it('formats StructuredError with error and code', () => {
    const error = new StructuredError('not allowed', 'FORBIDDEN', 403);
    expect(formatLambdaError(error)).toEqual({ error: 'not allowed', code: 'FORBIDDEN' });
  });

  it('formats plain Error with INTERNAL_ERROR', () => {
    const error = new Error('something broke');
    const result = formatLambdaError(error);
    expect(result.error).toBe('something broke');
    expect(result.code).toBe('INTERNAL_ERROR');
  });

  it('formats unknown value as generic error', () => {
    expect(formatLambdaError(null)).toEqual({
      error: 'An unknown error occurred',
      code: 'INTERNAL_ERROR',
    });
    expect(formatLambdaError(undefined)).toEqual({
      error: 'An unknown error occurred',
      code: 'INTERNAL_ERROR',
    });
    expect(formatLambdaError(42)).toEqual({
      error: 'An unknown error occurred',
      code: 'INTERNAL_ERROR',
    });
  });
});

describe('jsonLog', () => {
  it('writes structured JSON to stderr', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    jsonLog('INFO', 'test message', { key: 'value' });
    expect(spy).toHaveBeenCalledTimes(1);
    const output = JSON.parse(spy.mock.calls[0][0] as string);
    expect(output.level).toBe('INFO');
    expect(output.message).toBe('test message');
    expect(output.key).toBe('value');
    expect(output.timestamp).toBeDefined();
    spy.mockRestore();
  });

  it('handles undefined context', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    jsonLog('ERROR', 'oops');
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });
});
