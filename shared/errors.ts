export class StructuredError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly details?: Record<string, unknown>;

  constructor(message: string, code: string, statusCode: number = 500, details?: Record<string, unknown>) {
    super(message);
    this.name = 'StructuredError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }

  toResponse(): Record<string, unknown> {
    return {
      error: this.message,
      code: this.code,
    };
  }
}

export class ValidationError extends StructuredError {
  public readonly fieldPath: string;

  constructor(message: string, fieldPath: string) {
    super(message, 'VALIDATION_ERROR', 400, { fieldPath });
    this.name = 'ValidationError';
    this.fieldPath = fieldPath;
  }
}

export class NotFoundError extends StructuredError {
  constructor(message: string) {
    super(message, 'NOT_FOUND', 404);
    this.name = 'NotFoundError';
  }
}

export class UnauthorizedError extends StructuredError {
  constructor(message: string) {
    super(message, 'UNAUTHORIZED', 401);
    this.name = 'UnauthorizedError';
  }
}

export class SecretsManagerError extends StructuredError {
  constructor(message: string) {
    super(message, 'SECRETS_MANAGER_ERROR', 500);
    this.name = 'SecretsManagerError';
  }
}

export function formatLambdaError(error: unknown): Record<string, unknown> {
  if (error instanceof StructuredError) {
    return error.toResponse();
  }
  if (error instanceof Error) {
    return {
      error: error.message,
      code: 'INTERNAL_ERROR',
    };
  }
  return {
    error: 'An unknown error occurred',
    code: 'INTERNAL_ERROR',
  };
}

export function jsonLog(level: string, message: string, context?: Record<string, unknown>): void {
  const entry: Record<string, unknown> = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...context,
  };
  console.error(JSON.stringify(entry));
}
