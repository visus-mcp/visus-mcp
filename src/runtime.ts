/**
 * Runtime Detection - Dual-Mode Support
 *
 * Detects execution environment and provides appropriate entry points:
 * - stdio MCP server (npx visus-mcp)
 * - AWS Lambda function (API Gateway + Lambda)
 *
 * This enables a unified codebase for both open-source and hosted tiers.
 */

/**
 * Runtime environment types
 */
export type RuntimeEnvironment = 'stdio' | 'lambda' | 'unknown';

/**
 * Runtime configuration
 */
export interface RuntimeConfig {
  environment: RuntimeEnvironment;
  isLambda: boolean;
  isStdio: boolean;
  region?: string;
  functionName?: string;
}

/**
 * Detect current runtime environment
 *
 * Detection logic:
 * 1. AWS_LAMBDA_FUNCTION_NAME exists → Lambda
 * 2. VISUS_MCP_MODE=stdio → stdio (explicit override)
 * 3. stdin is a TTY → unknown/error
 * 4. Default → stdio (MCP server mode)
 *
 * @returns Runtime configuration
 */
export function detectRuntime(): RuntimeConfig {
  // Check for AWS Lambda environment
  const lambdaFunctionName = process.env.AWS_LAMBDA_FUNCTION_NAME;
  const lambdaRegion = process.env.AWS_REGION;

  if (lambdaFunctionName) {
    return {
      environment: 'lambda',
      isLambda: true,
      isStdio: false,
      region: lambdaRegion,
      functionName: lambdaFunctionName,
    };
  }

  // Check for explicit stdio mode (for testing or edge cases)
  const explicitMode = process.env.VISUS_MCP_MODE;
  if (explicitMode === 'stdio') {
    return {
      environment: 'stdio',
      isLambda: false,
      isStdio: true,
    };
  }

  // Default to stdio mode (MCP server)
  // This is the open-source tier default
  return {
    environment: 'stdio',
    isLambda: false,
    isStdio: true,
  };
}

/**
 * Log runtime configuration to stderr
 * (MCP protocol uses stdout for JSON-RPC, so logs go to stderr)
 *
 * @param config Runtime configuration
 */
export function logRuntimeConfig(config: RuntimeConfig): void {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event: 'runtime_detected',
    environment: config.environment,
    lambda: config.isLambda ? {
      function_name: config.functionName,
      region: config.region,
    } : undefined,
  };

  console.error(JSON.stringify(logEntry));
}

/**
 * Validate runtime environment is appropriate for operation
 *
 * This function logs warnings for unexpected conditions but NEVER throws errors.
 * This ensures the MCP server can start even in non-standard environments
 * (e.g., claude.ai hosted MCP runner) by defaulting to stdio mode.
 *
 * @param config Runtime configuration
 */
export function validateRuntime(config: RuntimeConfig): void {
  // Log warning for unknown environments, but don't crash
  // detectRuntime() should default to 'stdio', so this should rarely happen
  if (config.environment === 'unknown') {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'runtime_validation_warning',
      level: 'warn',
      message: 'Unknown runtime environment detected. Defaulting to stdio mode. Set VISUS_MCP_MODE=stdio explicitly if needed.',
      environment: config.environment
    }));
  }

  // In Lambda, warn if required environment variables are missing
  // But don't crash - let Lambda itself handle the error
  if (config.isLambda) {
    if (!process.env.AWS_REGION) {
      console.error(JSON.stringify({
        timestamp: new Date().toISOString(),
        event: 'runtime_validation_warning',
        level: 'warn',
        message: 'AWS_REGION not set in Lambda environment. This may cause AWS SDK calls to fail.',
        environment: config.environment
      }));
    }
  }
}
