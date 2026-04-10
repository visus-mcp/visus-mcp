#!/usr/bin/env node

// VISUS-DEBUG: Global error handlers MUST come first
process.on('uncaughtException', (err) => {
  console.error('[VISUS-DEBUG] uncaughtException:', err.message, err.stack);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('[VISUS-DEBUG] unhandledRejection:', reason);
  process.exit(1);
});
console.error('[VISUS-DEBUG] Module loaded');

/**
 * Visus MCP - Dual-Mode Entry Point (Phase 2)
 *
 * Supports two runtime modes:
 * 1. stdio MCP server (npx visus-mcp) - Open source tier
 * 2. AWS Lambda handler (API Gateway) - Hosted tier
 *
 * Runtime detection determines which mode to use based on environment variables.
 *
 * Tools:
 * - visus_fetch: Fetch and sanitize web page content
 * - visus_fetch_structured: Extract structured data from web pages
 *
 * ALL content passes through the Lateos injection sanitizer before reaching the LLM.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError
} from '@modelcontextprotocol/sdk/types.js';

import { visusFetch, visusFetchToolDefinition } from './tools/fetch.js';
import { visusFetchStructured, visusFetchStructuredToolDefinition } from './tools/fetch-structured.js';
import { visusRead, visusReadToolDefinition } from './tools/read.js';
import { visusSearch, visusSearchToolDefinition } from './tools/search.js';
import { visusReport, visusReportToolDefinition } from './tools/report.js';
import { visusVerify, visusVerifyToolDefinition } from './tools/verify.js';
import { visusReadCsv, visusReadCsvToolDefinition } from './tools/visus_read_csv.js';
import { visusReadExcel, visusReadExcelToolDefinition } from './tools/visus_read_excel.js';
import { visusReadGsheet, visusReadGsheetToolDefinition } from './tools/visus_read_gsheet.js';
import { closeBrowser } from './browser/playwright-renderer.js';
import { detectRuntime, logRuntimeConfig, validateRuntime } from './runtime.js';
import { shouldElicit } from './sanitizer/hitl-gate.js';
import { runElicitation } from './sanitizer/elicit-runner.js';
import type { ThreatReport } from './sanitizer/threat-reporter.js';

/**
 * Create and configure the MCP server
 */
console.error('[VISUS-DEBUG] Creating server...');
const server = new Server(
  {
    name: 'visus-mcp',
    version: '0.14.0'
  },
  {
    capabilities: {
      tools: {}
    }
  }
);
console.error('[VISUS-DEBUG] Server created');

/**
 * Handle tool list requests
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      visusFetchToolDefinition,
      visusFetchStructuredToolDefinition,
      visusReadToolDefinition,
      visusSearchToolDefinition,
      visusReportToolDefinition,
      visusVerifyToolDefinition,
      visusReadCsvToolDefinition,
      visusReadExcelToolDefinition,
      visusReadGsheetToolDefinition
    ]
  };
});

/**
 * Helper function to handle HITL elicitation for CRITICAL threats
 *
 * Returns modified output with threat_report removed if user declined,
 * or blocked response if user declined to proceed.
 */
async function handleCriticalThreatElicitation(
  output: any,
  url: string
): Promise<{ output: any; blocked: boolean }> {
  const threatReport = output.threat_report as ThreatReport | undefined;

  // Check if elicitation is needed
  if (shouldElicit(threatReport ?? null)) {
    const { proceed, includeReport } = await runElicitation(
      server,
      threatReport!,
      url
    );

    if (!proceed) {
      // User declined — return blocked response with threat report
      return {
        output: {
          url,
          blocked: true,
          reason: 'User declined to proceed after CRITICAL threat detected',
          threat_report: threatReport
        },
        blocked: true
      };
    }

    // User accepted — proceed with sanitized content
    // Remove threat_report if user didn't request it
    if (!includeReport && output.threat_report) {
      const { threat_report, ...outputWithoutReport } = output;
      return { output: outputWithoutReport, blocked: false };
    }
  }

  return { output, blocked: false };
}

/**
 * Handle tool execution requests
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'visus_fetch': {
        const result = await visusFetch(args as any);

        if (!result.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `visus_fetch failed: ${result.error.message}`
          );
        }

        // Handle HITL elicitation for CRITICAL threats
        const { output } = await handleCriticalThreatElicitation(
          result.value,
          (args as any).url
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(output, null, 2)
            }
          ]
        };
      }

      case 'visus_fetch_structured': {
        const result = await visusFetchStructured(args as any);

        if (!result.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `visus_fetch_structured failed: ${result.error.message}`
          );
        }

        // Handle HITL elicitation for CRITICAL threats
        const { output } = await handleCriticalThreatElicitation(
          result.value,
          (args as any).url
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(output, null, 2)
            }
          ]
        };
      }

      case 'visus_read': {
        const result = await visusRead(args as any);

        if (!result.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `visus_read failed: ${result.error.message}`
          );
        }

        // Handle HITL elicitation for CRITICAL threats
        const { output } = await handleCriticalThreatElicitation(
          result.value,
          (args as any).url
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(output, null, 2)
            }
          ]
        };
      }

      case 'visus_search': {
        const result = await visusSearch(args as any);

        if (!result.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `visus_search failed: ${result.error.message}`
          );
        }

        // Handle HITL elicitation for CRITICAL threats
        // For search, use the query as the "URL" in the elicitation message
        const { output } = await handleCriticalThreatElicitation(
          result.value,
          `search: ${(args as any).query}`
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(output, null, 2)
            }
          ]
        };
      }

      case 'visus_report': {
        const result = await visusReport(args as any);

        if (!result.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `visus_report failed: ${result.error.message}`
          );
        }

        // No HITL for reports - they are read-only compliance exports
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.value, null, 2)
            }
          ]
        };
      }

      case 'visus_verify': {
        const result = await visusVerify(args as any);

        if (!result.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `visus_verify failed: ${result.error.message}`
          );
        }

        // No HITL for verification - it's a read-only audit operation
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.value, null, 2)
            }
          ]
        };
      }

      case 'visus_read_csv': {
        const result = await visusReadCsv(args as any);

        if (!result.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `visus_read_csv failed: ${result.error.message}`
          );
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.value, null, 2)
            }
          ]
        };
      }

      case 'visus_read_excel': {
        const result = await visusReadExcel(args as any);

        if (!result.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `visus_read_excel failed: ${result.error.message}`
          );
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.value, null, 2)
            }
          ]
        };
      }

      case 'visus_read_gsheet': {
        const result = await visusReadGsheet(args as any);

        if (!result.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `visus_read_gsheet failed: ${result.error.message}`
          );
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.value, null, 2)
            }
          ]
        };
      }

      default:
        throw new McpError(
          ErrorCode.MethodNotFound,
          `Unknown tool: ${name}`
        );
    }
  } catch (error) {
    if (error instanceof McpError) {
      throw error;
    }

    throw new McpError(
      ErrorCode.InternalError,
      `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
});

/**
 * Start the MCP server (stdio mode)
 */
async function startMcpServer() {
  console.error('[VISUS-DEBUG] startMcpServer() entered');

  const transport = new StdioServerTransport();

  // Connect server to transport
  console.error('[VISUS-DEBUG] Connecting transport...');
  await server.connect(transport);
  console.error('[VISUS-DEBUG] Transport connected');

  // Log startup to stderr (not stdout - MCP uses stdout)
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: 'mcp_server_started',
    name: 'visus-mcp',
    version: '0.14.0',
    tools: ['visus_fetch', 'visus_fetch_structured', 'visus_read', 'visus_search']
  }));

  // Graceful shutdown
  process.on('SIGINT', async () => {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'mcp_server_shutdown'
    }));

    await closeBrowser();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'mcp_server_shutdown'
    }));

    await closeBrowser();
    process.exit(0);
  });

  console.error('[VISUS-DEBUG] About to await infinite promise to keep server alive');
  // Keep the server running indefinitely
  // The MCP server is event-driven and will respond to stdin messages
  // This infinite promise prevents the function from returning and keeps the process alive
  await new Promise(() => {});
}

/**
 * Main entry point - Dual-mode detection
 */
async function main() {
  console.error('[VISUS-DEBUG] main() entered');

  // Detect runtime environment
  const runtime = detectRuntime();
  logRuntimeConfig(runtime);
  validateRuntime(runtime);

  // Route to appropriate entry point
  if (runtime.isStdio) {
    console.error('[VISUS-DEBUG] stdio mode detected, calling startMcpServer()');
    // Open-source tier: stdio MCP server
    await startMcpServer();
    console.error('[VISUS-DEBUG] startMcpServer() returned (should never happen)');
  } else if (runtime.isLambda) {
    // Hosted tier: Lambda handler
    // In Lambda mode, the handler is exported and invoked by AWS
    // This code path is not executed; see lambda-handler.ts export below
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'lambda_mode_detected',
      message: 'Lambda handler will be invoked by AWS runtime'
    }));
  }
}

// Run stdio MCP server when executed directly (not in Lambda)
// Note: Lambda deployments import from ./lambda-handler.ts directly (see infrastructure/stack.ts)
if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  console.error('[VISUS-DEBUG] Not in Lambda, calling main()');
  main().catch((error) => {
    console.error('[VISUS-DEBUG] main() threw error:', error);
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'startup_error',
      error: error instanceof Error ? error.message : String(error)
    }));
    process.exit(1);
  });
} else {
  console.error('[VISUS-DEBUG] AWS_LAMBDA_FUNCTION_NAME detected, skipping main()');
}
