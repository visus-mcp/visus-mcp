#!/usr/bin/env node

/**
 * Visus MCP Server Entry Point
 *
 * Registers and serves the two Visus tools via the Model Context Protocol (MCP).
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
import { closeBrowser } from './browser/playwright-renderer.js';

/**
 * Create and configure the MCP server
 */
const server = new Server(
  {
    name: 'visus-mcp',
    version: '0.1.0'
  },
  {
    capabilities: {
      tools: {}
    }
  }
);

/**
 * Handle tool list requests
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      visusFetchToolDefinition,
      visusFetchStructuredToolDefinition
    ]
  };
});

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

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.value, null, 2)
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
 * Start the server
 */
async function main() {
  const transport = new StdioServerTransport();

  // Connect server to transport
  await server.connect(transport);

  // Log startup to stderr (not stdout - MCP uses stdout)
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: 'server_started',
    name: 'visus-mcp',
    version: '0.1.0',
    tools: ['visus_fetch', 'visus_fetch_structured']
  }));

  // Graceful shutdown
  process.on('SIGINT', async () => {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'server_shutdown'
    }));

    await closeBrowser();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'server_shutdown'
    }));

    await closeBrowser();
    process.exit(0);
  });
}

// Run server
main().catch((error) => {
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: 'server_error',
    error: error instanceof Error ? error.message : String(error)
  }));
  process.exit(1);
});
