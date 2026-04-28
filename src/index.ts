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
import { visusContextScan, visusContextScanToolDefinition } from './tools/context-scan.js';
import { visusGetLedgerProof, visusGetLedgerProofToolDefinition } from './tools/ledger-proof.js';
import { closeBrowser } from './browser/playwright-renderer.js';
import { detectRuntime, logRuntimeConfig, validateRuntime } from './runtime.js';
import { shouldElicit, buildElicitMessage } from './sanitizer/hitl-gate.js';
import { runElicitation } from './sanitizer/elicit-runner.js';
import type { ThreatReport } from './sanitizer/threat-reporter.js';
import { SessionLedger, type SessionRiskSummary } from './security/session-ledger.js';
import { visusScanMcp, visusScanMcpToolDefinition } from './tools/mcp-config-scan.js';

/**
 * Create and configure the MCP server
 */
console.error('[VISUS-DEBUG] Creating server...');
const server = new Server(
  {
    name: 'visus-mcp',
      version: '0.17.0'
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
import { detectAndNeutralize } from './sanitizer/index.js';

function sanitizeToolDefinition(tool: any): any {
  let sanitized = { ...tool };
  
  // Sanitize description
  if (sanitized.description) {
    const result = detectAndNeutralize(sanitized.description);
    if (result.content_modified) {
      console.error(`[SECURITY] Tool ${sanitized.name} description sanitized`);
    }
    sanitized = { ...sanitized, description: result.content };
  }
  
  // Sanitize inputSchema by stringifying and re-parsing (basic, no deep recurse for MVP)
  if (sanitized.inputSchema) {
    try {
      const schemaStr = JSON.stringify(sanitized.inputSchema);
      const schemaResult = detectAndNeutralize(schemaStr);
      if (schemaResult.content_modified) {
        console.error(`[SECURITY] Tool ${sanitized.name} schema sanitized`);
        sanitized = { ...sanitized, inputSchema: JSON.parse(schemaResult.content) };
      }
    } catch (e) {
      console.error(`[SECURITY] Failed to sanitize schema for ${sanitized.name}:`, e);
    }
  }
  
  return sanitized;
}

server.setRequestHandler(ListToolsRequestSchema, async () => {
  const rawTools = [
    visusFetchToolDefinition,
    visusFetchStructuredToolDefinition,
    visusReadToolDefinition,
    visusSearchToolDefinition,
    visusReportToolDefinition,
    visusVerifyToolDefinition,
    visusReadCsvToolDefinition,
    visusReadExcelToolDefinition,
    visusReadGsheetToolDefinition,
    visusContextScanToolDefinition,
    visusGetLedgerProofToolDefinition,
    visusScanMcpToolDefinition
  ];
  
  const sanitizedTools = rawTools.map(sanitizeToolDefinition);
  
  return {
    tools: sanitizedTools
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const sessionId = request.sessionId || 'default';
  try {
    switch (name) {
      // ... existing cases, add:
      case 'visus_db_verify': {
        return await visusDbVerify(args);
      }

      case 'visus_fetch': {
        const result = await visusFetch(args as any);

        if (!result.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `visus_fetch failed: ${result.error.message}`
          );
        }

        // VSIL Check
        const { score, newThreats, chainId, dangling } = await ledger.checkContextualIntegrity(sessionId, name, args, result.value);
        if (score > 0.7) {
          const threatReport = result.value.threat_report;
          const message = 'High session risk detected from prior turns (chains/priming). Proceed with caution?';
          const { proceed, includeReport } = await runElicitation(server, message);

          if (!proceed) {
            return {
              content: [{ type: 'text', text: JSON.stringify({ blocked: true, session_risk: score, reason: 'User declined high-risk session' }, null, 2) }]
            };
          }

          // Merge new threats
          if (threatReport) threatReport.new_threats = [...(threatReport.new_threats || []), ...newThreats];
        }

        // Update ledger
        const hashes = ledger.extractEntityHashes ? await ledger.extractEntityHashes(args, result.value) : [];
        ledger.update(sessionId, hashes, name, newThreats);

        // Extend output
        const extended = { ...result.value };
        if (extended.threat_summary) {
          extended.threat_summary.session_risk = score;
          extended.threat_summary.chain_detected = !!chainId;
          extended.threat_summary.priming_flags = dangling ? ['dangling_instruction'] : [];
        }

        // Existing HITL
        const { output } = await handleCriticalThreatElicitation(extended, (args as any).url);
        return { content: [{ type: 'text', text: JSON.stringify(output, null, 2) }] };
      }

      case 'visus_fetch_structured': {
        const result = await visusFetchStructured(args as any);

        if (!result.ok) {
          throw new McpError(
            ErrorCode.InternalError,
            `visus_fetch_structured failed: ${result.error.message}`
          );
        }

        // VSIL Check (similar)
        const { score, newThreats, chainId, dangling } = await ledger.checkContextualIntegrity(sessionId, name, args, result.value);
        if (score > 0.7) {
          const threatReport = result.value.threat_report;
          const message = 'High session risk detected. Proceed with structured extraction?';
          const { proceed } = await runElicitation(server, message);

          if (!proceed) {
            return {
              content: [{ type: 'text', text: JSON.stringify({ blocked: true, session_risk: score }, null, 2) }]
            };
          }

          if (threatReport) threatReport.new_threats = [...(threatReport.new_threats || []), ...newThreats];
        }

        // Update ledger
        const hashes = ledger.extractEntityHashes ? await ledger.extractEntityHashes(args, result.value) : [];
        ledger.update(sessionId, hashes, name, newThreats);

        // Extend output
        const extended = { ...result.value };
        if (extended.threat_summary) {
          extended.threat_summary.session_risk = score;
          extended.threat_summary.chain_detected = !!chainId;
        }

        // HITL for threats
        const { output } = await handleCriticalThreatElicitation(extended, (args as any).url);
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

        // VSIL for read (session continuity)
        const { score } = await ledger.checkContextualIntegrity(sessionId, name, args, result.value);
        if (score > 0.7) {
          ledger.update(sessionId, [], name, []); // Log but no block for read-only
          console.error(`High session risk for read: ${score}`); // Log only
        }

        // HITL for threats
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

        // VSIL for search (priming URLs)
        const { score } = await ledger.checkContextualIntegrity(sessionId, name, args, result.value);
        if (score > 0.7) {
          ledger.update(sessionId, [], name, []); // Log
        }

        // HITL for search results threats
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

        // No VSIL/HITL for reports
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

        // No VSIL/HITL for verify
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

      case 'visus_context_scan': {
        args.sessionId = sessionId;
        const result = await visusContextScan(args);
        return {
          content: [
            { type: 'text', text: JSON.stringify(result, null, 2) }
          ]
        };
      }

      case 'visus_get_ledger_proof': {
        const { arguments: args } = request.params;
        const result = await visusGetLedgerProof(args.request_id);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2)
            }
          ]
        };
      }

      case 'visus_scan_mcp': {
        const result = await visusScanMcp(args as any);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2)
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
 * Helper function to handle HITL elicitation for CRITICAL threats
 *
 * Returns modified output with threat_report removed if user declined,
 * or blocked response if user declined to proceed.
 */
async function handleCriticalThreatElicitation(
  output: any,
  url: string,
  wormRisk: number = 0
): Promise<{ output: any; blocked: boolean }> {
  const threatReport = output.threat_report as ThreatReport | undefined;
  const wormScore = (output.sanitization as any)?.worm_risk_score ?? 0;

  if (shouldElicit(threatReport, Math.max(wormRisk, wormScore))) {
    const message = buildElicitMessage(threatReport || { total_findings: 0, findings_toon: '', overall_severity: 'CRITICAL' } as any, url, Math.max(wormRisk, wormScore));
    const { proceed, includeReport } = await runElicitation(server, message);

    if (!proceed) {
      return {
        output: {
          url,
          blocked: true,
          reason: 'User declined after threat/worm detected',
          threat_report: threatReport
        },
        blocked: true
      };
    }

    if (!includeReport && output.threat_report) {
      const { threat_report, ...clean } = output;
      return { output: clean, blocked: false };
    }
  }

  return { output, blocked: false };
}

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
    tools: ['visus_fetch', 'visus_fetch_structured', 'visus_read', 'visus_search', 'visus_context_scan']
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
