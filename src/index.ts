#!/usr/bin/env node
// @ts-nocheck

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
 * Visus MCP - Tri-Mode Entry Point (Phase 3)
 *
 * 1. stdio MCP server   (default / npx visus-mcp)   -- Claude Desktop
 * 2. AWS Lambda handler (API Gateway)               -- Hosted tier
 * 3. HTTP/Streamable    (--transport http)           -- claude.ai / remote clients
 *
 * KEY DESIGN: createVisusMcpServer() factory produces a fresh Server instance
 * per connection. This is required because the MCP SDK forbids connecting one
 * Server to multiple transports simultaneously.
 *
 * ledger is a module-level singleton shared across all sessions (intentional --
 * cross-session risk tracking is the point of VSIL).
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
import { SessionLedger } from './security/session-ledger.js';
import { visusScanMcp, visusScanMcpToolDefinition } from './tools/mcp-config-scan.js';
import { visusDbVerify, visusDbVerifyToolDefinition } from './tools/db-guard.js';
import { detectAndNeutralize } from './sanitizer/index.js';

// Module-level singleton -- shared across all sessions for cross-session risk tracking
const ledger = new SessionLedger();
console.error('[VISUS-DEBUG] SessionLedger instantiated');

// ---------------------------------------------------------------------------
// HITL helper -- takes srv as parameter so it works with any Server instance
// ---------------------------------------------------------------------------

async function handleCriticalThreatElicitation(
  srv,
  output,
  url,
  wormRisk = 0
) {
  const threatReport = output.threat_report;
  const wormScore = output.sanitization?.worm_risk_score ?? 0;

  if (shouldElicit(threatReport, Math.max(wormRisk, wormScore))) {
    const message = buildElicitMessage(
      threatReport || { total_findings: 0, findings_toon: '', overall_severity: 'CRITICAL' },
      url,
      Math.max(wormRisk, wormScore)
    );
    const { proceed, includeReport } = await runElicitation(srv, message);

    if (!proceed) {
      return {
        output: { url, blocked: true, reason: 'User declined after threat/worm detected', threat_report: threatReport },
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

// ---------------------------------------------------------------------------
// Tool definition sanitizer
// ---------------------------------------------------------------------------

function sanitizeToolDefinition(tool) {
  let sanitized = { ...tool };

  if (sanitized.description) {
    const result = detectAndNeutralize(sanitized.description);
    if (result.content_modified) {
      console.error('[SECURITY] Tool ' + sanitized.name + ' description sanitized');
    }
    sanitized = { ...sanitized, description: result.content };
  }

  if (sanitized.inputSchema) {
    try {
      const schemaStr = JSON.stringify(sanitized.inputSchema);
      const schemaResult = detectAndNeutralize(schemaStr);
      if (schemaResult.content_modified) {
        console.error('[SECURITY] Tool ' + sanitized.name + ' schema sanitized');
        sanitized = { ...sanitized, inputSchema: JSON.parse(schemaResult.content) };
      }
    } catch (e) {
      console.error('[SECURITY] Failed to sanitize schema for ' + sanitized.name + ':', e);
    }
  }

  return sanitized;
}

// ---------------------------------------------------------------------------
// SERVER FACTORY -- call this once per connection, never share across connections
// ---------------------------------------------------------------------------

function createVisusMcpServer() {
  console.error('[VISUS-DEBUG] Creating server instance...');

  const srv = new Server(
    { name: 'visus-mcp', version: '0.29.0' },
    { capabilities: { tools: {} } }
  );

  // Tool list handler
  srv.setRequestHandler(ListToolsRequestSchema, async () => {
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
      visusScanMcpToolDefinition,
      visusDbVerifyToolDefinition
    ];
    return { tools: rawTools.map(sanitizeToolDefinition) };
  });

  // Tool call handler
  srv.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const sessionId = request.sessionId || 'default';

    try {
      switch (name) {
        case 'visus_db_verify': {
          return await visusDbVerify(args);
        }

        case 'visus_fetch': {
          const result = await visusFetch(args);
          if (!result.ok) throw new McpError(ErrorCode.InternalError, 'visus_fetch failed: ' + result.error.message);

          const { score, newThreats, chainId, dangling } = await ledger.checkContextualIntegrity(sessionId, name, args, result.value);
          if (score > 0.7) {
            const threatReport = result.value.threat_report;
            const { proceed, includeReport } = await runElicitation(srv, 'High session risk detected from prior turns (chains/priming). Proceed with caution?');
            if (!proceed) return { content: [{ type: 'text', text: JSON.stringify({ blocked: true, session_risk: score, reason: 'User declined high-risk session' }, null, 2) }] };
            if (threatReport) threatReport.new_threats = [...(threatReport.new_threats || []), ...newThreats];
          }

          const hashes = ledger.extractEntityHashes ? await ledger.extractEntityHashes(args, result.value) : [];
          ledger.update(sessionId, hashes, name, newThreats);

          const extended = { ...result.value };
          if (extended.threat_summary) {
            extended.threat_summary.session_risk = score;
            extended.threat_summary.chain_detected = !!chainId;
            extended.threat_summary.priming_flags = dangling ? ['dangling_instruction'] : [];
          }

          const { output } = await handleCriticalThreatElicitation(srv, extended, args.url);
          return { content: [{ type: 'text', text: JSON.stringify(output, null, 2) }] };
        }

        case 'visus_fetch_structured': {
          const result = await visusFetchStructured(args);
          if (!result.ok) throw new McpError(ErrorCode.InternalError, 'visus_fetch_structured failed: ' + result.error.message);

          const { score, newThreats, chainId } = await ledger.checkContextualIntegrity(sessionId, name, args, result.value);
          if (score > 0.7) {
            const threatReport = result.value.threat_report;
            const { proceed } = await runElicitation(srv, 'High session risk detected. Proceed with structured extraction?');
            if (!proceed) return { content: [{ type: 'text', text: JSON.stringify({ blocked: true, session_risk: score }, null, 2) }] };
            if (threatReport) threatReport.new_threats = [...(threatReport.new_threats || []), ...newThreats];
          }

          const hashes = ledger.extractEntityHashes ? await ledger.extractEntityHashes(args, result.value) : [];
          ledger.update(sessionId, hashes, name, newThreats);

          const extended = { ...result.value };
          if (extended.threat_summary) {
            extended.threat_summary.session_risk = score;
            extended.threat_summary.chain_detected = !!chainId;
          }

          const { output } = await handleCriticalThreatElicitation(srv, extended, args.url);
          return { content: [{ type: 'text', text: JSON.stringify(output, null, 2) }] };
        }

        case 'visus_read': {
          const result = await visusRead(args);
          if (!result.ok) throw new McpError(ErrorCode.InternalError, 'visus_read failed: ' + result.error.message);

          const { score } = await ledger.checkContextualIntegrity(sessionId, name, args, result.value);
          if (score > 0.7) {
            ledger.update(sessionId, [], name, []);
            console.error('[VSIL] High session risk for read: ' + score);
          }

          const { output } = await handleCriticalThreatElicitation(srv, result.value, args.url);
          return { content: [{ type: 'text', text: JSON.stringify(output, null, 2) }] };
        }

        case 'visus_search': {
          const result = await visusSearch(args);
          if (!result.ok) throw new McpError(ErrorCode.InternalError, 'visus_search failed: ' + result.error.message);

          const { score } = await ledger.checkContextualIntegrity(sessionId, name, args, result.value);
          if (score > 0.7) ledger.update(sessionId, [], name, []);

          const { output } = await handleCriticalThreatElicitation(srv, result.value, 'search: ' + args.query);
          return { content: [{ type: 'text', text: JSON.stringify(output, null, 2) }] };
        }

        case 'visus_report': {
          const result = await visusReport(args);
          if (!result.ok) throw new McpError(ErrorCode.InternalError, 'visus_report failed: ' + result.error.message);
          return { content: [{ type: 'text', text: JSON.stringify(result.value, null, 2) }] };
        }

        case 'visus_verify': {
          const result = await visusVerify(args);
          if (!result.ok) throw new McpError(ErrorCode.InternalError, 'visus_verify failed: ' + result.error.message);
          return { content: [{ type: 'text', text: JSON.stringify(result.value, null, 2) }] };
        }

        case 'visus_read_csv': {
          const result = await visusReadCsv(args);
          if (!result.ok) throw new McpError(ErrorCode.InternalError, 'visus_read_csv failed: ' + result.error.message);
          return { content: [{ type: 'text', text: JSON.stringify(result.value, null, 2) }] };
        }

        case 'visus_read_excel': {
          const result = await visusReadExcel(args);
          if (!result.ok) throw new McpError(ErrorCode.InternalError, 'visus_read_excel failed: ' + result.error.message);
          return { content: [{ type: 'text', text: JSON.stringify(result.value, null, 2) }] };
        }

        case 'visus_read_gsheet': {
          const result = await visusReadGsheet(args);
          if (!result.ok) throw new McpError(ErrorCode.InternalError, 'visus_read_gsheet failed: ' + result.error.message);
          return { content: [{ type: 'text', text: JSON.stringify(result.value, null, 2) }] };
        }

        case 'visus_context_scan': {
          args.sessionId = sessionId;
          const result = await visusContextScan(args);
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }

        case 'visus_get_ledger_proof': {
          const result = await visusGetLedgerProof(request.params.arguments.request_id);
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }

        case 'visus_scan_mcp': {
          const result = await visusScanMcp(args);
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }

        default:
          throw new McpError(ErrorCode.MethodNotFound, 'Unknown tool: ' + name);
      }
    } catch (error) {
      if (error instanceof McpError) throw error;
      throw new McpError(ErrorCode.InternalError, 'Tool execution failed: ' + (error instanceof Error ? error.message : String(error)));
    }
  });

  return srv;
}

// ---------------------------------------------------------------------------
// Mode 1: stdio -- Claude Desktop (unchanged behaviour)
// ---------------------------------------------------------------------------

async function startMcpServer() {
  console.error('[VISUS-DEBUG] startMcpServer() entered');

  const srv = createVisusMcpServer();
  const transport = new StdioServerTransport();

  console.error('[VISUS-DEBUG] Connecting stdio transport...');
  await srv.connect(transport);
  console.error('[VISUS-DEBUG] Transport connected');

  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: 'mcp_server_started',
    name: 'visus-mcp',
    version: '0.29.0',
    transport: 'stdio'
  }));

  process.on('SIGINT', async () => {
    console.error(JSON.stringify({ timestamp: new Date().toISOString(), event: 'shutdown', transport: 'stdio' }));
    await closeBrowser();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.error(JSON.stringify({ timestamp: new Date().toISOString(), event: 'shutdown', transport: 'stdio' }));
    await closeBrowser();
    process.exit(0);
  });

  console.error('[VISUS-DEBUG] Awaiting messages...');
  await new Promise(() => {});
}

// ---------------------------------------------------------------------------
// Mode 3: Streamable HTTP -- claude.ai and remote MCP clients
//
// Each POST /mcp that initialises a new session gets a FRESH Server instance
// from createVisusMcpServer(). This is the fix for the "Already connected to
// a transport" crash that occurs when claude.ai opens two connections.
// ---------------------------------------------------------------------------

async function startHttpServer() {
  const { default: express } = await import('express');
  const { default: cors } = await import('cors');
  const { randomUUID } = await import('crypto');
  const { StreamableHTTPServerTransport } = await import('@modelcontextprotocol/sdk/server/streamableHttp.js');

  const PORT = parseInt(process.env.PORT ?? '3100', 10);
  const HOST = process.env.HOST ?? '127.0.0.1';

  const app = express();

  app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'mcp-session-id'],
    exposedHeaders: ['mcp-session-id'],
  }));

  app.use(express.json({ limit: '4mb' }));

  // sessions: sessionId -> { transport, server }
  const sessions = new Map();

  app.get('/health', (_req, res) => {
    res.json({
      status: 'healthy',
      service: 'visus-mcp',
      version: '0.29.0',
      transport: 'streamable-http',
      sessions: sessions.size,
      uptime: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
    });
  });

  // POST /mcp -- init new session or route to existing one
  app.post('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'];

    if (sessionId && sessions.has(sessionId)) {
      const { transport } = sessions.get(sessionId);
      await transport.handleRequest(req, res, req.body);
      return;
    }

    // New session: fresh Server + fresh Transport
    const srv = createVisusMcpServer();

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sid) => {
        sessions.set(sid, { transport, server: srv });
        console.error(JSON.stringify({
          timestamp: new Date().toISOString(),
          event: 'session_started',
          session_id: sid,
          active_sessions: sessions.size,
        }));
      },
    });

    transport.onclose = () => {
      const sid = transport.sessionId;
      if (sid) {
        sessions.delete(sid);
        console.error(JSON.stringify({
          timestamp: new Date().toISOString(),
          event: 'session_closed',
          session_id: sid,
          active_sessions: sessions.size,
        }));
      }
    };

    await srv.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  // GET /mcp -- SSE stream
  app.get('/mcp', async (req, res) => {
    const sessionId = req.headers['mcp-session-id'];
    const session = sessionId ? sessions.get(sessionId) : undefined;

    if (!session) {
      res.status(404).json({ error: 'Session not found. POST /mcp first.' });
      return;
    }

    await session.transport.handleRequest(req, res);
  });

  // DELETE /mcp -- session teardown
  app.delete('/mcp', (req, res) => {
    const sessionId = req.headers['mcp-session-id'];
    if (sessionId) {
      sessions.delete(sessionId);
      console.error(JSON.stringify({ timestamp: new Date().toISOString(), event: 'session_deleted', session_id: sessionId }));
    }
    res.status(200).end();
  });

  app.listen(PORT, HOST, () => {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'mcp_server_started',
      name: 'visus-mcp',
      version: '0.29.0',
      transport: 'streamable-http',
      endpoint: 'http://' + HOST + ':' + PORT + '/mcp',
    }));
    console.error('=== visus-mcp Streamable HTTP v0.29.0 ===');
    console.error('  Endpoint : http://' + HOST + ':' + PORT + '/mcp');
    console.error('  Health   : http://' + HOST + ':' + PORT + '/health');
    console.error('  Add to claude.ai -> Connectors: https://<tunnel>/mcp');
    console.error('==========================================');
  });

  process.on('SIGINT', async () => {
    await closeBrowser();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await closeBrowser();
    process.exit(0);
  });

  await new Promise(() => {});
}

// ---------------------------------------------------------------------------
// Main -- tri-mode router
// Priority: --transport http > Lambda env > stdio (default)
// ---------------------------------------------------------------------------

async function main() {
  console.error('[VISUS-DEBUG] main() entered');

  const argv = process.argv.slice(2);
  const tIdx = argv.findIndex(a => a === '--transport');
  const tMode = tIdx !== -1 ? argv[tIdx + 1]?.toLowerCase() : null;

  if (tMode === 'http' || tMode === 'sse') {
    const pIdx = argv.findIndex(a => a === '--port');
    if (pIdx !== -1 && argv[pIdx + 1]) process.env.PORT = argv[pIdx + 1];
    const hIdx = argv.findIndex(a => a === '--host');
    if (hIdx !== -1 && argv[hIdx + 1]) process.env.HOST = argv[hIdx + 1];

    console.error('[VISUS-DEBUG] HTTP mode, calling startHttpServer()');
    await startHttpServer();
    return;
  }

  const runtime = detectRuntime();
  logRuntimeConfig(runtime);
  validateRuntime(runtime);

  if (runtime.isStdio) {
    console.error('[VISUS-DEBUG] stdio mode, calling startMcpServer()');
    await startMcpServer();
  } else if (runtime.isLambda) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'lambda_mode_detected',
      message: 'Lambda handler will be invoked by AWS runtime'
    }));
  }
}

if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  console.error('[VISUS-DEBUG] Not in Lambda, calling main()');
  main().catch((error) => {
    console.error('[VISUS-DEBUG] main() threw:', error);
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'startup_error',
      error: error instanceof Error ? error.message : String(error)
    }));
    process.exit(1);
  });
} else {
  console.error('[VISUS-DEBUG] Lambda detected, skipping main()');
}

// @ts-nocheck
