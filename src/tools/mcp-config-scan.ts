/**
 * visus_scan_mcp - MCP Configuration Risk Scanner
 *
 * Scans MCP server parameters for RCE, shell injection, and env abuse risks.
 * Integrates with existing sanitizer for pattern detection.
 */

import { detectAndNeutralize, type DetectionResult } from '../sanitizer/injection-detector.js';
import { INJECTION_PATTERNS } from '../sanitizer/patterns.js';

const RISK_PATTERNS = {
  shell_injection: /sh\s+-c|bash\s+-c|cmd\s+\/c/i,
  env_abuse: /(PATH|LD_PRELOAD|PYTHONPATH)=[^;]*?(rm|del|exec|\/bin\/sh)/i,
  rce_node: /child_process\.spawn\s*\(\s*['&quot;]sh['&quot;]/i,
  rce_python: /subprocess\.Popen\s*\(\s*shell=True|os\.system/i,
  unsafe_flags: /--allow-run|--no-sandbox|--disable-web-security/i,
  sql_injection: /(union\s+select|or\s+1=1|--|\/\*\*)/i, // CVE-2026-42208 SQLi patterns
  high_entropy: 4.5 // Threshold
} as const;

type RiskSeverity = 'low' | 'medium' | 'high' | 'critical';

interface Finding {
  pattern: string;
  location: string;
  snippet: string;
  severity: RiskSeverity;
}

interface ScanResult {
  findings: Finding[];
  score: number;
  safeToSpawn: boolean;
  remediation: string[];
  mcp_risks: string[]; // From sanitizer
  command_risks: CommandRisk[];
}

function scoreEntropy(s: string): number {
  if (!s) return 0;
  const chars = [...s];
  const freq = new Map<string, number>();
  for (const c of chars) {
    freq.set(c, (freq.get(c) || 0) + 1);
  }
  const length = chars.length;
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / length;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

function parseMcpParams(configStr: string): { command?: string; args: string[]; env: Record<string, string> } {
  try {
    const params = JSON.parse(configStr);
    return {
      command: params.command,
      args: params.args || [],
      env: params.env || {}
    };
  } catch {
    throw new Error('Invalid JSON config');
  }
}

function getRelevantSanitizerPatterns(): string[] {
  return INJECTION_PATTERNS.filter(p => 
    p.name.includes('code_execution') || 
    p.name.includes('file_system') || 
    p.name.includes('credential') ||
    p.name === 'sql_injection_vectors' || // CVE-2026-42208
    p.severity === 'critical'
  ).map(p => p.name);
}

function scanString(str: string, location: string): { 
  riskFindings: Finding[]; 
  sanitizerResult: DetectionResult; 
  localScore: number; 
  relevantPatterns: string[]; 
} {
  const riskFindings: Finding[] = [];
  let localScore = 0;

  // RISK_PATTERNS scan
  for (const [name, pat] of Object.entries(RISK_PATTERNS)) {
    if (typeof pat === 'number') continue; // Skip threshold
    if (pat.test(str)) {
      riskFindings.push({ pattern: name, location, snippet: str.slice(0, 100), severity: 'high' as const });
      localScore += name === 'shell_injection' || name === 'rce_node' || name === 'rce_python' ? 5 : 3;
    }
  }

  // Heuristic for length
  if (str.length > 500) localScore += 1;

  // Entropy
  if (scoreEntropy(str) > RISK_PATTERNS.high_entropy) {
    riskFindings.push({ pattern: 'high_entropy_payload', location, snippet: str.slice(0, 100) + '...', severity: 'medium' as const });
    localScore += 3;
  }

  // Sanitizer for relevant patterns
  const sanitizerResult = detectAndNeutralize(str);
  const relevantPatterns = sanitizerResult.patterns_detected.filter(p => getRelevantSanitizerPatterns().includes(p) || p === 'sql_injection_vectors');
  localScore += relevantPatterns.length * 4;

  return { riskFindings, sanitizerResult, localScore, relevantPatterns };
}

function scanMcpConfig(params: ReturnType<typeof parseMcpParams>, whitelist: string[] = []): Omit<ScanResult, 'command_risks'> {
  const findings: Finding[] = [];
  let score = 0;
  const mcpRisks: string[] = [];
  const remediation: string[] = [];

  // Scan command
  if (params.command) {
    const { riskFindings, localScore: cmdScore, relevantPatterns: cmdPatterns } = scanString(params.command, 'command');
    for (const f of riskFindings) {
      if (!whitelist.includes(f.pattern)) {
        findings.push(f);
        if (f.pattern === 'shell_injection') remediation.push('Use array form for commands instead of shell strings');
      }
    }
    score += cmdScore;
    mcpRisks.push(...cmdPatterns);
    if (cmdPatterns.length > 0) {
      remediation.push('Run command through Visus sanitizer before use');
    }
  }

  // Scan args
  const argsStr = params.args.join(' ');
  if (argsStr) {
    const { riskFindings, localScore: argsScore, relevantPatterns: argsPatterns } = scanString(argsStr, 'args');
    for (const f of riskFindings) {
      if (!whitelist.includes(f.pattern)) {
        findings.push(f);
        if (f.pattern === 'unsafe_flags') remediation.push('Remove unsafe browser flags; use secure defaults');
      }
    }
    score += argsScore;
    mcpRisks.push(...argsPatterns);
    if (argsPatterns.length > 0) {
      remediation.push('Sanitize args array elements individually');
    }
  }

  // Scan env
  for (const [key, value] of Object.entries(params.env)) {
    if (typeof value === 'string') {
      const envStr = `${key}=${value}`;
      const { riskFindings, localScore: envScore, relevantPatterns: envPatterns } = scanString(envStr, `env.${key}`);
      for (const f of riskFindings) {
        if (!whitelist.includes(f.pattern)) {
          findings.push(f);
          if (f.pattern === 'env_abuse') remediation.push(`Avoid modifying ${key} with untrusted values; use allowlist`);
        }
      }
      score += envScore;
      mcpRisks.push(...envPatterns);
      if (envPatterns.length > 0) {
        remediation.push(`Redact sensitive data in env.${key}`);
      }
    }
  }

  // Heuristic for shell true
  if (params.args.some((arg: any) => arg === true && params.args[params.args.indexOf(arg)-1] === 'shell') || 
      JSON.stringify(params).includes('"shell":true')) {
    if (!whitelist.includes('shell_true')) {
      findings.push({ pattern: 'shell_true', location: 'params', snippet: 'shell: true detected', severity: 'critical' as const });
      score += 8;
      remediation.push('Explicitly set shell: false to mitigate RCE risks');
    }
  }

  const safeToSpawn = score < 7;

  return { findings, score: Math.round(score), safeToSpawn, remediation, mcp_risks: mcpRisks };
}

import { detectCommandInjection, type CommandRisk } from '../../security/command-guard.js';

export interface ScanResult {
  findings: Finding[];
  score: number;
  safeToSpawn: boolean;
  remediation: string[];
  mcp_risks: string[];
  command_risks: CommandRisk[];
}

export async function visusScanMcp(input: { config: string; options?: { mode?: 'strict' | 'balanced' | 'permissive'; whitelist?: string } }): Promise<ScanResult> {
  const { config, options = {} } = input;
  const whitelist = options.whitelist ? options.whitelist.split(',').map(w => w.trim()).filter(Boolean) : [];
  const params = parseMcpParams(config);
  let result = scanMcpConfig(params, whitelist);

  // Add command injection detection
  const commandRisks = detectCommandInjection(params, { whitelist });
  result.command_risks = commandRisks;
  result.score += commandRisks.reduce((sum, r) => sum + ({critical: 5, high: 3, medium: 2, low: 1}[r.severity] || 0), 0);
  if (commandRisks.length > 0) {
    result.remediation.push('Review and sanitize command parameters for injection risks');
  }

  // Adjust safeToSpawn based on mode
  const thresholds = {
    strict: 4,
    balanced: 7,
    permissive: Infinity
  };
  result.safeToSpawn = result.score < thresholds[options.mode || 'balanced'];

  return result;
}

export const visusScanMcpToolDefinition = {
  name: 'visus_scan_mcp',
  description: 'Scan MCP server configuration parameters for security risks before spawning. Pass config as JSON string: {command?: string, args?: string[], env?: object}. Returns findings, score, and remediation advice.',
  inputSchema: {
    type: 'object',
    properties: {
      config: {
        type: 'string',
        description: 'JSON string of MCP params to scan (e.g., {"command": "node", "args": ["index.js"], "env": {}})'
      },
      options: {
        type: 'object',
        properties: {
          mode: {
            type: 'string',
            enum: ['strict', 'balanced', 'permissive'],
            default: 'balanced',
            description: 'Risk tolerance: strict blocks more aggressively'
          },
          whitelist: {
            type: 'string',
            description: 'Comma-separated patterns to ignore (e.g., "shell_injection,high_entropy_payload")'
          }
        },
        required: []
      }
    },
    required: ['config']
  }
} as const;
