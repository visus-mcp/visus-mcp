/**
 * Command Guard - Detects command injection risks in MCP parameters
 *
 * Integrates with sanitizer patterns for unified detection.
 */

import { INJECTION_PATTERNS } from '../sanitizer/patterns.js';

const HIGH_ENTROPY_THRESHOLD = 4.5;

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

function mapSeverity(sev: 'low' | 'medium' | 'high' | 'critical'): CommandRisk['severity'] {
  return sev as CommandRisk['severity'];
}

export interface CommandRisk {
  pattern: string;
  location: string;
  snippet: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface DetectionResult {
  risks: CommandRisk[];
  totalScore: number;
  entropyScore: number;
}

export function detectCommandInjection(params: Record<string, any>, options: { whitelist?: string[] } = {}): DetectionResult {
  const { whitelist = [] } = options;
  const risks: CommandRisk[] = [];
  let totalScore = 0;
  let entropyScore = 0;

  const commandPatterns = INJECTION_PATTERNS.filter(p =>
    p.name.startsWith('shell_') ||
    p.name.startsWith('bash_') ||
    p.name.startsWith('cmd_') ||
    p.name.startsWith('tool_') ||
    p.name.includes('rce') ||
    p.name.includes('rug_pull') ||
    p.name.includes('schema_') ||
    p.name === 'powershell_injection'
  );

  const severityWeights: Record<CommandRisk['severity'], number> = {
    low: 1,
    medium: 3,
    high: 5,
    critical: 8
  };

  let allText = '';
  if (params.command && typeof params.command === 'string') allText += params.command;
  if (params.args && Array.isArray(params.args)) {
    params.args.forEach((arg: any) => { if (typeof arg === 'string') allText += arg; });
  }
  if (params.env) {
    Object.values(params.env).forEach((val: any) => { if (typeof val === 'string') allText += val; });
  }
  entropyScore = scoreEntropy(allText);

  if (entropyScore > HIGH_ENTROPY_THRESHOLD) {
    const entropyRisk: CommandRisk = {
      pattern: 'high_entropy_payload',
      location: 'aggregate',
      snippet: allText.substring(0, 50) + '...',
      severity: 'medium'
    };
    risks.push(entropyRisk);
    totalScore += severityWeights['medium'] + (entropyScore - HIGH_ENTROPY_THRESHOLD) * 2;
  }

  if (params.command && typeof params.command === 'string') {
    const cmd = params.command;
    const cmdEntropy = scoreEntropy(cmd);

    for (const pat of commandPatterns) {
      if (pat.regex.test(cmd) && !whitelist.includes(pat.name)) {
        const risk: CommandRisk = {
          pattern: pat.name,
          location: 'command',
          snippet: cmd.substring(0, 100) + (cmd.length > 100 ? '...' : ''),
          severity: mapSeverity(pat.severity)
        };
        risks.push(risk);
        totalScore += severityWeights[risk.severity] * (cmdEntropy > 3 ? 1.5 : 1);
      }
    }
  }

  if (params.args && Array.isArray(params.args)) {
    params.args.forEach((arg: any, index: number) => {
      if (typeof arg === 'string') {
        const argEntropy = scoreEntropy(arg);

        for (const pat of commandPatterns) {
          if (pat.regex.test(arg) && !whitelist.includes(pat.name)) {
            const risk: CommandRisk = {
              pattern: pat.name,
              location: `args[${index}]`,
              snippet: arg.substring(0, 100) + (arg.length > 100 ? '...' : ''),
              severity: mapSeverity(pat.severity)
            };
            risks.push(risk);
            totalScore += severityWeights[risk.severity] * (argEntropy > 3 ? 1.5 : 1);
          }
        }
      }
    });
  }

  if (params.env && typeof params.env === 'object') {
    Object.entries(params.env).forEach(([key, val]) => {
      if (typeof val === 'string') {
        const envStr = `${key}=${val}`;
        const envEntropy = scoreEntropy(envStr);

        for (const pat of commandPatterns) {
          if (pat.regex.test(envStr) && !whitelist.includes(pat.name)) {
            const risk: CommandRisk = {
              pattern: pat.name,
              location: `env.${key}`,
              snippet: envStr.substring(0, 100) + (envStr.length > 100 ? '...' : ''),
              severity: mapSeverity(pat.severity)
            };
            risks.push(risk);
            totalScore += severityWeights[risk.severity] * (envEntropy > 3 ? 1.5 : 1);
          }
        }
      }
    });
  }

  totalScore = Math.min(totalScore, 10);

  return { risks, totalScore, entropyScore };
}

export function escapeCommand(command: string | string[]): string[] {
  if (Array.isArray(command)) return command.map(e => String(e).replace(/['"&|;<>`]/g, '\\$&'));
  return [command.replace(/['"&|;<>`]/g, '\\$&')];
}