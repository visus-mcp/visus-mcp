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

const HIGH_ENTROPY_THRESHOLD = 4.5;

function mapSeverity(sev: 'low' | 'medium' | 'high' | 'critical'): CommandRisk['severity'] {
  return sev as CommandRisk['severity'];
}

export interface DetectionResult {
  risks: CommandRisk[];
  totalScore: number; // Dynamic risk score (0-10)
  entropyScore: number; // Aggregated entropy
}

export function detectCommandInjection(params: Record<string, any>, options: { whitelist?: string[] } = {}): DetectionResult {
  const { whitelist = [] } = options;
  const risks: CommandRisk[] = [];
  let totalScore = 0;
  let entropyScore = 0;

  // Relevant patterns: those starting with shell_ or including rce/cmd, now including new poisoning patterns
  const commandPatterns = INJECTION_PATTERNS.filter(p => 
    p.name.startsWith('shell_') || 
    p.name.startsWith('bash_') ||
    p.name.startsWith('cmd_') ||
    p.name.startsWith('tool_') || // New tool poisoning patterns
    p.name.includes('rce') ||
    p.name.includes('rug_pull') ||
    p.name.includes('schema_') ||
    p.name.includes('injection') && p.name !== 'direct_instruction_injection'
  );

  // Severity weights for scoring
  const severityWeights = {
    low: 1,
    medium: 3,
    high: 5,
    critical: 8
  };

  // Aggregate entropy across fields
  let allText = '';
  if (params.command && typeof params.command === 'string') allText += params.command;
  if (params.args && Array.isArray(params.args)) {
    params.args.forEach(arg => { if (typeof arg === 'string') allText += arg; });
  }
  if (params.env) {
    Object.values(params.env).forEach(val => { if (typeof val === 'string') allText += val; });
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
    totalScore += severityWeights['medium'] + (entropyScore - HIGH_ENTROPY_THRESHOLD) * 2; // Bonus for high entropy
  }

  // Scan command
  if (params.command && typeof params.command === 'string') {
    const cmd = params.command;
    const cmdEntropy = scoreEntropy(cmd);
    if (cmdEntropy > HIGH_ENTROPY_THRESHOLD * 0.8) totalScore += (cmdEntropy * 1.5); // Per-field entropy boost

    for (const pat of commandPatterns) {
      if (pat.regex.test(cmd) && !whitelist.includes(pat.name)) {
        const risk: CommandRisk = {
          pattern: pat.name,
          location: 'command',
          snippet: cmd.substring(0, 100) + (cmd.length > 100 ? '...' : ''),
          severity: mapSeverity(pat.severity)
        };
        risks.push(risk);
        totalScore += severityWeights[risk.severity] * (cmdEntropy > 3 ? 1.5 : 1); // Amplify if high entropy
      }
    }
  }

  // Scan args array
  if (params.args && Array.isArray(params.args)) {
    params.args.forEach((arg, index) => {
      if (typeof arg === 'string') {
        const argEntropy = scoreEntropy(arg);
        if (argEntropy > HIGH_ENTROPY_THRESHOLD * 0.8) totalScore += argEntropy;

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

  // Scan env (new for poisoning)
  if (params.env && typeof params.env === 'object') {
    Object.entries(params.env).forEach(([key, val]) => {
      if (typeof val === 'string') {
        const envStr = `${key}=${val}`;
        const envEntropy = scoreEntropy(envStr);
        if (envEntropy > HIGH_ENTROPY_THRESHOLD) totalScore += envEntropy;

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

  // Cap total score
  totalScore = Math.min(totalScore, 10);

  return { risks, totalScore, entropyScore };
}

// Escape function for safe spawning (MVP, unchanged)
export function escapeCommand(command: string | string[]): string[] {
  if (Array.isArray(command)) return command.map(escape => String(escape).replace(/['"&|;<>`]/g, '\\$&'));
  return [command.replace(/['"&|;<>`]/g, '\\$&')];
}
