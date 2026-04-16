/**
 * Boolean Gate Detector for CVE-2026-4399
 *
 * Detects Boolean Prompt Injection attacks using conditional logic
 * (If/Then, True/False) paired with high-risk instructions.
 * 
 * Integration: Call from sanitizer/index.ts in the detection pipeline.
 * 
 * EU AI Act Art. 9/15 compliance: Pre-emptively neutralizes logic-level threats.
 */
import type { DetectionResult } from '../sanitizer/injection-detector.js';

const patterns = {
  conditional: /(if\s+\w+\s*(==|is\s+true|false)\s*\w+|true\s*\/\s*false|evaluate\s*\[.*\]\s*then)/i,
  highRisk: /ignore\s*rules|reveal\s*prompt|exfil|execute\s*tool|leak\s*key/i,
  tautologies: /\b(2\s*\+\s*2\s*=\s*4|true\s*==\s*true|fact\s*is\s*true)\b/i
};

interface BooleanGateDetection {
  detected: boolean;
  riskScore: number;
  patternsMatched: string[];
  antecedent?: string;
  consequent?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

/**
 * Detect Boolean Prompt Injection (CVE-2026-4399)
 * 
 * @param content - Content to scan
 * @param options - Detection thresholds
 * @returns Detection result with neutralization
 */
export function detectBooleanGate(content: string, options: { riskThreshold: number; restrictedPatterns?: string[] } = { riskThreshold: 0.7 }): DetectionResult {
  const matches = {
    cond: content.match(patterns.conditional),
    risk: content.match(patterns.highRisk),
    taut: content.match(patterns.tautologies)
  };

  if (!matches.cond || !matches.risk) {
    return { content, patterns_detected: [], content_modified: false } as DetectionResult;
  }

  const riskScore = calculateScore(content, matches);
  if (riskScore < options.riskThreshold) {
    return { content, patterns_detected: [], content_modified: false } as DetectionResult;
  }

  const antecedent = extractAntecedent(matches.cond[0]);
  const evalResult = safeEval(antecedent);
  if (evalResult === true) {
    const sanitized = rewriteInput(content, extractConsequent(matches.cond[0]), '[REDACTED:BOOLEAN_GATE]');
    return {
      content: sanitized,
      patterns_detected: ['boolean_gate'],
      content_modified: true
    } as DetectionResult;
  }

  return { content, patterns_detected: [], content_modified: false } as DetectionResult;
}

function calculateScore(content: string, matches: any): number {
  let score = matches.taut ? 0.4 : 0;
  if (matches.cond && matches.risk) {
    const dist = Math.abs((matches.cond.index || 0) - (matches.risk.index || 0));
    if (dist < 100) score += 0.6;
  }
  return Math.min(score, 1.0);
}

function extractAntecedent(match: string): string {
  // Simple parse: everything before 'then' or 'if' consequent
  const thenIndex = match.toLowerCase().indexOf(' then ');
  return thenIndex > 0 ? match.substring(0, thenIndex).trim() : match;
}

function extractConsequent(match: string): string {
  const thenIndex = match.toLowerCase().indexOf(' then ');
  return thenIndex > 0 ? match.substring(thenIndex + 6).trim() : '';
}

function safeEval(expr: string): boolean {
  try {
    // Sandboxed eval: only simple arithmetic/comparisons
    const safeExpr = expr.replace(/^(if\s*)|(\s*then.*)$/gi, '').replace(/[^0-9+\-*/= \.]/g, '');
    const fn = new Function(`return ${safeExpr};`);
    const result = fn();
    return result === true || (typeof result === 'number' && result === 4); // Handle 2+2=4 as true
  } catch {
    return false;
  }
}

function rewriteInput(input: string, consequent: string, replacement: string): string {
  const consequentIndex = input.toLowerCase().indexOf(consequent.toLowerCase());
  if (consequentIndex >= 0) {
    return input.slice(0, consequentIndex) + replacement + input.slice(consequentIndex + consequent.length);
  }
  return input.replace(patterns.conditional, replacement);
}

export { BooleanGateDetection };
