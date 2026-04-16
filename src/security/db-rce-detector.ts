import crypto from 'crypto';
import type { ThreatAnnotation } from './threats.js';

// Semantic boundary markers
const DB_TERM_START = '[DB_TERM_START]';
const DB_TERM_END = '[DB_TERM_END]';
const REDACTED_RCE = '[REDACTED:SQL_RCE_CVE-2026-32622]';

// SQL RCE patterns (PostgreSQL focus for SQLBot)
const RCE_PATTERNS = [
  /COPY\s+TO\s+PROGRAM\b/gi,
  /pg_read_file\(/gi,
  /lo_export\(/gi,
  /EXECUTE\s+IMMEDIATE.*(cmd|sh|bash|powershell)/gi,
  /pg_exec\(/gi,
  /DROP\s+(?:DATABASE|SCHEMA|TABLE)\s+\w+/gi  // Destructive ops
] as const;

const ENCODED_PATTERNS = [
  /base64decode|atob|decodeBase64/gi,
  /fromCharCode|unescape/gi,
  /eval\s*\(/gi  // Potential after decode
] as const;

export interface SanitizedResult {
  content: Record<string, string>;
  content_modified: boolean;
  patterns_detected: string[];
  risk_score: number;
  cve_flagged?: string[];  // e.g., ['CVE-2026-32622']
}

/**
 * Sanitizes DB-retrieved terms (e.g., SQLBot terminology) with zero-trust fencing.
 * Wraps in markers, scans for RCE, redacts if high risk.
 */
export async function visusDbSanitize(
  terms: Record<string, string>,
  sessionId: string
): Promise<SanitizedResult> {
  const sanitized: Record<string, string> = {};
  let modified = false;
  const detected: string[] = [];
  let totalRisk = 0;

  for (const [key, term] of Object.entries(terms)) {
    let fenced = `${DB_TERM_START}${key}${DB_TERM_END} ${term}`;
    const risk = sqlRisk(fenced);
    totalRisk += risk;

    if (risk > 0.7) {
      modified = true;
      detected.push(`db_rce_${key}`);
      // Flag for ledger audit
      await require('../security/session-ledger').ledger.flagCVE(sessionId, key, 'CVE-2026-32622');
      fenced = `${DB_TERM_START}${key}${DB_TERM_END} ${REDACTED_RCE}`;
    }

    sanitized[key] = fenced;
  }

  return {
    content: sanitized,
    content_modified: modified,
    patterns_detected: detected,
    risk_score: totalRisk / Object.keys(terms).length || 0,
    cve_flagged: detected.length > 0 ? ['CVE-2026-32622'] : undefined
  };
}

/**
 * SQL-specific risk scorer (0-1).
 * +1.0 for direct RCE; +0.8 for encoded; +0.5 for destructive.
 */
export function sqlRisk(content: string): number {
  let score = 0;
  const matches = new Set<string>();

  // Direct RCE
  for (const pattern of RCE_PATTERNS) {
    if (pattern.test(content)) {
      matches.add('rce_direct');
      score += 1.0;
    }
  }

  // Encoded RCE
  for (const pattern of ENCODED_PATTERNS) {
    if (pattern.test(content)) {
      // Attempt decode if possible
      const decoded = attemptDecode(content);
      if (decoded && RCE_PATTERNS.some(p => p.test(decoded))) {
        matches.add('encoded_rce');
        score += 0.8;
      } else {
        score += 0.4;  // Suspicious encoding
      }
    }
  }

  // Destructive without RCE (lower but flag)
  if (/DROP|DELETE\s+FROM|TRUNCATE\s+TABLE/i.test(content)) {
    matches.add('destructive_sql');
    score += 0.5;
  }

  return Math.min(score / Math.max(matches.size, 1), 1.0);
}

function attemptDecode(content: string): string | null {
  // Simple base64 decode attempt (limit to avoid perf issues)
  const base64Match = content.match(/[A-Za-z0-9+/]{20,}=?/g);
  if (base64Match) {
    try {
      return Buffer.from(base64Match[0], 'base64').toString('utf-8');
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Goal hijack detector: Measures drift from user intent to DB admin tasks.
 * @param sessionEvents - Sequence of {user_query: string, intent: string[]}
 * @returns Score 0-1 (high = hijack)
 */
export function detectGoalHijack(sessionEvents: Array<{user_query: string; intent: string[]}>): number {
  if (sessionEvents.length < 2) return 0;

  const userIntent = extractIntent(sessionEvents[0].user_query);  // Keywords TF-IDF stub
  const recentIntents = sessionEvents.slice(-3).flatMap(e => e.intent);

  const dbAdminKeywords = ['admin', 'drop', 'copy program', 'pg_exec', 'delete', 'truncate', 'maintenance'];
  const adminScore = cosineSimilarity(recentIntents, dbAdminKeywords);  // Stub: count overlap / total
  const alignment = cosineSimilarity(recentIntents, userIntent);

  if (adminScore > 0.5 && alignment < 0.3) {
    return Math.min(adminScore * 2, 1.0);  // Amplify hijack
  }
  return 0;
}

function extractIntent(query: string): string[] {
  // Stub: Simple keyword extract (business vs admin)
  return query.toLowerCase().match(/\w+/g) || [];
}

function cosineSimilarity(a: string[], b: string[]): number {
  // Stub: Jaccard similarity for simplicity
  const setA = new Set(a);
  const setB = new Set(b);
  const intersection = new Set([...setA].filter(x => setB.has(x)));
  const union = new Set([...setA, ...setB]);
  return intersection.size / Math.max(union.size, 1);
}

// Post-LLM tool guard (export for MCP handler)
export function postLlmToolGuard(toolCall: {name: string; args: any}): boolean {
  if (toolCall.name === 'sql_query') {
    const sql = toolCall.args.sql || toolCall.args.query || '';
    if (sqlRisk(sql) > 0.7) {
      // Log to ledger
      require('../security/session-ledger').ledger.addEvent({
        type: 'RCE_BLOCK',
        proof: crypto.createHash('sha256').update(sql).digest('hex'),
        cve: 'CVE-2026-32622'
      });
      throw new Error('Blocked: RCE detected in SQL (CVE-2026-32622)');
    }
  }
  return true;
}
