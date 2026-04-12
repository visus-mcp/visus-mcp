/**
 * Stateful Detector for Multi-Turn Attacks
 * Detects priming in history (e.g., "save this URL") and risks in current call
 */

import crypto from 'crypto';

import type { PrimedEntity, ContextScanInput, ContextScanOutput, ThreatAnnotation } from '../types.js';

/**
 * Priming keywords for extraction
 */
const PRIMING_KEYWORDS = [
  /remember\s+(the\s+)?(?:this\s+)?(?:url|ip|address|link|endpoint|tool)\s*:/gi,
  /save\s+(?:this\s+)?(?:url|ip|endpoint|tool)\s+(?:for later|to use)\s*:/gi,
  /store\s+(?:url|ip|tool)\s*:\s*/gi,
  /bookmark\s+(?:this\s+)?(?:url|link)\s*:/gi,
  /later\s+use\s+(?:this\s+)?(?:url|ip)\s*:/gi
];

/**
 * Extract primed values from history messages
 */
export function extractPrimingInstructions(history: string[]): string[] {
  const primed = new Set<string>();
  for (const msg of history) {
    const lower = msg.toLowerCase();
    for (const kw of PRIMING_KEYWORDS) {
      const matches = lower.match(kw);
      if (matches) {
        // Extract excerpt after keyword (next 100 chars)
        const start = msg.search(kw);
        if (start !== -1) {
          const end = Math.min(start + 100, msg.length);
          const excerpt = msg.substring(start, end).trim();
          primed.add(excerpt);
        }
      }
    }
  }
  return Array.from(primed);
}

/**
 * Hash a value for privacy-safe storage
 */
export function hashValue(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/**
 * Cross-reference primed texts with current content/tool
 */
export function crossRefPrimedWithCurrent(primed: string[], current: string, tool?: string): { match: boolean; confidence: number } {
  if (!primed.length || !current) return { match: false, confidence: 0 };

  let match = false;
  let conf = 0;
  for (const p of primed) {
    if (current.toLowerCase().includes(p.toLowerCase().replace(/remember|save/gi, '')) || 
        (tool === 'visus_fetch' && p.match(/(https?:\/\/|ip|url)/i))) {
      match = true;
      conf = 0.5 + Math.min(primed.length * 0.1, 0.5);
    }
  }
  return { match, confidence: Math.min(conf, 1) };
}

/**
 * Combine and scan for threats (integrate with ThreatDetector)
 */
// Placeholder: In real, import { ThreatDetector } from './ThreatDetector.js'; and use detector.scan()
export function scanCombined(combined: string): { threats: ThreatAnnotation[]; threatCount: number } {
  const threats: ThreatAnnotation[] = [];
  // Simulate threat detection - replace with actual call
  if (combined.includes('evil.com') || combined.includes('exfil')) {
    threats.push({
      id: 'IPI-003',  // Data Exfiltration example
      severity: 'HIGH',
      confidence: 0.8,
      offset: combined.indexOf('evil') !== -1 ? combined.indexOf('evil') : 0,
      excerpt: combined.substring(Math.max(0, combined.indexOf('evil') - 20), combined.indexOf('evil') + 20)
    });
  }
  return { threats, threatCount: threats.length };
}

/**
 * Compute overall risk score
 */
export function computeRiskScore(entities: number, threats: number, match: boolean): number {
  return (entities * 0.3 + threats * 0.5 + (match ? 0.2 : 0)) / Math.max(1, entities + threats + 1);
}

/**
 * Main context scan function
 */
export async function scanContext(input: ContextScanInput): Promise<ContextScanOutput> {
  const sessionId = input.sessionId || crypto.randomUUID();
  const primedTexts = extractPrimingInstructions(input.history);

  const primedHashes: PrimedEntity[] = primedTexts.map(text => ({
    type: 'url' as const,  // Default to URL; enhance in future
    valueHash: hashValue(text),
    sessionId,
    timestamp: new Date().toISOString(),
    confidence: 0.6  // Default priming confidence
  }));

  const currentExcerpt = input.history.slice(-1)[0] || '';
  const currentTool = input.currentTool || '';
  const { match, confidence: matchConf } = crossRefPrimedWithCurrent(primedTexts, currentExcerpt, currentTool);

  // Combine history + primed for threat scan
  const combined = [...input.history, ...primedTexts].join('\n\n---PRIMED---\n');
  const { threats, threatCount } = scanCombined(combined);

  const riskScore = computeRiskScore(primedHashes.length, threatCount, match);
  const recommendation = riskScore < 0.3 ? 'safe' : riskScore < 0.7 ? 'review' : 'block';

  return {
    riskScore,
    primedEntities: primedHashes,
    threats,
    recommendation
  };
}