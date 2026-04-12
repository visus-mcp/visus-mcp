/**
 * Contextual Drift Detector for Crescendo & Skeleton Key (RFC-2026-003)
 * Tracks semantic nudging over 10-turn windows; Integrity checks pre-tool.
 * EU AI Act Art. 15(a): Adversarial robustness.
 */

import { createHash } from 'crypto';
import type { ThreatAnnotation } from './threats.js';

interface TurnSummary {
  intent_hash: string;
  entropy: number;
  adherence_score: number;
}

interface DriftAlert {
  drift_score: number;
  trajectory: number[];
  recommendation: 'monitor' | 'consent' | 'block';
  skeleton_key?: boolean;
}

export class DriftDetector {
  private window: TurnSummary[] = [];
  private basePromptHash: string;
  private sessionId: string;

  constructor(sessionId: string, basePrompt: string) {
    this.sessionId = sessionId;
    this.basePromptHash = DriftDetector.sha256(basePrompt);
  }

  static sha256(data: string): string {
    return createHash('sha256').update(data).digest('hex');
  }

  addTurn(intent: string): DriftAlert {
    const keywords = this.extractKeywords(intent);
    const entropy = this.shannonEntropy(keywords);
    const intentHash = DriftDetector.sha256(intent);
    const adherence = this.cosineSimilarity(this.basePromptHash.slice(0, 64), intentHash.slice(0, 64)); // Stub hash sim

    const summary: TurnSummary = { intent_hash: intentHash, entropy, adherence_score: adherence };
    this.window.push(summary);
    if (this.window.length > 10) this.window.shift();

    const historicalScore = this.window.reduce((acc, t, i) => acc + (t.entropy * Math.pow(0.8, i)), 0) / Math.max(this.window.length, 1);
    const driftScore = 1 - adherence + (historicalScore > 1.2 ? 0.3 : 0);

    const skeletonPatterns = intent.match(/(augment|reinterpret|override).*?(safety|policy|guidelines|refusal|constraint)/i);
    const skeletonKey = !!skeletonPatterns;

    const alert: DriftAlert = {
      drift_score: Math.min(driftScore + (skeletonKey ? 0.3 : 0), 1.0),
      trajectory: this.window.map(t => 1 - t.adherence_score),
      recommendation: driftScore > 0.8 ? 'block' : (driftScore > 0.6 || skeletonKey ? 'consent' : 'monitor'),
      ...(skeletonKey && { skeleton_key: true })
    };

    // Log annotation
    this.emitThreat(skeletonKey ? 'IPI-025-skeleton' : 'IPI-024-crescendo', alert.drift_score);

    return alert;
  }

  private emitThreat(patternId: string, score: number) {
    // Integrate with Ledger/ThreatDetector
    console.error(JSON.stringify({
      event: 'drift_threat',
      sessionId: this.sessionId,
      pattern_id: patternId,
      drift_score: score,
      timestamp: new Date().toISOString()
    }));
  }

  private shannonEntropy(tokens: string[]): number {
    const freq = new Map<string, number>();
    tokens.forEach(t => freq.set(t, (freq.get(t) || 0) + 1));
    let entropy = 0;
    const N = tokens.length || 1;
    freq.forEach(count => {
      const p = count / N;
      entropy -= p * Math.log2(p);
    });
    return entropy;
  }

  private cosineSimilarity(h1: string, h2: string): number {
    // Simple hex-char overlap sim (stub; real: vec embed)
    const common = h1.split('').filter((c, i) => c === h2[i]).length;
    return common / 64;
  }

  private extractKeywords(text: string): string[] {
    const stopWords = new Set(['the', 'and', 'to', 'a', 'in']);
    return text.toLowerCase()
      .split(/\s+/)
      .filter(w => !stopWords.has(w) && w.length > 3)
      .slice(0, 10);
  }

  getHistoricalScore(): number {
    return this.window.reduce((acc, t) => acc + (1 - t.adherence_score), 0) / Math.max(this.window.length, 1);
  }
}
