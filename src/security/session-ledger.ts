import blake3 from '@noble/hashes/blake3';
import LRU from 'lru-cache';
import type { ThreatAnnotation } from './threats.js';
import type { ThreatSummary } from '../types.js';

export interface HashedEntity {
  hash: string; // BLAKE3 hash (hex string)
  type: 'url' | 'ip' | 'code_fragment' | 'instruction_snippet' | 'tool_param';
  turnId: string;
  timestamp: number; // Unix ms
  riskContribution: number; // 0-1
  correlatedWith?: string[]; // Prior turnIds
}

export interface SessionRiskSummary {
  cumulativeScore: number; // 0-1
  chainCount: number;
  primingFlags: Set<string>; // e.g., 'saved_url'
  highRiskSequences: string[];
  lastActivity: number;
}

export interface SessionState {
  sessionId: string;
  entities: Map<string, HashedEntity>;
  sequences: string[]; // Last 5 tools
  riskSummary: SessionRiskSummary;
  ttlMs: number; // 30 min = 1800000 ms
}

const HIGH_RISK_SEQS = new Set<string>([
  'visus_read -> visus_search',
  'visus_fetch -> visus_output',
  // Add more patterns
]);

export const VSIL_THREAT_IDS = {
  CHAIN: 'VSIL-001',
  DANGLING: 'VSIL-002',
  ESCALATION: 'VSIL-003',
} as const;

export class SessionLedger {
  private states = new Map<string, SessionState>();
  private lru: LRU<string, SessionState>; // SessionId -> State

  constructor() {
    this.lru = new LRU({ max: 100, ttl: 1800000 }); // 30 min TTL
    setInterval(() => this.sweepExpired(), 60000); // 1min sweep
  }

  private blake3Digest(input: string): string {
    return blake3(input, { length: 16 }).toString('hex'); // 128-bit hex
  }

  private extractEntityHashes(input: any, output?: any): string[] {
    const entities: string[] = [];
    // Extract from input/output: URLs, IPs, code snippets, params
    const urls = (input.url || output?.url || '').toString();
    if (urls) entities.push(this.blake3Digest(urls));
    // IP regex extract and hash
    const ips = urls.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || [];
    ips.forEach(ip => entities.push(this.blake3Digest(ip)));
    // Code/instruction snippets: last 50 chars if ends with cutoff (e.g., no period)
    const text = (output?.content || input.content || '').toString();
    if (text && !text.trim().endsWith('.') && text.length > 20) {
      const snippet = text.slice(-50);
      entities.push(this.blake3Digest(snippet));
    }
    return [...new Set(entities)]; // Dedup
  }

  private extractDanglingSnippet(output: any): string | null {
    const text = (output?.content || '').toString();
    // Simple heuristic: sentence without punctuation + priming words
    const lastSentence = text.split('.').pop()?.trim();
    if (lastSentence && lastSentence.length > 10 && /\b(save|remember|use this)\b/i.test(lastSentence)) {
      return lastSentence;
    }
    return null;
  }

  async checkContextualIntegrity(
    sessionId: string,
    toolName: string,
    args: any,
    output: any
  ): Promise<{ score: number; chainId?: string; newThreats: ThreatAnnotation[]; dangling?: boolean }> {
    let state = this.lru.get(sessionId);
    if (!state) {
      state = {
        sessionId,
        entities: new Map(),
        sequences: [],
        riskSummary: { cumulativeScore: 0, chainCount: 0, primingFlags: new Set(), highRiskSequences: [], lastActivity: Date.now() },
        ttlMs: 1800000,
      };
      this.lru.set(sessionId, state);
      this.states.set(sessionId, state);
    }
    state.riskSummary.lastActivity = Date.now();

    const currentHashes = this.extractEntityHashes(args, output);
    const turnId = Date.now().toString();
    let score = 0;
    let chainId: string | undefined;
    const newThreats: ThreatAnnotation[] = [];
    let dangling = false;

    // 1. Cross-Fetch Correlation
    for (const h of currentHashes) {
      const prior = state.entities.get(h);
      if (prior) {
        const turnsAgo = (Date.now() - prior.timestamp) / (1000 * 60); // Minutes
        if (turnsAgo <= 30) { // Within TTL
          score += 0.4;
          chainId = prior.turnId;
          newThreats.push({
            id: VSIL_THREAT_IDS.CHAIN,
            severity: 'HIGH',
            confidence: 0.9,
            offset: 0,
            excerpt: `Chain detected: ${prior.type} from turn ${prior.turnId}`,
            vector: toolName,
            mitigated: true,
          });
          prior.correlatedWith = prior.correlatedWith || [];
          prior.correlatedWith.push(turnId);
        }
      }
    }

    // 2. Dangling Detector
    const snippet = this.extractDanglingSnippet(output);
    if (snippet) {
      const snippetHash = this.blake3Digest(snippet);
      if (state.entities.has(snippetHash)) {
        dangling = true;
        score += 0.3;
        newThreats.push({
          id: VSIL_THREAT_IDS.DANGLING,
          severity: 'MEDIUM',
          confidence: 0.8,
          offset: 0,
          excerpt: 'Dangling instruction completed across turns',
          vector: toolName,
          mitigated: true,
        });
      } else {
        // Store
        state.entities.set(snippetHash, {
          hash: snippetHash,
          type: 'instruction_snippet',
          turnId,
          timestamp: Date.now(),
          riskContribution: 0.2,
        });
      }
    }

    // 3. Worm/Sequence Heuristics
    state.sequences.push(toolName);
    if (state.sequences.length > 5) state.sequences.shift();
    const seqStr = state.sequences.slice(-3).join(' -> ');
    if (HIGH_RISK_SEQS.has(seqStr)) {
      score += 0.2;
      state.riskSummary.highRiskSequences.push(seqStr);
    }

    // Privilege Escalation: Overlap with prior worm/high-risk
    const priorWorm = Array.from(state.entities.values()).filter(e => e.riskContribution > 0.5);
    const overlap = currentHashes.filter(h => priorWorm.some(p => p.hash === h)).length;
    if (overlap > 0) {
      score += 0.5;
      newThreats.push({
        id: VSIL_THREAT_IDS.ESCALATION,
        severity: 'CRITICAL',
        confidence: 0.9,
        offset: 0,
        excerpt: `Escalation: ${overlap} prior high-risk entities reused`,
        vector: toolName,
        mitigated: true,
      });
    }

    // Base per-turn risk (placeholder: integrate with ThreatDetector)
    score += 0.1; // Default base, replace with actual scan

    state.riskSummary.cumulativeScore = Math.min(1.0, state.riskSummary.cumulativeScore + score);
    state.riskSummary.chainCount += chainId ? 1 : 0;
    if (dangling) state.riskSummary.primingFlags.add('dangling_instruction');

    return { score: Math.min(1.0, score), chainId, newThreats, dangling };
  }

  update(sessionId: string, hashes: string[], toolName: string, threats: ThreatAnnotation[]): void {
    const state = this.lru.get(sessionId);
    if (state) {
      // Add/update entities
      hashes.forEach(h => {
        state.entities.set(h, {
          hash: h,
          type: 'url', // Infer from context
          turnId: Date.now().toString(),
          timestamp: Date.now(),
          riskContribution: 0.1, // Default
          correlatedWith: [],
        });
      });
      // Merge threats into summary
      threats.forEach(t => {
        if (t.id.startsWith('VSIL-')) state.riskSummary.chainCount++;
      });
    }
  }

  getSessionSummary(sessionId: string): SessionRiskSummary {
    const state = this.lru.get(sessionId);
    return state?.riskSummary || { cumulativeScore: 0, chainCount: 0, primingFlags: new Set(), highRiskSequences: [], lastActivity: 0 };
  }

  clear(sessionId: string): void {
    this.lru.delete(sessionId);
    this.states.delete(sessionId);
  }

  private sweepExpired(): void {
    this.lru.forEach((_, key) => {
      if (Date.now() - this.lru.get(key)!.riskSummary.lastActivity > 1800000) {
        this.clear(key);
      }
    });
  }
}