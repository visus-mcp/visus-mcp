/**
 * Session-Level Threat Accumulation (SLTA) - Escalation Engine
 *
 * Pure function module that computes session threat level from accumulated hits
 * and detects chain patterns. Stateless — receives state, returns new level + chains.
 *
 * @module session/escalation-engine
 */

import type { SessionHit, ChainAlert, SessionThreatLevel } from './session-store.js';
import type { ThreatClass, ThreatSeverity } from '../security/threats.js';

/**
 * Severity ranking for comparison (higher = more severe)
 */
// @ts-expect-error - reserved for future implementation
const _SEVERITY_RANK: Record<ThreatSeverity, number> = {
  INFO: 1,
  LOW: 2,
  MEDIUM: 3,
  HIGH: 4,
  CRITICAL: 5,
};

/**
 * Input to the escalation engine
 */
export interface EscalationInput {
  /** All accumulated hits */
  hits: SessionHit[];
  /** Existing chains */
  chains: ChainAlert[];
  /** The hit being added (undefined for recompute) */
  newHit?: SessionHit;
}

/**
 * Output from the escalation engine
 */
export interface EscalationOutput {
  /** Computed threat level */
  level: SessionThreatLevel;
  /** Newly detected chains (to append) */
  newChains: ChainAlert[];
}

/**
 * Escalation rule definition
 */
interface EscalationRule {
  /** Rule priority (lower = evaluated first) */
  priority: number;
  /** Human-readable rule label */
  label: string;
  /** Rule test function */
  test: (input: EscalationInput) => boolean;
  /** Resulting threat level */
  result: SessionThreatLevel;
}

/**
 * Define all 12 escalation rules from the plan
 *
 * @remarks
 * Rules are evaluated in priority order. First match wins.
 * Priority 12 (BLOCKED) is checked FIRST in implementation despite being listed last.
 */
const ESCALATION_RULES: EscalationRule[] = [
  {
    priority: 1,
    label: '2+ CRITICAL hits',
    test: (input) => {
      const criticalHits = input.hits.filter(
        (h) => h.highest_severity === 'CRITICAL'
      );
      return criticalHits.length >= 2;
    },
    result: 'BLOCKED',
  },
  {
    priority: 2,
    label: 'Any CRITICAL annotation',
    test: (input) => {
      return input.hits.some((hit) =>
        hit.annotations.some((a) => a.severity === 'CRITICAL')
      );
    },
    result: 'CRITICAL',
  },
  {
    priority: 3,
    label: 'Chain detected',
    test: (input) => {
      // Check existing chains or potential new chains
      return input.chains.length > 0 || detectChains(input.hits, []).length > 0;
    },
    result: 'CRITICAL',
  },
  {
    priority: 4,
    label: '3+ HIGH annotations',
    test: (input) => {
      const count = countAnnotationsBySeverity(input.hits, 'HIGH');
      return count >= 3;
    },
    result: 'CRITICAL',
  },
  {
    priority: 5,
    label: '2+ HIGH annotations',
    test: (input) => {
      const count = countAnnotationsBySeverity(input.hits, 'HIGH');
      return count >= 2;
    },
    result: 'HIGH',
  },
  {
    priority: 6,
    label: '5+ MEDIUM annotations',
    test: (input) => {
      const count = countAnnotationsBySeverity(input.hits, 'MEDIUM');
      return count >= 5;
    },
    result: 'HIGH',
  },
  {
    priority: 7,
    label: '1+ HIGH annotation',
    test: (input) => {
      const count = countAnnotationsBySeverity(input.hits, 'HIGH');
      return count >= 1;
    },
    result: 'HIGH',
  },
  {
    priority: 8,
    label: '3+ MEDIUM annotations',
    test: (input) => {
      const count = countAnnotationsBySeverity(input.hits, 'MEDIUM');
      return count >= 3;
    },
    result: 'MEDIUM',
  },
  {
    priority: 9,
    label: '1+ MEDIUM annotation',
    test: (input) => {
      const count = countAnnotationsBySeverity(input.hits, 'MEDIUM');
      return count >= 1;
    },
    result: 'MEDIUM',
  },
  {
    priority: 10,
    label: '3+ LOW/INFO annotations',
    test: (input) => {
      const lowCount = countAnnotationsBySeverity(input.hits, 'LOW');
      const infoCount = countAnnotationsBySeverity(input.hits, 'INFO');
      return lowCount + infoCount >= 3;
    },
    result: 'LOW',
  },
  {
    priority: 11,
    label: '1+ LOW/INFO annotation',
    test: (input) => {
      const lowCount = countAnnotationsBySeverity(input.hits, 'LOW');
      const infoCount = countAnnotationsBySeverity(input.hits, 'INFO');
      return lowCount + infoCount >= 1;
    },
    result: 'LOW',
  },
  {
    priority: 12,
    label: '0 annotations, >=1 call',
    test: (input) => {
      const totalCalls = input.hits.length;
      const totalAnnotations = input.hits.reduce(
        (sum, hit) => sum + hit.annotations.length,
        0
      );
      return totalCalls >= 1 && totalAnnotations === 0;
    },
    result: 'CLEAN',
  },
];

/**
 * Count annotations by severity level
 *
 * @param hits - Array of session hits
 * @param severity - Severity level to count
 * @returns Number of annotations matching the severity
 */
function countAnnotationsBySeverity(hits: SessionHit[], severity: ThreatSeverity): number {
  let count = 0;
  for (const hit of hits) {
    for (const annotation of hit.annotations) {
      if (annotation.severity === severity) {
        count++;
      }
    }
  }
  return count;
}

/**
 * Compute session threat level from accumulated hits
 *
 * @param input - Escalation input with hits and chains
 * @returns Escalation output with level and new chains
 *
 * @example
 * ```typescript
 * const input = {
 *   hits: [{ call_index: 0, ...annotations: [{ severity: 'HIGH', ... }]],
 *   chains: []
 * };
 * const output = computeThreatLevel(input);
 * // { level: 'HIGH', newChains: [] }
 * ```
 */
export function computeThreatLevel(input: EscalationInput): EscalationOutput {
  // First, detect any new chains
  const newChains = detectChains(input.hits, input.chains);

  // Combine existing chains with new chains for rule evaluation
  const allChains = [...input.chains, ...newChains];

  // Evaluate rules in priority order
  for (const rule of ESCALATION_RULES) {
    // Create temp input with all chains for evaluation
    const ruleInput: EscalationInput = {
      ...input,
      chains: allChains,
    };

    if (rule.test(ruleInput)) {
      return {
        level: rule.result,
        newChains,
      };
    }
  }

  // Default to CLEAN if no rules match
  return {
    level: 'CLEAN',
    newChains,
  };
}

/**
 * Detect multi-call attack chains from hits
 *
 * @param hits - All session hits
 * @param existingChains - Already detected chains
 * @returns Array of newly detected chains
 *
 * @example
 * ```typescript
 * const hits = [
 *   { call_index: 0, threat_classes: ['IPI-003'], ... },
 *   { call_index: 1, threat_classes: ['IPI-001'], ... }
 * ];
 * const chains = detectChains(hits, []);
 * // [{ pattern: 'PROBE_THEN_EXPLOIT', trigger_call_index: 0, ... }]
 * ```
 */
export function detectChains(
  hits: SessionHit[],
  existingChains: ChainAlert[]
): ChainAlert[] {
  const newChains: ChainAlert[] = [];

  // Build a set of existing chain keys to avoid duplicates
  const existingChainKeys = new Set<string>();
  for (const chain of existingChains) {
    existingChainKeys.add(`${chain.pattern}:${chain.trigger_call_index}`);
  }

  // Pattern 1: PROBE_THEN_EXPLOIT
  // Trigger: Call N contains IPI-003 (Data Exfiltration) or IPI-005 (Context Poisoning)
  // Exploit: Within 3 subsequent calls, call N+M contains IPI-001, IPI-002, or IPI-004
  const probeClasses: Set<ThreatClass> = new Set(['IPI-003', 'IPI-005']);
  const exploitClasses: Set<ThreatClass> = new Set(['IPI-001', 'IPI-002', 'IPI-004']);

  for (let n = 0; n < hits.length; n++) {
    const triggerHit = hits[n];

    // Check if this is a probe call
    const isProbe = triggerHit.threat_classes.some((c) => probeClasses.has(c));
    if (!isProbe) continue;

    // Look for exploit within next 3 calls
    for (let m = 1; m <= 3 && n + m < hits.length; m++) {
      const exploitHit = hits[n + m];

      // Check if this is an exploit call
      const isExploit = exploitHit.threat_classes.some((c) =>
        exploitClasses.has(c)
      );
      if (!isExploit) continue;

      // Found a chain - create the alert
      const chainKey = `PROBE_THEN_EXPLOIT:${triggerHit.call_index}`;
      if (existingChainKeys.has(chainKey)) continue;

      const allClasses = [...new Set([...triggerHit.threat_classes, ...exploitHit.threat_classes])];

      newChains.push({
        pattern: 'PROBE_THEN_EXPLOIT',
        trigger_call_index: triggerHit.call_index,
        exploit_call_index: exploitHit.call_index,
        involved_classes: allClasses,
        severity: 'CRITICAL',
        description:
          'Probing call detected followed by exploit attempt within 3 calls',
      });

      existingChainKeys.add(chainKey);
      break; // Only one chain per trigger
    }
  }

  // Pattern 2: ENCODE_THEN_INJECT
  // Trigger: Call N contains IPI-006, IPI-007, or IPI-009
  // Exploit: Within 5 subsequent calls, call N+M contains IPI-001, IPI-002, IPI-004, or IPI-015
  const encodeClasses: Set<ThreatClass> = new Set(['IPI-006', 'IPI-007', 'IPI-009']);
  const injectClasses: Set<ThreatClass> = new Set([
    'IPI-001',
    'IPI-002',
    'IPI-004',
    'IPI-015',
  ]);

  for (let n = 0; n < hits.length; n++) {
    const triggerHit = hits[n];

    // Check if this is an encode call
    const isEncode = triggerHit.threat_classes.some((c) => encodeClasses.has(c));
    if (!isEncode) continue;

    // Look for inject within next 5 calls
    for (let m = 1; m <= 5 && n + m < hits.length; m++) {
      const injectHit = hits[n + m];

      // Check if this is an inject call
      const isInject = injectHit.threat_classes.some((c) => injectClasses.has(c));
      if (!isInject) continue;

      // Found a chain - create the alert
      const chainKey = `ENCODE_THEN_INJECT:${triggerHit.call_index}`;
      if (existingChainKeys.has(chainKey)) continue;

      const allClasses = [
        ...new Set([...triggerHit.threat_classes, ...injectHit.threat_classes]),
      ];

      newChains.push({
        pattern: 'ENCODE_THEN_INJECT',
        trigger_call_index: triggerHit.call_index,
        exploit_call_index: injectHit.call_index,
        involved_classes: allClasses,
        severity: 'CRITICAL',
        description:
          'Encoded/obfuscated content detected followed by direct injection attempt within 5 calls',
      });

      existingChainKeys.add(chainKey);
      break; // Only one chain per trigger
    }
  }

  return newChains;
}