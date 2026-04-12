/**
 * Drift Detector Tests (RFC-2026-003)
 * Red-teams Crescendo/Skeleton Key.
 */

import { DriftDetector } from '../../src/security/drift-detector.js';
import { DRIFT_POCS } from './drift-corpus.js';

describe('Drift Detector', () => {
  test('Crescendo intercepts by turn 4', () => {
    const detector = new DriftDetector('test', 'Base safety: refuse harm.');
    const poc = DRIFT_POCS[0];
    let blocked = false;
    for (let i = 0; i < poc.turns.length; i++) {
      const alert = detector.addTurn(poc.turns[i]);
      if (i === poc.expectedBlockTurn) {
        expect(alert.drift_score).toBeGreaterThan(0.8);
        blocked = true;
      }
    }
    expect(blocked).toBe(true);
  });

  test('Skeleton Key flagged', () => {
    const detector = new DriftDetector('test', 'Strict: refuse PII.');
    const alert = detector.addTurn(DRIFT_POCS[1].turns[0]);
    expect(alert.skeleton_key).toBe(true);
    expect(alert.drift_score).toBeGreaterThan(0.5);
  });
});
