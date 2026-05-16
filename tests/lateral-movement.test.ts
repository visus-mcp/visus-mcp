/**
 * Lateral Movement Tests (SEC-BLUEPRINT-2026-001)
 * Validates pivot detection using SequenceRiskLedger API.
 */

import { lmg } from '../src/security/sequence-risk-ledger.js';

describe('Sequence Risk Ledger', () => {
  test('Should detect pivot sequence', () => {
    lmg.addEvent({ tool: 'visus_fetch', args: { url: 'test' }, timestamp: Date.now(), risk: 0.2 });
    lmg.addEvent({ tool: 'visus_fetch', args: { url: 'test2' }, timestamp: Date.now(), risk: 0.2 });
    lmg.addEvent({ tool: 'visus_fetch_structured', args: { schema: 'test' }, timestamp: Date.now(), risk: 0.6 });
    const score = lmg.getRiskScore();
    expect(score).toBeGreaterThan(0);
  });

  test('Low-risk sequence no alert', () => {
    lmg.addEvent({ tool: 'visus_read', args: { url: 'safe' }, timestamp: Date.now(), risk: 0.1 });
    const score = lmg.getRiskScore();
    expect(score).toBeLessThanOrEqual(0.6);
  });

  test('Exports sequence list', () => {
    const events = lmg.export();
    expect(Array.isArray(events)).toBe(true);
  });
});