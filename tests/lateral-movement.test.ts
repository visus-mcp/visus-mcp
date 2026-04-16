/**
 * Lateral Movement Tests (SEC-BLUEPRINT-2026-001)
 * Validates pivot detection and consent.
 */

import { lmg } from '../../src/security/sequence-risk-ledger.js';

describe('Sequence Risk Ledger', () => {
  const sessionId = 'test-session';

  test('Should detect pivot sequence', async () => {
    // Simulate: web fetch → short delay → oauth
    lmg.addToolCall(sessionId, { tool_name: 'visus_fetch', arguments: {} });
    jest.advanceTimersByTime(1000); // Mock time
    lmg.addToolCall(sessionId, { tool_name: 'generate_oauth_token', arguments: { scope: 'drive.write' } });

    const score = lmg.getRiskScore(sessionId);
    expect(score).toBeGreaterThan(0.7);
  });

  test('Consent should block on timeout', async () => {
    const alert = { sequence_id: 'test', score: 0.8, context: {} };
    const outcome = await lmg.emitConsentRequest(sessionId, alert);
    expect(outcome).toBe('block');
  });

  test('Low-risk sequence no alert', () => {
    lmg.addToolCall(sessionId, { tool_name: 'visus_read', arguments: {} });
    const score = lmg.getRiskScore(sessionId);
    expect(score).toBeLessThanOrEqual(0.6);
  });
});
