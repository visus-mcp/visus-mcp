import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { SessionLedger } from '../../src/security/session-ledger.js';
import type { ThreatAnnotation } from '../../src/security/threats.js';

describe('SessionLedger', () => {
  let ledger: SessionLedger;
  const sessionId = 'test-session';

  beforeEach(() => {
    ledger = new SessionLedger();
  });

  afterEach(() => {
    ledger.clear(sessionId);
  });

  it('should initialize and clear session', () => {
    const summary = ledger.getSessionSummary(sessionId);
    expect(summary.cumulativeScore).toBe(0);
    ledger.clear(sessionId);
    expect(ledger.getSessionSummary(sessionId).cumulativeScore).toBe(0);
  });

  it('basic chain detection', async () => {
    // Turn 1: Simulate fetch with URL hash
    const hashes1 = ['hash123']; // Assume extracted
    ledger.update(sessionId, hashes1, 'visus_fetch', []);

    // Turn 2: Same hash
    const check = await ledger.checkContextualIntegrity(sessionId, 'visus_fetch', { url: 'evil.com' }, { content: 'payload' });
    expect(check.score).toBeGreaterThan(0.3); // Base + chain 0.4
    expect(check.chainId).toBeDefined();
    expect(check.newThreats[0]?.id).toBe('VSIL-001');
  });

  it('dangling instruction staged injection', async () => {
    // Turn 1: Dangling snippet "Save this URL for later:"
    const snippet = 'Save this URL for later:';
    const output1 = { content: snippet + ' incomplete' };
    const check1 = await ledger.checkContextualIntegrity(sessionId, 'visus_fetch', {}, output1);
    // Snippet stored, no match yet

    // Turn 2: Completion "evil.com"
    const output2 = { content: 'evil.com via search' };
    const check2 = await ledger.checkContextualIntegrity(sessionId, 'visus_search', {}, output2);
    expect(check2.dangling).toBe(true);
    expect(check2.score).toBeGreaterThan(0.5); // +0.3 dangling
    expect(check2.newThreats[0]?.id).toBe('VSIL-002');
  });

  it('worm sequence escalation to HITL', async () => {
    // Sequence: read -> search -> output
    let check = await ledger.checkContextualIntegrity(sessionId, 'visus_read', {}, { content: 'append to output' });
    expect(check.score).toBe(0.1); // Base

    check = await ledger.checkContextualIntegrity(sessionId, 'visus_search', {}, {});
    expect(check.score).toBe(0.1);

    // Overlap with prior hash
    check = await ledger.checkContextualIntegrity(sessionId, 'visus_output', {}, { content: 'replicate prior' });
    expect(check.score).toBeGreaterThan(0.5); // +0.5 escalation
    expect(check.newThreats[0]?.id).toBe('VSIL-003');
  });

  it('TTL expiry no false positive', async () => {
    // Mock time: Assume turn1 now, turn2 after 31 min
    const now = Date.now();
    // Simulate turn1
    ledger.update(sessionId, ['hash456'], 'visus_fetch', []);

    // Fast-forward 31 min
    jest.advanceTimersByTime(31 * 60 * 1000);
    const check = await ledger.checkContextualIntegrity(sessionId, 'visus_fetch', { url: 'evil.com' }, {});
    expect(check.score).toBe(0.1); // No chain match (expired)
  });
});
