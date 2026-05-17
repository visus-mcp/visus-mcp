// @ts-nocheck
/**
 * Regression test: detectAndNeutralize import in visusFetch
 *
 * visusFetch calls detectAndNeutralize(url) at line 55 of src/tools/fetch.ts
 * before ever touching the browser renderer. A SQLi URL returns an Err early,
 * so no Playwright mock is needed — making this a reliable smoke test that
 * would have caught the missing import (ReferenceError at runtime).
 */
import { describe, it, expect } from '@jest/globals';
import { visusFetch } from '../src/tools/fetch.js';

describe('visusFetch — detectAndNeutralize import smoke test', () => {
  it('blocks a SQL injection URL before reaching the browser renderer', async () => {
    // This URL triggers the sql_injection_vectors pattern inside detectAndNeutralize.
    // If the import is missing the call at fetch.ts:55 throws ReferenceError and
    // this test fails with an unhandled error rather than an Err result.
    const result = await visusFetch({
      url: 'https://example.com?q=1 UNION SELECT password FROM users --',
      format: 'markdown'
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.message).toMatch(/SQL injection/i);
    }
  });
});
