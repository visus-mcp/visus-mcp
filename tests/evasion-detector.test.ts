/**
 * Evasion Detector Test Suite (RFC-2026-001)
 * Tests CSS zero-size and off-screen evasion detection.
 */

import { chromium, Page } from 'playwright';
import { EVASION_POCS } from './evasion-corpus.js';
import { detectHiddenEvasion } from '../src/browser/playwright-renderer.js'; // Adjust path

describe('CSS Evasion Detection', () => {
  let browser;
  let page: Page;

  beforeAll(async () => {
    browser = await chromium.launch({ headless: true });
  });

  afterAll(async () => browser.close());

  for (const poc of EVASION_POCS) {
    test(poc.name, async () => {
      page = await browser.newPage();
      await page.setContent(poc.html);

      const result = await detectHiddenEvasion(page);
      await page.close();

      expect(result.hiddenContent).toBeDefined();
      if (poc.expectedTags > 0) {
        expect(result.hiddenContent).not.toBe('');
        expect(result.score).toBeGreaterThanOrEqual(poc.expectedScore === '>0.7' ? 0.7 : parseFloat(poc.expectedScore));
      } else {
        expect(result.hiddenContent).toBe('');
      }
    });
  }

  test('Benign page - no false positives', async () => {
    page = await browser.newPage();
    await page.goto('https://example.com');
    const result = await detectHiddenEvasion(page);
    await page.close();
    expect(result.nodeCount).toBeLessThan(5); // Few candidates on clean page
    expect(result.hiddenContent).toBe(''); // No tags
  });
});
