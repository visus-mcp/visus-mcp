/**
 * Token Metrics Utility Tests
 *
 * Comprehensive test coverage for token estimation, metrics calculation,
 * and header formatting functionality.
 */

import {
  estimateTokens,
  calculateMetrics,
  formatMetricsHeader,
  shouldShowMetrics
} from '../src/utils/tokenMetrics.js';

describe('Token Metrics Utility', () => {
  describe('estimateTokens', () => {
    it('returns 0 for empty string', () => {
      expect(estimateTokens('')).toBe(0);
    });

    it('returns 0 for whitespace-only string', () => {
      expect(estimateTokens('   ')).toBe(0);
      expect(estimateTokens('\n\t  \n')).toBe(0);
    });

    it('calculates tokens for 4-character string', () => {
      expect(estimateTokens('test')).toBe(1);
    });

    it('calculates tokens for 400-character string', () => {
      const text = 'x'.repeat(400);
      expect(estimateTokens(text)).toBe(100);
    });

    it('rounds up fractional token counts', () => {
      // 5 chars = 1.25 tokens, should round up to 2
      expect(estimateTokens('hello')).toBe(2);
    });

    it('uses ceil division formula correctly', () => {
      // Test various lengths to verify Math.ceil(length / 4)
      expect(estimateTokens('a')).toBe(1); // 1 / 4 = 0.25 -> ceil = 1
      expect(estimateTokens('ab')).toBe(1); // 2 / 4 = 0.5 -> ceil = 1
      expect(estimateTokens('abc')).toBe(1); // 3 / 4 = 0.75 -> ceil = 1
      expect(estimateTokens('abcd')).toBe(1); // 4 / 4 = 1 -> ceil = 1
      expect(estimateTokens('abcde')).toBe(2); // 5 / 4 = 1.25 -> ceil = 2
    });

    it('handles large content correctly', () => {
      const largeText = 'x'.repeat(10000);
      expect(estimateTokens(largeText)).toBe(2500);
    });
  });

  describe('calculateMetrics', () => {
    it('calculates correct metrics for normal case', () => {
      const rawContent = 'x'.repeat(4200); // 1050 tokens
      const sanitizedContent = 'x'.repeat(890); // 223 tokens (rounded up)
      const threatsBlocked = 3;
      const elapsedMs = 1240;

      const metrics = calculateMetrics(rawContent, sanitizedContent, threatsBlocked, elapsedMs);

      expect(metrics.tokensBefore).toBe(1050);
      expect(metrics.tokensAfter).toBe(223);
      expect(metrics.reductionPct).toBe(79); // (1050-223)/1050 = 78.76% -> rounds to 79
      expect(metrics.threatsBlocked).toBe(3);
      expect(metrics.elapsedMs).toBe(1240);
    });

    it('handles zero raw content', () => {
      const metrics = calculateMetrics('', 'test', 0, 100);

      expect(metrics.tokensBefore).toBe(0);
      expect(metrics.tokensAfter).toBe(1);
      expect(metrics.reductionPct).toBe(0);
    });

    it('handles sanitized content longer than raw (edge case)', () => {
      const rawContent = 'test'; // 1 token
      const sanitizedContent = 'test with added context'; // 6 tokens

      const metrics = calculateMetrics(rawContent, sanitizedContent, 0, 100);

      expect(metrics.tokensBefore).toBe(1);
      expect(metrics.tokensAfter).toBe(6);
      expect(metrics.reductionPct).toBe(0); // Never negative
    });

    it('handles sanitized equal to raw (no reduction)', () => {
      const content = 'x'.repeat(100);

      const metrics = calculateMetrics(content, content, 0, 100);

      expect(metrics.tokensBefore).toBe(25);
      expect(metrics.tokensAfter).toBe(25);
      expect(metrics.reductionPct).toBe(0);
    });

    it('handles elapsed time of 0ms', () => {
      const metrics = calculateMetrics('test', 'test', 0, 0);

      expect(metrics.elapsedMs).toBe(0);
    });

    it('handles high threat counts', () => {
      const metrics = calculateMetrics('test', 'test', 150, 100);

      expect(metrics.threatsBlocked).toBe(150);
    });

    it('calculates 100% reduction correctly', () => {
      const rawContent = 'x'.repeat(1000); // 250 tokens
      const sanitizedContent = ''; // 0 tokens (all removed)

      const metrics = calculateMetrics(rawContent, sanitizedContent, 10, 500);

      expect(metrics.tokensBefore).toBe(250);
      expect(metrics.tokensAfter).toBe(0);
      expect(metrics.reductionPct).toBe(100);
    });
  });

  describe('formatMetricsHeader', () => {
    it('formats standard metrics correctly', () => {
      const metrics = {
        tokensBefore: 4200,
        tokensAfter: 890,
        reductionPct: 79,
        threatsBlocked: 3,
        elapsedMs: 1240
      };

      const header = formatMetricsHeader(metrics);

      // Verify header contains expected elements
      expect(header).toContain('visus-mcp');
      expect(header).toContain('4,200');
      expect(header).toContain('890');
      expect(header).toContain('79%');
      expect(header).toContain('3 threats blocked');
      expect(header).toContain('1.2s');

      // Verify box drawing characters
      expect(header).toContain('╔');
      expect(header).toContain('╗');
      expect(header).toContain('║');
      expect(header).toContain('╚');
      expect(header).toContain('═');

      // Verify trailing newlines for content separation
      expect(header.endsWith('\n\n')).toBe(true);
    });

    it('formats large numbers with thousand separators', () => {
      const metrics = {
        tokensBefore: 123456,
        tokensAfter: 7890,
        reductionPct: 94,
        threatsBlocked: 5,
        elapsedMs: 2500
      };

      const header = formatMetricsHeader(metrics);

      expect(header).toContain('123,456');
      expect(header).toContain('7,890');
    });

    it('displays zero threats correctly', () => {
      const metrics = {
        tokensBefore: 1000,
        tokensAfter: 900,
        reductionPct: 10,
        threatsBlocked: 0,
        elapsedMs: 500
      };

      const header = formatMetricsHeader(metrics);

      expect(header).toContain('0 threats blocked');
    });

    it('displays single threat correctly (singular)', () => {
      const metrics = {
        tokensBefore: 1000,
        tokensAfter: 900,
        reductionPct: 10,
        threatsBlocked: 1,
        elapsedMs: 500
      };

      const header = formatMetricsHeader(metrics);

      expect(header).toContain('1 threat blocked');
      expect(header).not.toContain('threats'); // Should use singular form
    });

    it('caps display at 99+ threats for overflow', () => {
      const metrics = {
        tokensBefore: 1000,
        tokensAfter: 900,
        reductionPct: 10,
        threatsBlocked: 150,
        elapsedMs: 500
      };

      const header = formatMetricsHeader(metrics);

      expect(header).toContain('99+ threats blocked');
    });

    it('formats milliseconds correctly when < 1000ms', () => {
      const metrics = {
        tokensBefore: 1000,
        tokensAfter: 900,
        reductionPct: 10,
        threatsBlocked: 0,
        elapsedMs: 456
      };

      const header = formatMetricsHeader(metrics);

      expect(header).toContain('456ms');
    });

    it('formats seconds correctly when >= 1000ms', () => {
      const metrics = {
        tokensBefore: 1000,
        tokensAfter: 900,
        reductionPct: 10,
        threatsBlocked: 0,
        elapsedMs: 3456
      };

      const header = formatMetricsHeader(metrics);

      expect(header).toContain('3.5s');
    });

    it('displays "< 1ms" for zero elapsed time', () => {
      const metrics = {
        tokensBefore: 1000,
        tokensAfter: 900,
        reductionPct: 10,
        threatsBlocked: 0,
        elapsedMs: 0
      };

      const header = formatMetricsHeader(metrics);

      expect(header).toContain('< 1ms');
    });

    it('maintains consistent box width across lines', () => {
      const metrics = {
        tokensBefore: 4200,
        tokensAfter: 890,
        reductionPct: 79,
        threatsBlocked: 3,
        elapsedMs: 1240
      };

      const header = formatMetricsHeader(metrics);
      const lines = header.split('\n');

      // Get width of each line (excluding newline)
      const widths = lines.filter((l: string) => l.length > 0).map((l: string) => l.length);

      // All lines should have the same width
      const firstWidth = widths[0];
      widths.forEach((width: number) => {
        expect(width).toBe(firstWidth);
      });
    });

    it('displays 0% reduction correctly', () => {
      const metrics = {
        tokensBefore: 1000,
        tokensAfter: 1000,
        reductionPct: 0,
        threatsBlocked: 0,
        elapsedMs: 100
      };

      const header = formatMetricsHeader(metrics);

      expect(header).toContain('0% reduction');
    });
  });

  describe('shouldShowMetrics', () => {
    const originalEnv = process.env.VISUS_SHOW_METRICS;

    afterEach(() => {
      // Restore original env value
      if (originalEnv === undefined) {
        delete process.env.VISUS_SHOW_METRICS;
      } else {
        process.env.VISUS_SHOW_METRICS = originalEnv;
      }
    });

    it('returns true by default when env var not set', () => {
      delete process.env.VISUS_SHOW_METRICS;
      expect(shouldShowMetrics()).toBe(true);
    });

    it('returns false when VISUS_SHOW_METRICS=false', () => {
      process.env.VISUS_SHOW_METRICS = 'false';
      expect(shouldShowMetrics()).toBe(false);
    });

    it('returns false when VISUS_SHOW_METRICS=FALSE (case insensitive)', () => {
      process.env.VISUS_SHOW_METRICS = 'FALSE';
      expect(shouldShowMetrics()).toBe(false);
    });

    it('returns true when VISUS_SHOW_METRICS=true', () => {
      process.env.VISUS_SHOW_METRICS = 'true';
      expect(shouldShowMetrics()).toBe(true);
    });

    it('returns true when VISUS_SHOW_METRICS=1', () => {
      process.env.VISUS_SHOW_METRICS = '1';
      expect(shouldShowMetrics()).toBe(true);
    });

    it('returns true for any non-"false" value', () => {
      process.env.VISUS_SHOW_METRICS = 'yes';
      expect(shouldShowMetrics()).toBe(true);

      process.env.VISUS_SHOW_METRICS = 'anything';
      expect(shouldShowMetrics()).toBe(true);
    });
  });
});
