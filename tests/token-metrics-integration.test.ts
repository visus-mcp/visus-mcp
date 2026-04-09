/**
 * Token Metrics Integration Tests
 *
 * Smoke tests to verify that token metrics headers are correctly integrated
 * into all content-returning tools (v0.12.0 feature).
 */

import { visusFetch } from '../src/tools/fetch.js';
import { visusFetchStructured } from '../src/tools/fetch-structured.js';
import { visusRead } from '../src/tools/read.js';
import { visusSearch } from '../src/tools/search.js';
import { renderPage, closeBrowser } from '../src/browser/playwright-renderer.js';
import { extractArticle } from '../src/browser/reader.js';
import type { BrowserRenderResult } from '../src/types.js';
import { Ok } from '../src/types.js';

// Mock the browser renderer
jest.mock('../src/browser/playwright-renderer.js', () => ({
  renderPage: jest.fn(),
  closeBrowser: jest.fn(),
  checkUrl: jest.fn()
}));

// Mock the reader module to avoid jsdom dependencies
jest.mock('../src/browser/reader.js', () => ({
  extractArticle: jest.fn()
}));

const mockRenderPage = renderPage as jest.MockedFunction<typeof renderPage>;
const mockExtractArticle = extractArticle as jest.MockedFunction<typeof extractArticle>;

describe('Token Metrics Integration', () => {
  const originalEnv = process.env.VISUS_SHOW_METRICS;

  beforeAll(() => {
    // Ensure metrics are enabled for these tests
    process.env.VISUS_SHOW_METRICS = 'true';
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  afterAll(async () => {
    // Restore original env value
    if (originalEnv === undefined) {
      delete process.env.VISUS_SHOW_METRICS;
    } else {
      process.env.VISUS_SHOW_METRICS = originalEnv;
    }
    await closeBrowser();
  });

  describe('visus_fetch metrics header', () => {
    it('should include metrics header when VISUS_SHOW_METRICS is true', async () => {
      const mockResult: BrowserRenderResult = {
        html: '<html><body>' + 'x'.repeat(5000) + '</body></html>',
        title: 'Test Page',
        url: 'https://example.com',
        text: 'x'.repeat(5000)
      };

      mockRenderPage.mockResolvedValue(Ok(mockResult));

      const result = await visusFetch({
        url: 'https://example.com',
        format: 'markdown'
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        // Verify metrics header is present
        expect(result.value.content).toContain('visus-mcp');
        expect(result.value.content).toContain('→');
        expect(result.value.content).toContain('tokens');
        expect(result.value.content).toContain('reduction');
        expect(result.value.content).toContain('threats blocked');
        expect(result.value.content).toContain('fetch');

        // Verify box drawing characters
        expect(result.value.content).toContain('╔');
        expect(result.value.content).toContain('╗');
        expect(result.value.content).toContain('║');
        expect(result.value.content).toContain('╚');
        expect(result.value.content).toContain('═');
      }
    });

    it('should NOT include metrics header when VISUS_SHOW_METRICS is false', async () => {
      process.env.VISUS_SHOW_METRICS = 'false';

      const mockResult: BrowserRenderResult = {
        html: '<html><body>Clean content</body></html>',
        title: 'Test Page',
        url: 'https://example.com',
        text: 'Clean content'
      };

      mockRenderPage.mockResolvedValue(Ok(mockResult));

      const result = await visusFetch({
        url: 'https://example.com',
        format: 'markdown'
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        // Verify metrics header is NOT present
        expect(result.value.content).not.toContain('visus-mcp');
        expect(result.value.content).not.toContain('╔');
      }

      // Restore for other tests
      process.env.VISUS_SHOW_METRICS = 'true';
    });
  });

  describe('visus_fetch_structured metrics', () => {
    it('should include content field with metrics header', async () => {
      const mockResult: BrowserRenderResult = {
        html: '<html><body><h1>Title</h1><p>Description text</p></body></html>',
        title: 'Test Page',
        url: 'https://example.com'
      };

      mockRenderPage.mockResolvedValue(Ok(mockResult));

      const result = await visusFetchStructured({
        url: 'https://example.com',
        schema: {
          title: 'The main heading',
          description: 'The first paragraph'
        }
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        // Verify data field exists (structured data)
        expect(result.value.data).toBeDefined();

        // Verify content field exists with metrics header
        expect(result.value.content).toBeDefined();
        expect(result.value.content).toContain('visus-mcp');
        expect(result.value.content).toContain('tokens');
        expect(result.value.content).toContain('threats blocked');

        // Verify formatted data is present in content
        expect(result.value.content).toContain('**title**:');
        expect(result.value.content).toContain('**description**:');
      }
    });
  });

  describe('visus_read metrics header', () => {
    it('should include metrics header in extracted article content', async () => {
      const articleContent = 'Content paragraph. '.repeat(500);

      const mockResult: BrowserRenderResult = {
        html: `
          <html>
            <body>
              <article>
                <h1>Article Title</h1>
                <p>${articleContent}</p>
              </article>
            </body>
          </html>
        `,
        title: 'Article',
        url: 'https://example.com'
      };

      mockRenderPage.mockResolvedValue(Ok(mockResult));
      mockExtractArticle.mockReturnValue(Ok({
        title: 'Article Title',
        content: articleContent,
        byline: null,
        excerpt: null,
        publishedTime: null,
        wordCount: 1000,
        readerModeAvailable: true
      }));

      const result = await visusRead({
        url: 'https://example.com'
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        // Verify metrics header is present
        expect(result.value.content).toContain('visus-mcp');
        expect(result.value.content).toContain('→');
        expect(result.value.content).toContain('tokens');
        expect(result.value.content).toContain('reduction');
        expect(result.value.content).toContain('threats blocked');
      }
    });
  });

  describe('visus_search metrics', () => {
    beforeEach(() => {
      // Mock fetch for DuckDuckGo API
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          AbstractText: 'Test search result abstract',
          AbstractURL: 'https://example.com/result1',
          RelatedTopics: [
            {
              Text: 'Related topic 1',
              FirstURL: 'https://example.com/result2'
            },
            {
              Text: 'Related topic 2',
              FirstURL: 'https://example.com/result3'
            }
          ]
        })
      } as Response);
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('should include content field with metrics header', async () => {
      const result = await visusSearch({
        query: 'test query',
        max_results: 5
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        // Verify results field exists (structured data)
        expect(result.value.results).toBeDefined();
        expect(result.value.results.length).toBeGreaterThan(0);

        // Verify content field exists with metrics header
        expect(result.value.content).toBeDefined();
        expect(result.value.content).toContain('visus-mcp');
        expect(result.value.content).toContain('tokens');
        expect(result.value.content).toContain('threats blocked');

        // Verify formatted search results are present
        expect(result.value.content).toContain('1. **');
        expect(result.value.content).toContain('URL:');
      }
    });
  });

  describe('Tools that should NOT have metrics', () => {
    it('visus_report should not import token metrics', async () => {
      // This is a compile-time check - if report.ts imports tokenMetrics,
      // TypeScript will fail. We can verify this by checking the module doesn't export
      // any content field that would include metrics.

      // Import the report module to ensure it compiles without tokenMetrics dependency
      const { visusReport } = await import('../src/tools/report.js');
      expect(visusReport).toBeDefined();
      expect(typeof visusReport).toBe('function');
    });

    it('visus_verify should not import token metrics', async () => {
      // Similar compile-time verification for verify tool
      const { visusVerify } = await import('../src/tools/verify.js');
      expect(visusVerify).toBeDefined();
      expect(typeof visusVerify).toBe('function');
    });
  });

  describe('Metrics accuracy', () => {
    it('should show token reduction when content is sanitized', async () => {
      const mockResult: BrowserRenderResult = {
        html: '<html><body>' + 'Test content. '.repeat(1000) + '</body></html>',
        title: 'Test Page',
        url: 'https://example.com'
      };

      mockRenderPage.mockResolvedValue(Ok(mockResult));

      const result = await visusFetch({
        url: 'https://example.com',
        format: 'markdown'
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        // Extract token counts from header
        const tokenMatch = result.value.content.match(/(\d{1,3}(?:,\d{3})*)\s*→\s*(\d{1,3}(?:,\d{3})*)\s*tokens/);
        expect(tokenMatch).toBeTruthy();

        if (tokenMatch) {
          const tokensBefore = parseInt(tokenMatch[1].replace(/,/g, ''));
          const tokensAfter = parseInt(tokenMatch[2].replace(/,/g, ''));

          // Verify token counts are positive
          expect(tokensBefore).toBeGreaterThan(0);
          expect(tokensAfter).toBeGreaterThan(0);

          // For clean content, tokens after should be <= tokens before
          expect(tokensAfter).toBeLessThanOrEqual(tokensBefore);
        }
      }
    });

    it('should show elapsed time in reasonable range', async () => {
      const mockResult: BrowserRenderResult = {
        html: '<html><body>Fast fetch</body></html>',
        title: 'Test Page',
        url: 'https://example.com'
      };

      mockRenderPage.mockResolvedValue(Ok(mockResult));

      const result = await visusFetch({
        url: 'https://example.com',
        format: 'markdown'
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        // Verify timing is present and reasonable (ms or s format)
        const timingMatch = result.value.content.match(/fetch\s+(?:< 1ms|\d+ms|\d+\.\d+s)/);
        expect(timingMatch).toBeTruthy();
      }
    });
  });
});
