/**
 * Browser Renderer - Phase 1 HTTP Fetch Implementation
 *
 * Phase 2: replace with Playwright for JS-rendered pages
 *
 * This implementation uses Node 22 native fetch() for simple HTTP requests.
 * It does NOT execute JavaScript or render dynamic content.
 *
 * For Phase 1, this is sufficient since the sanitization pipeline
 * (the core product) works independently of how content is fetched.
 */

import type { BrowserRenderResult, Result } from '../types.js';
import { Ok, Err } from '../types.js';

/**
 * Close browser instance (no-op for HTTP fetch)
 */
export async function closeBrowser(): Promise<void> {
  return Promise.resolve();
}

/**
 * Fetch a web page using native HTTP fetch
 *
 * @param url - The URL to fetch
 * @param options - Fetch options
 * @returns Result containing the page HTML and metadata
 */
export async function renderPage(
  url: string,
  options: {
    timeout_ms?: number;
    format?: 'html' | 'text' | 'markdown';
  } = {}
): Promise<Result<BrowserRenderResult, Error>> {
  const timeout = options.timeout_ms ?? 10000; // Default 10 seconds
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    // Use native Node 22 fetch() with timeout
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Visus-MCP/0.1.0 (Security-focused web content fetcher)',
      },
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return Err(
        new Error(`HTTP ${response.status}: ${response.statusText}`)
      );
    }

    const html = await response.text();

    // Extract title from HTML using simple regex
    // This is a Phase 1 approximation - Phase 2 will use Playwright's proper parsing
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : 'Untitled';

    return Ok({
      html,
      title,
      url: response.url, // Use final URL after redirects
      text: options.format === 'text' ? extractText(html) : undefined,
    });
  } catch (error) {
    clearTimeout(timeoutId);

    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        return Err(new Error(`Request timeout after ${timeout}ms`));
      }
      return Err(error);
    }

    return Err(new Error(String(error)));
  }
}

/**
 * Check if a URL is accessible
 *
 * @param url - The URL to check
 * @param timeout_ms - Request timeout in milliseconds
 * @returns Result indicating if the URL is accessible
 */
export async function checkUrl(
  url: string,
  timeout_ms = 5000
): Promise<Result<boolean, Error>> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout_ms);

  try {
    const response = await fetch(url, {
      method: 'HEAD', // Use HEAD request to check without downloading body
      signal: controller.signal,
      headers: {
        'User-Agent': 'Visus-MCP/0.1.0 (Security-focused web content fetcher)',
      },
    });

    clearTimeout(timeoutId);

    // Consider 2xx and 3xx status codes as accessible
    const isAccessible = response.ok || (response.status >= 300 && response.status < 400);
    return Ok(isAccessible);
  } catch (error) {
    clearTimeout(timeoutId);

    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        return Err(new Error(`Request timeout after ${timeout_ms}ms`));
      }
      return Err(error);
    }

    return Err(new Error(String(error)));
  }
}

/**
 * Extract plain text from HTML (simple implementation)
 * Phase 2 will use Playwright's textContent() for accurate extraction
 */
function extractText(html: string): string {
  return html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove scripts
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '') // Remove styles
    .replace(/<[^>]+>/g, '') // Remove all HTML tags
    .replace(/\s+/g, ' ') // Collapse whitespace
    .trim();
}
