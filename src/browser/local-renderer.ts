/**
 * Local Playwright Renderer
 *
 * Fallback renderer that uses local Playwright chromium when:
 * - VISUS_RENDERER_URL is not set (no Lambda available)
 * - Native fetch() fails with SSL or network errors
 *
 * This ensures robust web rendering even in environments with SSL issues
 * (e.g., macOS subprocess environments).
 */

import { chromium, type Browser, type Page } from 'playwright';
import type { BrowserRenderResult, Result } from '../types.js';
import { Ok, Err } from '../types.js';

let browserInstance: Browser | null = null;

/**
 * Get or create a browser instance (singleton pattern for performance)
 */
async function getBrowser(): Promise<Browser> {
  if (!browserInstance || !browserInstance.isConnected()) {
    browserInstance = await chromium.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--disable-gpu',
      ],
    });
  }
  return browserInstance;
}

/**
 * Fetch and render a web page using local Playwright chromium
 *
 * @param url - The URL to fetch
 * @param timeoutMs - Request timeout in milliseconds
 * @returns Result containing the page HTML and metadata
 */
export async function fetchWithPlaywright(
  url: string,
  timeoutMs: number
): Promise<Result<BrowserRenderResult, Error>> {
  let page: Page | null = null;

  try {
    const browser = await getBrowser();
    page = await browser.newPage({
      userAgent: 'Visus-MCP/0.12.0 (Security-focused web content fetcher; +https://github.com/visus-mcp/visus-mcp)',
    });

    // Set timeout for navigation
    page.setDefaultTimeout(timeoutMs);

    // Navigate to URL and wait for network idle
    await page.goto(url, {
      waitUntil: 'networkidle',
      timeout: timeoutMs,
    });

    // Extract content
    const html = await page.content();
    const title = await page.title();

    // Get content type from response headers if available
    const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    const contentTypeHeader = response?.headers()['content-type'];
    const contentType = contentTypeHeader
      ? contentTypeHeader.split(';')[0].trim()
      : 'text/html';

    return Ok({
      html,
      title,
      url,
      contentType,
      text: undefined,
    });

  } catch (error) {
    if (error instanceof Error) {
      // Handle timeout errors
      if (error.message.includes('Timeout') || error.message.includes('timeout')) {
        return Err(new Error(`Navigation timeout after ${timeoutMs}ms`));
      }

      // Handle navigation errors
      if (error.message.includes('net::ERR_')) {
        return Err(new Error(`Network error: ${error.message}`));
      }

      return Err(error);
    }

    return Err(new Error(String(error)));

  } finally {
    // Always close the page to free resources
    if (page) {
      await page.close().catch(() => {
        // Ignore close errors
      });
    }
  }
}

/**
 * Close the browser instance and clean up resources
 * Call this when shutting down the MCP server
 */
export async function closeBrowser(): Promise<void> {
  if (browserInstance) {
    await browserInstance.close().catch(() => {
      // Ignore close errors
    });
    browserInstance = null;
  }
}
