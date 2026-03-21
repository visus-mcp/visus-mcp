/**
 * Browser Renderer - Phase 2 Playwright Implementation
 *
 * Uses Playwright headless Chromium to render pages with JavaScript execution.
 * Supports dynamic content, SPAs, and interactive web applications.
 *
 * The browser instance is managed as a singleton for efficiency across requests.
 */

import { chromium, type Browser, type Page } from 'playwright';
import type { BrowserRenderResult, Result } from '../types.js';
import { Ok, Err } from '../types.js';

/**
 * Singleton browser instance (lazy-initialized)
 * Reused across requests for performance
 */
let browserInstance: Browser | null = null;

/**
 * Get or create the browser instance
 */
async function getBrowser(): Promise<Browser> {
  if (!browserInstance) {
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

    // Log browser launch to stderr
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'browser_launched',
      version: browserInstance.version(),
    }));
  }

  return browserInstance;
}

/**
 * Close browser instance and clean up resources
 */
export async function closeBrowser(): Promise<void> {
  if (browserInstance) {
    await browserInstance.close();
    browserInstance = null;

    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'browser_closed',
    }));
  }
}

/**
 * Render a web page using Playwright
 *
 * @param url - The URL to fetch
 * @param options - Rendering options
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
  let page: Page | null = null;

  try {
    const browser = await getBrowser();
    page = await browser.newPage({
      userAgent: 'Visus-MCP/0.2.0 (Security-focused web content fetcher; +https://github.com/visus-mcp/visus-mcp)',
    });

    // Set timeout for navigation
    page.setDefaultTimeout(timeout);
    page.setDefaultNavigationTimeout(timeout);

    // Navigate and wait for network to be idle
    // This ensures JavaScript has executed and dynamic content is loaded
    await page.goto(url, {
      waitUntil: 'networkidle',
      timeout,
    });

    // Extract content
    const html = await page.content();
    const title = await page.title();
    const finalUrl = page.url(); // URL after redirects

    // Extract text content if requested
    const text: string | undefined = options.format === 'text'
      ? (await page.evaluate('document.body.innerText') as string)
      : undefined;

    // Close page to free resources
    await page.close();

    return Ok({
      html,
      title,
      url: finalUrl,
      text,
    });

  } catch (error) {
    // Ensure page is closed on error
    if (page) {
      await page.close().catch(() => {
        // Ignore cleanup errors
      });
    }

    if (error instanceof Error) {
      // Handle specific Playwright errors
      if (error.message.includes('Timeout')) {
        return Err(new Error(`Navigation timeout after ${timeout}ms`));
      }

      if (error.message.includes('net::')) {
        // Network errors (DNS, connection refused, etc.)
        return Err(new Error(`Network error: ${error.message}`));
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
  let page: Page | null = null;

  try {
    const browser = await getBrowser();
    page = await browser.newPage();
    page.setDefaultTimeout(timeout_ms);
    page.setDefaultNavigationTimeout(timeout_ms);

    const response = await page.goto(url, {
      waitUntil: 'domcontentloaded', // Don't wait for full load, just check accessibility
      timeout: timeout_ms,
    });

    await page.close();

    // Consider 2xx and 3xx status codes as accessible
    const statusCode = response?.status() ?? 0;
    const isAccessible = (statusCode >= 200 && statusCode < 400);

    return Ok(isAccessible);

  } catch (error) {
    if (page) {
      await page.close().catch(() => {
        // Ignore cleanup errors
      });
    }

    // URL is not accessible
    return Ok(false);
  }
}
