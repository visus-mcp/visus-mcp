/**
 * Browser Renderer - Phase 2 Lambda Architecture
 *
 * This module provides web page rendering with three-tier fallback:
 *   1. Lambda renderer (Playwright on AWS Lambda x86_64) - if VISUS_RENDERER_URL set
 *   2. Local undici fetch() - fallback if Lambda unavailable
 *
 * CRITICAL: The sanitizer ALWAYS runs locally. Rendered HTML is returned from
 * Lambda to the local process before Claude sees it. PHI never touches Lateos infrastructure.
 */

import type { BrowserRenderResult, Result } from '../types.js';
import { Ok, Err } from '../types.js';

/**
 * Configuration
 */
const RENDERER_URL = process.env.VISUS_RENDERER_URL;

/**
 * Lambda renderer response types
 */
interface LambdaRenderSuccess {
  html: string;
  title: string;
  status_code: number;
  fetched_at: string;
  render_time_ms: number;
  renderer: 'playwright';
}

interface LambdaRenderError {
  error: string;
  url: string;
  fetched_at: string;
}

/**
 * Log to stderr which renderer is being used
 */
function logRenderer(renderer: 'lambda' | 'fetch', url: string): void {
  console.error(JSON.stringify({
    timestamp: new Date().toISOString(),
    event: 'renderer_selected',
    renderer,
    url,
  }));
}

/**
 * Exponential backoff retry helper
 */
async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries: number,
  initialDelayMs: number
): Promise<T> {
  let lastError: Error;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt < maxRetries - 1) {
        const delayMs = initialDelayMs * Math.pow(2, attempt);
        console.error(JSON.stringify({
          timestamp: new Date().toISOString(),
          event: 'retry_attempt',
          attempt: attempt + 1,
          max_retries: maxRetries,
          delay_ms: delayMs,
          error: lastError.message,
        }));

        await new Promise(resolve => setTimeout(resolve, delayMs));
      }
    }
  }

  throw lastError!;
}

/**
 * Render a page using Lambda renderer
 */
async function renderWithLambda(
  url: string,
  timeout_ms: number
): Promise<Result<BrowserRenderResult, Error>> {
  if (!RENDERER_URL) {
    return Err(new Error('VISUS_RENDERER_URL not configured'));
  }

  logRenderer('lambda', url);

  try {
    // Retry Lambda calls with exponential backoff (3 attempts)
    const response = await retryWithBackoff(async () => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout_ms + 5000);

      try {
        return await fetch(`${RENDERER_URL}/render`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            url,
            timeout_ms,
            content_limit_bytes: 512000, // 500KB default
          }),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeoutId);
      }
    }, 3, 1000); // 3 retries, starting with 1s delay

    const body = await response.json() as LambdaRenderSuccess | LambdaRenderError;

    // Check if response is an error
    if ('error' in body) {
      return Err(new Error(`Lambda renderer error: ${body.error}`));
    }

    // Success response
    return Ok({
      html: body.html,
      title: body.title,
      url,
      contentType: 'text/html', // Lambda renderer defaults to HTML
      text: undefined, // Lambda renderer doesn't extract text
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'lambda_renderer_failed',
      url,
      error: errorMessage,
    }));

    return Err(new Error(`Lambda renderer failed: ${errorMessage}`));
  }
}

/**
 * Render a page using native fetch (fallback)
 */
async function renderWithFetch(
  url: string,
  timeout_ms: number
): Promise<Result<BrowserRenderResult, Error>> {
  logRenderer('fetch', url);

  try {
    // Use AbortController for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout_ms);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'Visus-MCP/0.3.1 (Security-focused web content fetcher; +https://github.com/lateos/visus-mcp)',
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        return Err(new Error(`HTTP ${response.status}: ${response.statusText}`));
      }

      const html = await response.text();

      // Capture Content-Type header
      const contentTypeHeader = response.headers.get('content-type');
      const contentType = contentTypeHeader
        ? contentTypeHeader.split(';')[0].trim()  // Remove charset and other params
        : 'text/html'; // Default to HTML if missing

      // Extract title using regex (simple fallback)
      const titleMatch = html.match(/<title[^>]*>(.*?)<\/title>/i);
      const title = titleMatch ? titleMatch[1].trim() : '';

      return Ok({
        html,
        title,
        url,
        contentType,
        text: undefined,
      });

    } finally {
      clearTimeout(timeoutId);
    }

  } catch (error) {
    if (error instanceof Error) {
      // Handle abort/timeout errors
      if (error.name === 'AbortError') {
        return Err(new Error(`Navigation timeout after ${timeout_ms}ms`));
      }

      // Handle network errors
      if (error.message.includes('ENOTFOUND') || error.message.includes('ECONNREFUSED')) {
        return Err(new Error(`Network error: ${error.message}`));
      }

      return Err(error);
    }

    return Err(new Error(String(error)));
  }
}

/**
 * Render a web page using the best available renderer
 *
 * Rendering strategy:
 *   1. Lambda renderer (if VISUS_RENDERER_URL is set)
 *   2. Undici fetch() (fallback)
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

  // Strategy 1: Try Lambda renderer if configured
  if (RENDERER_URL) {
    const lambdaResult = await renderWithLambda(url, timeout);

    // If Lambda succeeds, return result
    if (lambdaResult.ok) {
      return lambdaResult;
    }

    // Lambda failed, log warning and fall back to fetch
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      event: 'lambda_fallback_to_fetch',
      url,
      lambda_error: lambdaResult.error.message,
    }));
  }

  // Strategy 2: Fallback to undici fetch
  return await renderWithFetch(url, timeout);
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
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout_ms);

    try {
      const response = await fetch(url, {
        method: 'HEAD',
        signal: controller.signal,
      });

      // Consider 2xx and 3xx status codes as accessible
      const isAccessible = (response.status >= 200 && response.status < 400);

      return Ok(isAccessible);

    } finally {
      clearTimeout(timeoutId);
    }

  } catch (error) {
    // URL is not accessible
    return Ok(false);
  }
}

/**
 * Close browser instance and clean up resources
 * (No-op in Lambda architecture - included for compatibility)
 */
export async function closeBrowser(): Promise<void> {
  // No-op: Lambda renderer is stateless, no local browser to close
  // This function exists for backward compatibility with tests
}
