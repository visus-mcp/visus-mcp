/**
 * Reader Mode - Mozilla Readability Integration
 *
 * Extracts clean article content from web pages using Mozilla's Readability.js.
 * This module strips navigation, ads, and boilerplate to return main article content.
 *
 * CRITICAL: Content extraction happens BEFORE sanitization. The pipeline is:
 * Playwright renders → Readability extracts → Sanitizer runs → Token ceiling applied
 */

import { Readability } from '@mozilla/readability';
import { JSDOM } from 'jsdom';
import type { Result } from '../types.js';
import { Ok, Err } from '../types.js';

/**
 * Result from reader mode extraction
 */
export interface ReaderResult {
  title: string;
  byline: string | null;           // Author
  publishedTime: string | null;     // ISO timestamp or null
  content: string;                  // Extracted text content
  excerpt: string | null;           // Short summary
  wordCount: number;                // Estimated word count
  readerModeAvailable: boolean;     // True if Readability succeeded
}

/**
 * Extract clean article content using Mozilla Readability
 *
 * @param html - Rendered HTML from Playwright
 * @param url - Original URL (required for relative link resolution)
 * @returns Result containing extracted article or fallback to full HTML
 */
export function extractArticle(
  html: string,
  url: string
): Result<ReaderResult, Error> {
  try {
    // Parse HTML with jsdom
    const dom = new JSDOM(html, { url });
    const document = dom.window.document;

    // Attempt extraction with Readability
    const reader = new Readability(document);
    const article = reader.parse();

    // If Readability succeeds, return extracted content
    if (article && article.textContent) {
      const wordCount = estimateWordCount(article.textContent);

      return Ok({
        title: article.title || 'Untitled',
        byline: article.byline || null,
        publishedTime: article.publishedTime || null,
        content: article.textContent,
        excerpt: article.excerpt || null,
        wordCount,
        readerModeAvailable: true
      });
    }

    // Readability failed - fallback to raw text extraction
    const fallbackText = extractFallbackText(document);
    const wordCount = estimateWordCount(fallbackText);

    // Extract title from <title> tag as fallback
    const titleElement = document.querySelector('title');
    const fallbackTitle = titleElement?.textContent?.trim() || 'Untitled';

    return Ok({
      title: fallbackTitle,
      byline: null,
      publishedTime: null,
      content: fallbackText,
      excerpt: null,
      wordCount,
      readerModeAvailable: false
    });

  } catch (error) {
    return Err(
      error instanceof Error
        ? error
        : new Error(`Reader extraction failed: ${String(error)}`)
    );
  }
}

/**
 * Estimate word count from text content
 *
 * @param text - Text content to count
 * @returns Estimated word count
 */
function estimateWordCount(text: string): number {
  if (!text || text.trim().length === 0) {
    return 0;
  }

  // Split on whitespace and filter out empty strings
  const words = text.trim().split(/\s+/).filter(word => word.length > 0);
  return words.length;
}

/**
 * Fallback text extraction when Readability fails
 *
 * Extracts visible text from the page, skipping script/style elements.
 *
 * @param document - JSDOM document
 * @returns Extracted text content
 */
function extractFallbackText(document: Document): string {
  // Remove script and style elements
  const scripts = document.querySelectorAll('script, style, noscript');
  scripts.forEach(el => el.remove());

  // Extract body text
  const bodyText = document.body?.textContent || '';

  // Clean up whitespace
  return bodyText
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0)
    .join('\n');
}
