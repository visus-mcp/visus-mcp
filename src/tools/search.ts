/**
 * Visus Search Tool - Safe Web Search
 *
 * Queries DuckDuckGo's Instant Answer API and sanitizes all results
 * before returning them to the LLM.
 *
 * SECURITY: Every search result snippet and title passes through the
 * sanitization pipeline. This prevents prompt injection via search results.
 */

import { sanitize, sanitizeWithProof } from '../sanitizer/index.js';
import { generateThreatReport } from '../sanitizer/threat-reporter.js';
import type { VisusSearchInput, VisusSearchOutput, Result } from '../types.js';
import { Ok, Err } from '../types.js';

/**
 * DuckDuckGo API Response Types
 */
interface DuckDuckGoRelatedTopic {
  Text?: string;
  FirstURL?: string;
}

interface DuckDuckGoResponse {
  AbstractText?: string;
  AbstractURL?: string;
  RelatedTopics?: Array<DuckDuckGoRelatedTopic | { Topics: DuckDuckGoRelatedTopic[] }>;
}

/**
 * Search the web via DuckDuckGo and return sanitized results
 *
 * @param input Search query and options
 * @returns Sanitized search results with injection detection metadata
 */
export async function visusSearch(input: VisusSearchInput): Promise<Result<VisusSearchOutput, Error>> {
  // Validate input
  if (!input.query || typeof input.query !== 'string' || input.query.trim().length === 0) {
    return Err(new Error('query must be a non-empty string'));
  }

  // Enforce max_results cap
  const maxResults = Math.min(input.max_results ?? 5, 10);

  try {
    // Call DuckDuckGo Instant Answer API
    const query = encodeURIComponent(input.query.trim());
    const apiUrl = `https://api.duckduckgo.com/?q=${query}&format=json&no_redirect=1&no_html=1`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    let response: Response;
    try {
      response = await fetch(apiUrl, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'visus-mcp/0.3.0 (https://github.com/lateos/visus-mcp)'
        }
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      return Ok({
        query: input.query,
        result_count: 0,
        sanitized: true,
        results: [],
        total_injections_removed: 0,
        message: `Search unavailable (HTTP ${response.status})`
      });
    }

    const data = await response.json() as DuckDuckGoResponse;

    // Extract results from DuckDuckGo response
    const rawResults: Array<{ title: string; url: string; snippet: string }> = [];

    // Add AbstractText as first result if present
    if (data.AbstractText && data.AbstractURL) {
      rawResults.push({
        title: extractTitle(data.AbstractText),
        url: data.AbstractURL,
        snippet: data.AbstractText
      });
    }

    // Extract from RelatedTopics
    if (data.RelatedTopics) {
      for (const topic of data.RelatedTopics) {
        // Handle both direct topics and nested topic groups
        if ('Topics' in topic && Array.isArray(topic.Topics)) {
          // Nested topics group
          for (const nestedTopic of topic.Topics) {
            if (nestedTopic.Text && nestedTopic.FirstURL) {
              rawResults.push({
                title: extractTitle(nestedTopic.Text),
                url: nestedTopic.FirstURL,
                snippet: nestedTopic.Text
              });
            }
          }
        } else if ('Text' in topic && topic.Text && topic.FirstURL) {
          // Direct topic
          rawResults.push({
            title: extractTitle(topic.Text),
            url: topic.FirstURL,
            snippet: topic.Text
          });
        }

        // Stop if we've collected enough results
        if (rawResults.length >= maxResults) {
          break;
        }
      }
    }

    // Filter out results with empty URLs and limit to max_results
    const validResults = rawResults
      .filter(r => r.url && r.url.trim().length > 0)
      .slice(0, maxResults);

    // If no results found, return empty array with message
    if (validResults.length === 0) {
      return Ok({
        query: input.query,
        result_count: 0,
        sanitized: true,
        results: [],
        total_injections_removed: 0,
        message: 'No results found'
      });
    }

    // Generate cryptographic proof for the entire search result batch
    const combinedRawContent = validResults.map(r => `${r.title}\n${r.snippet}`).join('\n\n');
    const batchProof = await sanitizeWithProof(
      combinedRawContent,
      `duckduckgo://search?q=${encodeURIComponent(input.query)}`,
      'visus_search',
      '1.0.0'
    );

    // Sanitize each result individually (for granular detection)
    const sanitizedResults = [];
    const allPatternsDetected = new Set<string>();
    let totalInjectionsRemoved = 0;
    let totalPIIRedacted = 0;

    for (const result of validResults) {
      // Sanitize title
      const titleSanitization = sanitize(result.title);

      // Sanitize snippet
      const snippetSanitization = sanitize(result.snippet);

      const injectionsRemoved =
        titleSanitization.sanitization.patterns_detected.length +
        snippetSanitization.sanitization.patterns_detected.length;

      const piiRedacted =
        titleSanitization.sanitization.pii_types_redacted.length +
        snippetSanitization.sanitization.pii_types_redacted.length;

      totalInjectionsRemoved += injectionsRemoved;
      totalPIIRedacted += piiRedacted;

      // Collect all patterns detected across all results
      titleSanitization.sanitization.patterns_detected.forEach(p => allPatternsDetected.add(p));
      snippetSanitization.sanitization.patterns_detected.forEach(p => allPatternsDetected.add(p));

      sanitizedResults.push({
        title: titleSanitization.content,
        url: result.url,
        snippet: snippetSanitization.content,
        injections_removed: injectionsRemoved,
        pii_redacted: piiRedacted
      });
    }

    // Generate aggregated threat report for all search results
    const threatReport = generateThreatReport({
      patterns_detected: Array.from(allPatternsDetected),
      pii_redacted: totalPIIRedacted,
      source_url: `DuckDuckGo Search: ${input.query}`
    });

    return Ok({
      query: input.query,
      result_count: sanitizedResults.length,
      sanitized: true,
      results: sanitizedResults,
      total_injections_removed: totalInjectionsRemoved,
      // Include threat_report only if findings exist
      ...(threatReport && { threat_report: threatReport }),
      // Include cryptographic proof header (EU AI Act Art. 13 Transparency)
      ...batchProof.proofHeader
    });

  } catch (error) {
    // Handle timeout or network errors
    if (error instanceof Error && error.name === 'AbortError') {
      return Ok({
        query: input.query,
        result_count: 0,
        sanitized: true,
        results: [],
        total_injections_removed: 0,
        message: 'Search unavailable (timeout)'
      });
    }

    return Ok({
      query: input.query,
      result_count: 0,
      sanitized: true,
      results: [],
      total_injections_removed: 0,
      message: `Search unavailable: ${error instanceof Error ? error.message : String(error)}`
    });
  }
}

/**
 * Extract title from text (first sentence or up to 80 chars)
 */
function extractTitle(text: string): string {
  // Try to find first sentence
  const firstSentenceMatch = text.match(/^[^.!?]+[.!?]/);
  if (firstSentenceMatch) {
    const sentence = firstSentenceMatch[0].trim();
    if (sentence.length <= 80) {
      return sentence;
    }
  }

  // Fallback to first 80 chars
  if (text.length <= 80) {
    return text.trim();
  }

  return text.substring(0, 77).trim() + '...';
}

/**
 * Tool definition for MCP registration
 */
export const visusSearchToolDefinition = {
  name: 'visus_search',
  title: 'Search the Web (Sanitized)',
  description: 'Searches the web via DuckDuckGo and returns sanitized results with prompt injection and PII removed before reaching the LLM. Use before visus_fetch or visus_read to safely discover and then read pages.',
  inputSchema: {
    type: 'object',
    properties: {
      query: {
        type: 'string',
        description: 'Search query'
      },
      max_results: {
        type: 'number',
        description: 'Maximum number of results to return (default: 5, max: 10)',
        default: 5
      }
    },
    required: ['query']
  },
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true
};
