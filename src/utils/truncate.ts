/**
 * Token-aware content truncation utility
 *
 * Anthropic MCP Directory enforces a 25,000 token response limit.
 * This utility provides safe truncation with token estimation.
 */

/**
 * Maximum tokens allowed in MCP response (Anthropic Directory limit)
 * We target 24,000 to leave headroom for metadata/JSON structure
 */
const MAX_TOKENS = 24000;

/**
 * Conservative token estimation: 1 token ≈ 4 characters
 * This is a safe approximation that errs on the side of caution
 */
const CHARS_PER_TOKEN = 4;

/**
 * Maximum characters based on token limit
 */
const MAX_CHARS = MAX_TOKENS * CHARS_PER_TOKEN; // 96,000 characters

/**
 * Truncate content if it exceeds the token ceiling
 *
 * @param content Content to potentially truncate
 * @returns Truncated content and metadata
 */
export function truncateContent(content: string): {
  content: string;
  truncated: boolean;
  truncated_at_chars?: number;
} {
  if (content.length <= MAX_CHARS) {
    // Content is within limits
    return {
      content,
      truncated: false
    };
  }

  // Content exceeds limit - truncate with warning message
  const truncatedContent = content.substring(0, MAX_CHARS);
  const warningMessage = `\n\n--- CONTENT TRUNCATED ---\nOriginal length: ${content.length} characters (~${Math.ceil(content.length / CHARS_PER_TOKEN)} tokens)\nTruncated to: ${MAX_CHARS} characters (~${MAX_TOKENS} tokens)\nReason: Anthropic MCP Directory enforces a 25,000 token response limit\n`;

  return {
    content: truncatedContent + warningMessage,
    truncated: true,
    truncated_at_chars: MAX_CHARS
  };
}

/**
 * Estimate token count for a given string
 * Uses conservative 4 chars per token approximation
 *
 * @param text Text to estimate
 * @returns Estimated token count
 */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / CHARS_PER_TOKEN);
}
