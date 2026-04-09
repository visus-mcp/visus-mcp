/**
 * Token Metrics Utility
 *
 * Provides token estimation, metrics calculation, and formatted header generation
 * for displaying token reduction statistics in tool responses.
 *
 * Supports the v0.12.0 token metrics feature - shows before/after token counts,
 * reduction percentage, threats blocked, and elapsed time.
 */

/**
 * Token metrics data structure
 */
export interface TokenMetrics {
  tokensBefore: number;
  tokensAfter: number;
  reductionPct: number;
  threatsBlocked: number;
  elapsedMs: number;
}

/**
 * Estimates token count from character count using GPT-family approximation.
 *
 * Formula: tokens ≈ characters / 4 (rounded up)
 *
 * This is a standard approximation for GPT-family models. For production
 * use cases requiring exact token counts, consider using tiktoken or similar.
 *
 * @param text Input text to estimate tokens for
 * @returns Estimated token count
 */
export function estimateTokens(text: string): number {
  if (!text || text.trim().length === 0) {
    return 0;
  }
  return Math.ceil(text.length / 4);
}

/**
 * Calculates token metrics from raw and sanitized content.
 *
 * Handles edge cases:
 * - Empty raw content → tokensBefore = 0
 * - Sanitized longer than raw (shouldn't happen) → reductionPct = 0
 * - Ensures reduction percentage is never negative
 *
 * @param rawContent Original content before sanitization
 * @param sanitizedContent Content after sanitization
 * @param threatsBlocked Number of threats detected and blocked
 * @param elapsedMs Elapsed time in milliseconds
 * @returns TokenMetrics object
 */
export function calculateMetrics(
  rawContent: string,
  sanitizedContent: string,
  threatsBlocked: number,
  elapsedMs: number
): TokenMetrics {
  const tokensBefore = estimateTokens(rawContent);
  const tokensAfter = estimateTokens(sanitizedContent);

  // Calculate reduction percentage, ensuring it's never negative
  let reductionPct = 0;
  if (tokensBefore > 0 && tokensAfter < tokensBefore) {
    reductionPct = Math.round(((tokensBefore - tokensAfter) / tokensBefore) * 100);
  }

  return {
    tokensBefore,
    tokensAfter,
    reductionPct,
    threatsBlocked,
    elapsedMs
  };
}

/**
 * Formats elapsed time for display.
 *
 * - < 1ms → "< 1ms"
 * - < 1000ms → "123ms"
 * - ≥ 1000ms → "1.2s"
 *
 * @param ms Elapsed time in milliseconds
 * @returns Formatted time string
 */
function formatElapsedTime(ms: number): string {
  if (ms === 0) {
    return '< 1ms';
  }
  if (ms < 1000) {
    return `${Math.round(ms)}ms`;
  }
  return `${(ms / 1000).toFixed(1)}s`;
}

/**
 * Formats a number with locale-specific thousand separators.
 *
 * Examples: 4200 → "4,200", 890 → "890"
 *
 * @param num Number to format
 * @returns Formatted number string
 */
function formatNumber(num: number): string {
  return num.toLocaleString('en-US');
}

/**
 * Formats threats blocked count with overflow handling.
 *
 * - 0-99 threats → exact count
 * - ≥ 100 threats → "99+"
 *
 * @param count Number of threats blocked
 * @returns Formatted threats string
 */
function formatThreats(count: number): string {
  if (count > 99) {
    return '99+ threats blocked';
  }
  const plural = count === 1 ? 'threat' : 'threats';
  return `${count} ${plural} blocked`;
}

/**
 * Formats token metrics as a visually-structured header box.
 *
 * Output format:
 * ```
 * ╔═ visus-mcp ═══════════════════════════════╗
 * ║ 4,200 → 890 tokens · 79% reduction        ║
 * ║ 3 threats blocked · fetch 1.2s            ║
 * ╚════════════════════════════════════════════╝
 * ```
 *
 * Box width is dynamically sized to fit content. Uses Unicode box-drawing
 * characters for clean visual appearance.
 *
 * @param metrics Token metrics to format
 * @returns Formatted header string (includes trailing newline for separation)
 */
export function formatMetricsHeader(metrics: TokenMetrics): string {
  const { tokensBefore, tokensAfter, reductionPct, threatsBlocked, elapsedMs } = metrics;

  // Build content lines
  const line1 = `${formatNumber(tokensBefore)} → ${formatNumber(tokensAfter)} tokens · ${reductionPct}% reduction`;
  const line2 = `${formatThreats(threatsBlocked)} · fetch ${formatElapsedTime(elapsedMs)}`;

  // Calculate box width (longest line + padding)
  const maxContentLength = Math.max(line1.length, line2.length);
  const boxWidth = maxContentLength + 2; // 1 space padding on each side

  // Build header line with title
  const title = ' visus-mcp ';
  const headerFillLength = boxWidth - title.length;
  const headerFill = '═'.repeat(Math.max(0, headerFillLength));
  const topLine = `╔${headerFill}${title}╗`;

  // Build content lines with padding
  const padLine = (text: string): string => {
    const padding = ' '.repeat(Math.max(0, boxWidth - text.length - 2)); // -2 for the two padding spaces
    return `║ ${text}${padding} ║`;
  };

  const contentLine1 = padLine(line1);
  const contentLine2 = padLine(line2);

  // Build bottom line
  const bottomLine = `╚${'═'.repeat(boxWidth)}╝`;

  // Assemble box with trailing newline for separation from content
  return `${topLine}\n${contentLine1}\n${contentLine2}\n${bottomLine}\n\n`;
}

/**
 * Checks if token metrics should be displayed based on environment configuration.
 *
 * Defaults to true. Can be disabled by setting VISUS_SHOW_METRICS=false.
 *
 * @returns true if metrics should be displayed, false otherwise
 */
export function shouldShowMetrics(): boolean {
  const envValue = process.env.VISUS_SHOW_METRICS;
  if (envValue === undefined) {
    return true; // Default: show metrics
  }
  return envValue.toLowerCase() !== 'false';
}
