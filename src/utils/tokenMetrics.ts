// STUB: auto-generated to unblock build
// Missing source not yet pushed to GitHub
// Replace with real implementation before production use

/**
 * Token metrics result structure
 */
export interface TokenMetricsResult {
  raw_tokens: number;
  sanitized_tokens: number;
  reduction_pct: number;
  threats_blocked: number;
  elapsed_ms: number;
}

/**
 * Check if metrics should be shown in output
 *
 * @returns false - metrics header is disabled by default
 */
export function shouldShowMetrics(): boolean {
  return false;
}

/**
 * Calculate token metrics from content transformation
 *
 * @param _rawContent - Original content (unused in stub)
 * @param _sanitizedContent - Sanitized content (unused in stub)
 * @param _threatsBlocked - Number of threats blocked (unused in stub)
 * @param _elapsedMs - Elapsed time in milliseconds (unused in stub)
 * @returns Zero-valued metrics result
 */
export function calculateMetrics(
  _rawContent: string,
  _sanitizedContent: string,
  _threatsBlocked: number,
  _elapsedMs: number
): TokenMetricsResult {
  return {
    raw_tokens: 0,
    sanitized_tokens: 0,
    reduction_pct: 0,
    threats_blocked: 0,
    elapsed_ms: 0,
  };
}

/**
 * Format metrics as a header string
 *
 * @param _metrics - Metrics to format (unused in stub)
 * @returns Empty string
 */
export function formatMetricsHeader(_metrics: TokenMetricsResult): string {
  return '';
}
