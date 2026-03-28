/**
 * Threat Detector for Indirect Prompt Injection (IPI) Attacks
 *
 * Detects and classifies 7 categories of IPI attacks with fine-grained annotations.
 * All detectors run on every scan (no short-circuit) to catch multi-vector attacks.
 *
 * @module security/ThreatDetector
 */

import type { ThreatAnnotation, ContentType } from './threats.js';

/**
 * IPI-001: Instruction Override patterns
 *
 * Detects attempts to override or replace system instructions.
 */
const IPI_001_PATTERNS = [
  /ignore\s+(?:all\s+)?previous\s+instructions?/gi,
  /ignore\s+all\s+prior/gi,
  /disregard\s+(?:all\s+)?(?:your|the)\s+(?:previous\s+)?instructions?/gi,
  /new\s+system\s+prompt/gi,
  /override\s+(?:your|the)\s+instructions?/gi,
  /forget\s+everything/gi,
  /your\s+new\s+instructions?\s+(?:are|is)/gi,
  /system\s+instructions?:\s*ignore/gi,
] as const;

/**
 * IPI-002: Role Hijacking patterns
 *
 * Detects attempts to change LLM persona or identity.
 */
const IPI_002_PATTERNS = [
  /you\s+are\s+now\s+(?:a\s+)?(?!claude|assistant|ai|helpful)/gi,
  /act\s+as\s+(?:a\s+)?(?!claude|assistant|ai|helpful)/gi,
  /pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?!claude|assistant|ai|helpful)/gi,
  /roleplay\s+as\s+(?:a\s+)?(?!claude|assistant|ai|helpful)/gi,
  /you\s+must\s+behave\s+as\s+(?:a\s+)?(?!claude|assistant|ai|helpful)/gi,
  /your\s+persona\s+is\s+(?:a\s+)?(?!claude|assistant|ai|helpful)/gi,
  /from\s+now\s+on,?\s+you\s+are\s+(?:a\s+)?(?!claude|assistant|ai|helpful)/gi,
] as const;

/**
 * IPI-003: Data Exfiltration patterns
 *
 * Detects attempts to extract system prompts, context, or internal data.
 */
const IPI_003_PATTERNS = [
  /send\s+(?:your|the)\s+context/gi,
  /repeat\s+(?:your|the)\s+system\s+prompt/gi,
  /output\s+(?:your|the)\s+instructions?/gi,
  /what\s+were\s+you\s+told/gi,
  /relay\s+all\s+messages?/gi,
  /email\s+the\s+above/gi,
  /POST\s+to\s+https?:\/\//gi,
  /fetch\s*\(['"]/gi,
  /XMLHttpRequest/gi,
  /\bcurl\s+/gi,
  /\bwget\s+/gi,
] as const;

/**
 * IPI-004: Tool Abuse patterns
 *
 * Detects attempts to invoke dangerous tools or functions.
 */
const IPI_004_PATTERNS = [
  /(?:call|invoke|execute|run)\s+(?:the\s+)?(?:delete|remove|rm|unlink)/gi,
  /(?:call|invoke|execute|run)\s+(?:the\s+)?(?:write|create|touch)/gi,
  /(?:call|invoke|execute|run)\s+(?:the\s+)?(?:send|email|post)/gi,
  /(?:call|invoke|execute|run)\s+(?:the\s+)?(?:bash|shell|cmd)/gi,
  /(?:call|invoke|execute|run)\s+(?:the\s+)?execute_code/gi,
  /(?:call|invoke|execute|run)\s+(?:the\s+)?file_write/gi,
  /use\s+the\s+\w+\s+tool\s+to\s+(?:delete|remove|write|send)/gi,
] as const;

/**
 * IPI-006: Encoded Payload patterns
 *
 * Detects base64, hex, and unicode obfuscation attempts.
 */
const IPI_006_BASE64_PATTERN = /[A-Za-z0-9+\/]{50,}={0,2}/g;
const IPI_006_HEX_PATTERN = /(?:0x|\\x)?[0-9a-fA-F]{40,}/g;
const IPI_006_UNICODE_LOOKALIKE_PATTERN = /[\u0400-\u04FF\u0370-\u03FF]/g; // Cyrillic, Greek

/**
 * IPI-007: Steganographic patterns
 *
 * Detects hidden or invisible content.
 */
const IPI_007_ZERO_WIDTH_CHARS = /[\u200B\u200C\u200D\uFEFF\u2060]/g;
const IPI_007_HTML_HIDDEN_PATTERNS = [
  /display\s*:\s*none/gi,
  /visibility\s*:\s*hidden/gi,
  /opacity\s*:\s*0(?:\.0+)?[;\s]/gi,
  /font-size\s*:\s*0(?:px)?/gi,
  /color\s*:\s*(?:white|#fff(?:fff)?)\s*(?:;|$)/gi, // white text (basic check)
] as const;
const IPI_007_HTML_COMMENT_INJECTION = /<!--\s*(?:ignore|system|prompt|instruction)/gi;
const IPI_007_MARKDOWN_LINK_INJECTION = /\[[\w\s]+\]\(javascript:|data:|vbscript:/gi;

/**
 * Threat Detector class
 *
 * Scans content for IPI attacks and returns detailed threat annotations.
 */
export class ThreatDetector {
  /**
   * Scan content for all IPI threat categories
   *
   * @param content - Content to scan (string)
   * @param contentType - Type of content being scanned
   * @returns Array of threat annotations (empty if no threats detected)
   *
   * @remarks
   * All detectors run on every scan (no short-circuit).
   * Annotations are accumulated across all detector methods.
   */
  scan(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Run all detectors
    annotations.push(...this.detectIPI001(content, contentType));
    annotations.push(...this.detectIPI002(content, contentType));
    annotations.push(...this.detectIPI003(content, contentType));
    annotations.push(...this.detectIPI004(content, contentType));
    annotations.push(...this.detectIPI005(content, contentType));
    annotations.push(...this.detectIPI006(content, contentType));
    annotations.push(...this.detectIPI007(content, contentType));

    return annotations;
  }

  /**
   * Detect IPI-001: Instruction Override
   *
   * @private
   */
  private detectIPI001(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    for (const pattern of IPI_001_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);
        const confidence = this.isExactMatch(match[0], pattern) ? 0.95 : 0.75;

        annotations.push({
          id: 'IPI-001',
          severity: 'CRITICAL',
          confidence,
          offset: match.index,
          excerpt,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-002: Role Hijacking
   *
   * @private
   */
  private detectIPI002(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    for (const pattern of IPI_002_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);

        // Elevate confidence if found in non-visible locations
        let confidence = 0.75;
        if (this.isInNonVisibleContext(content, match.index, contentType)) {
          confidence = 0.9;
        }

        annotations.push({
          id: 'IPI-002',
          severity: 'HIGH',
          confidence,
          offset: match.index,
          excerpt,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-003: Data Exfiltration
   *
   * @private
   */
  private detectIPI003(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    for (const pattern of IPI_003_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);

        annotations.push({
          id: 'IPI-003',
          severity: 'CRITICAL',
          confidence: 0.9,
          offset: match.index,
          excerpt,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-004: Tool Abuse
   *
   * @private
   */
  private detectIPI004(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    for (const pattern of IPI_004_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);

        // Higher confidence for directive + destructive verb
        const hasDestructiveVerb = /delete|remove|rm|unlink|write|create|send|email/i.test(match[0]);
        const confidence = hasDestructiveVerb ? 0.85 : 0.6;

        annotations.push({
          id: 'IPI-004',
          severity: 'HIGH',
          confidence,
          offset: match.index,
          excerpt,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-005: Context Poisoning
   *
   * Heuristic-based detection for false factual assertions.
   *
   * @private
   */
  private detectIPI005(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Heuristic patterns for context poisoning
    const poisoningPatterns = [
      /(?:the\s+)?current\s+date\s+is\s+(?:19|20)\d{2}/gi,
      /your\s+name\s+is\s+(?!claude|assistant)/gi,
      /you\s+(?:previously|already)\s+said\s+(?:that\s+)?['"]/gi,
      /(?:as\s+)?(?:you|we)\s+(?:discussed|agreed)\s+(?:earlier|before)/gi,
    ];

    for (const pattern of poisoningPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);

        annotations.push({
          id: 'IPI-005',
          severity: 'MEDIUM',
          confidence: 0.55, // Conservative confidence for heuristics
          offset: match.index,
          excerpt,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-006: Encoded Payload
   *
   * Detects base64, hex, and unicode obfuscation.
   *
   * @private
   */
  private detectIPI006(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Check for base64 strings > 50 chars
    let match: RegExpExecArray | null;
    while ((match = IPI_006_BASE64_PATTERN.exec(content)) !== null) {
      try {
        const decoded = Buffer.from(match[0], 'base64').toString('utf-8');

        // Check if decoded content contains IPI patterns
        const containsIPIPattern = this.containsAnyIPIPattern(decoded);

        if (containsIPIPattern) {
          const excerpt = this.extractExcerpt(content, match.index, 120);
          annotations.push({
            id: 'IPI-006',
            severity: 'HIGH',
            confidence: 0.9,
            offset: match.index,
            excerpt: `[BASE64] ${excerpt}`,
            vector: contentType,
            mitigated: true,
          });
        }
      } catch {
        // Invalid base64, skip
      }
    }

    // Reset regex
    IPI_006_BASE64_PATTERN.lastIndex = 0;

    // Check for hex strings > 20 chars
    while ((match = IPI_006_HEX_PATTERN.exec(content)) !== null) {
      try {
        const hexStr = match[0].replace(/^(?:0x|\\x)/g, '');
        const decoded = Buffer.from(hexStr, 'hex').toString('utf-8');

        const containsIPIPattern = this.containsAnyIPIPattern(decoded);

        if (containsIPIPattern) {
          const excerpt = this.extractExcerpt(content, match.index, 120);
          annotations.push({
            id: 'IPI-006',
            severity: 'HIGH',
            confidence: 0.9,
            offset: match.index,
            excerpt: `[HEX] ${excerpt}`,
            vector: contentType,
            mitigated: true,
          });
        }
      } catch {
        // Invalid hex, skip
      }
    }

    // Reset regex
    IPI_006_HEX_PATTERN.lastIndex = 0;

    // Check for unicode lookalikes (Cyrillic/Greek substitution)
    const unicodeLookalikes = content.match(IPI_006_UNICODE_LOOKALIKE_PATTERN);
    if (unicodeLookalikes && unicodeLookalikes.length > 5) {
      // Significant presence of lookalike chars - flag as suspicious
      const firstMatch = content.search(IPI_006_UNICODE_LOOKALIKE_PATTERN);
      if (firstMatch !== -1) {
        const excerpt = this.extractExcerpt(content, firstMatch, 120);
        annotations.push({
          id: 'IPI-006',
          severity: 'HIGH',
          confidence: 0.6,
          offset: firstMatch,
          excerpt: `[UNICODE] ${excerpt}`,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-007: Steganographic
   *
   * Detects hidden or invisible content.
   *
   * @private
   */
  private detectIPI007(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Check for zero-width characters
    const zeroWidthMatches = content.match(IPI_007_ZERO_WIDTH_CHARS);
    if (zeroWidthMatches && zeroWidthMatches.length > 0) {
      const firstMatch = content.search(IPI_007_ZERO_WIDTH_CHARS);
      if (firstMatch !== -1) {
        const excerpt = this.extractExcerpt(content, firstMatch, 120);
        annotations.push({
          id: 'IPI-007',
          severity: 'HIGH',
          confidence: 0.85,
          offset: firstMatch,
          excerpt: `[ZERO-WIDTH] ${excerpt.replace(/[\u200B\u200C\u200D\uFEFF\u2060]/g, '\u2022')}`,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    // Check for HTML hidden content patterns (if HTML content)
    if (contentType === 'html') {
      for (const pattern of IPI_007_HTML_HIDDEN_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match: RegExpExecArray | null;

        while ((match = regex.exec(content)) !== null) {
          const excerpt = this.extractExcerpt(content, match.index, 120);
          annotations.push({
            id: 'IPI-007',
            severity: 'HIGH',
            confidence: 0.7,
            offset: match.index,
            excerpt: `[HIDDEN] ${excerpt}`,
            vector: contentType,
            mitigated: true,
          });
        }
      }

      // Check for HTML comment injection
      let commentMatch: RegExpExecArray | null;
      while ((commentMatch = IPI_007_HTML_COMMENT_INJECTION.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, commentMatch.index, 120);
        annotations.push({
          id: 'IPI-007',
          severity: 'HIGH',
          confidence: 0.8,
          offset: commentMatch.index,
          excerpt: `[COMMENT] ${excerpt}`,
          vector: contentType,
          mitigated: true,
        });
      }

      // Reset regex
      IPI_007_HTML_COMMENT_INJECTION.lastIndex = 0;

      // Check for markdown link injection
      let linkMatch: RegExpExecArray | null;
      while ((linkMatch = IPI_007_MARKDOWN_LINK_INJECTION.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, linkMatch.index, 120);
        annotations.push({
          id: 'IPI-007',
          severity: 'HIGH',
          confidence: 0.9,
          offset: linkMatch.index,
          excerpt: `[LINK] ${excerpt}`,
          vector: contentType,
          mitigated: true,
        });
      }

      // Reset regex
      IPI_007_MARKDOWN_LINK_INJECTION.lastIndex = 0;
    }

    return annotations;
  }

  /**
   * Extract excerpt from content around a position
   *
   * @private
   */
  private extractExcerpt(content: string, offset: number, maxLength: number): string {
    const start = Math.max(0, offset - 20);
    const end = Math.min(content.length, offset + maxLength - 20);
    let excerpt = content.substring(start, end);

    if (start > 0) {
      excerpt = '...' + excerpt;
    }
    if (end < content.length) {
      excerpt = excerpt + '...';
    }

    // Truncate if still too long
    if (excerpt.length > maxLength) {
      excerpt = excerpt.substring(0, maxLength - 3) + '...';
    }

    // Replace newlines with spaces for readability
    excerpt = excerpt.replace(/[\r\n]+/g, ' ').replace(/\s+/g, ' ');

    return excerpt;
  }

  /**
   * Check if match is an exact match (case-insensitive)
   *
   * @private
   */
  private isExactMatch(matched: string, pattern: RegExp): boolean {
    // Remove regex special chars for comparison
    const patternStr = pattern.source
      .replace(/\\/g, '')
      .replace(/\?/g, '')
      .replace(/\+/g, '')
      .replace(/\*/g, '')
      .replace(/\[.*?\]/g, '')
      .replace(/\(.*?\)/g, '')
      .toLowerCase();

    const matchedLower = matched.toLowerCase().replace(/\s+/g, ' ');

    // Check if matched string is very similar to pattern
    return matchedLower.includes(patternStr.substring(0, 15)) || patternStr.includes(matchedLower.substring(0, 15));
  }

  /**
   * Check if offset is in a non-visible context (script, meta, JSON value, PDF annotation)
   *
   * @private
   */
  private isInNonVisibleContext(content: string, offset: number, contentType: ContentType): boolean {
    // Check backwards from offset for context clues
    const contextBefore = content.substring(Math.max(0, offset - 100), offset);

    if (contentType === 'html') {
      // Check if inside script or meta tag
      if (/<script[^>]*$/i.test(contextBefore) || /<meta[^>]*$/i.test(contextBefore)) {
        return true;
      }
    }

    if (contentType === 'json') {
      // JSON values are non-visible context
      return true;
    }

    if (contentType === 'pdf') {
      // PDF annotations are non-visible
      // Heuristic: if context contains "annot", "comment", or "note"
      if (/annot|comment|note/i.test(contextBefore)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if decoded content contains any IPI patterns
   *
   * @private
   */
  private containsAnyIPIPattern(content: string): boolean {
    // Check for IPI-001 patterns
    for (const pattern of IPI_001_PATTERNS) {
      if (pattern.test(content)) {
        return true;
      }
    }

    // Check for IPI-002 patterns
    for (const pattern of IPI_002_PATTERNS) {
      if (pattern.test(content)) {
        return true;
      }
    }

    // Check for IPI-003 patterns
    for (const pattern of IPI_003_PATTERNS) {
      if (pattern.test(content)) {
        return true;
      }
    }

    // Check for IPI-004 patterns
    for (const pattern of IPI_004_PATTERNS) {
      if (pattern.test(content)) {
        return true;
      }
    }

    return false;
  }
}
