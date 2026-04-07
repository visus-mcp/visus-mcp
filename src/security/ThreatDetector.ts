/**
 * Threat Detector for Indirect Prompt Injection (IPI) Attacks
 *
 * Detects and classifies 18 categories of IPI attacks with fine-grained annotations.
 * All detectors run on every scan (no short-circuit) to catch multi-vector attacks.
 *
 * Dual-stage detection:
 * - Raw HTML stage: IPI-011, IPI-012 (via scanRawHtml)
 * - Text stage: IPI-001 through IPI-010, IPI-013 through IPI-018 (via scan)
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
   * Scan content for all IPI threat categories (text stage)
   *
   * @param content - Content to scan (string)
   * @param contentType - Type of content being scanned
   * @returns Array of threat annotations (empty if no threats detected)
   *
   * @remarks
   * All detectors run on every scan (no short-circuit).
   * Annotations are accumulated across all detector methods.
   * This runs on extracted text - for raw HTML detection, use scanRawHtml().
   */
  scan(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Run all text-stage detectors
    annotations.push(...this.detectIPI001(content, contentType));
    annotations.push(...this.detectIPI002(content, contentType));
    annotations.push(...this.detectIPI003(content, contentType));
    annotations.push(...this.detectIPI004(content, contentType));
    annotations.push(...this.detectIPI005(content, contentType));
    annotations.push(...this.detectIPI006(content, contentType));
    annotations.push(...this.detectIPI007(content, contentType));
    annotations.push(...this.detectIPI008(content, contentType));
    annotations.push(...this.detectIPI009(content, contentType));
    annotations.push(...this.detectIPI010(content, contentType));
    annotations.push(...this.detectIPI013(content, contentType));
    annotations.push(...this.detectIPI014(content, contentType));
    annotations.push(...this.detectIPI015(content, contentType));
    annotations.push(...this.detectIPI016(content, contentType));
    annotations.push(...this.detectIPI017(content, contentType));
    annotations.push(...this.detectIPI018(content, contentType));

    return annotations;
  }

  /**
   * Scan raw HTML for web-based IDPI attacks (raw HTML stage)
   *
   * @param html - Raw HTML content to scan
   * @param contentType - Type of content (should be 'html')
   * @returns Array of threat annotations (empty if no threats detected)
   *
   * @remarks
   * Only runs IPI-011 and IPI-012 which require raw HTML before text extraction.
   * Call this BEFORE text extraction, then call scan() on the extracted text.
   * Degrades gracefully: returns [] for empty or non-HTML input.
   */
  scanRawHtml(html: string, contentType: ContentType): ThreatAnnotation[] {
    // Graceful degradation for non-HTML or empty input
    if (!html || html.trim().length === 0 || contentType !== 'html') {
      return [];
    }

    const annotations: ThreatAnnotation[] = [];

    // Run raw HTML-stage detectors only
    annotations.push(...this.detectIPI011(html, contentType));
    annotations.push(...this.detectIPI012(html, contentType));

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
   * Detect IPI-008: Malicious Infrastructure
   *
   * Detects web content that IS attack infrastructure (C2 panels, credential dumps,
   * phishing kits, bulk PII harvesting layouts).
   *
   * @private
   */
  private detectIPI008(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Performance limit: skip very large content (>1MB) to ensure <5ms completion
    if (content.length > 1_000_000) {
      return annotations;
    }

    let signalCount = 0;
    let detectionOffset = -1;

    // C2 panel fingerprints - look for admin panel terminology in bulk
    const c2PanelTerms = [
      /\b(?:bot|victim|target|zombie|client)s?\s*(?:online|connected|active)/gi,
      /\b(?:command|task)\s*(?:queue|history|log)/gi,
      /\badmin\s*panel.*(?:bot|victim|target)/gi,
      /\b(?:heartbeat|check-in|beacon)\s*(?:status|interval)/gi,
    ];

    for (const pattern of c2PanelTerms) {
      const matches = content.match(pattern);
      if (matches && matches.length >= 2) {
        signalCount++;
        if (detectionOffset === -1) {
          detectionOffset = content.search(pattern);
        }
      }
    }

    // Credential dump patterns - large concentrations of user:pass or cookie bundles
    const credentialPatterns = [
      /[\w\-\.]+@[\w\-\.]+:[^\s]{6,}/g, // email:password pattern
      /(?:username|user|login)\s*[:=]\s*\S+\s*(?:password|pass|pwd)\s*[:=]\s*\S+/gi,
      /\b(?:session|auth)_?token\s*[:=]\s*["'][\w\-]{20,}["']/gi,
    ];

    for (const pattern of credentialPatterns) {
      const matches = content.match(pattern);
      if (matches && matches.length >= 5) {
        signalCount++;
        if (detectionOffset === -1) {
          detectionOffset = content.search(pattern);
        }
      }
    }

    // Cookie bundle detection - large JSON arrays with cookie objects
    // Check for cookie/session field indicators first to avoid catastrophic backtracking
    const cookieFieldMatches = content.match(/"(?:name|domain|value|expires)":/gi);
    const hasCookieKeyword = /(?:cookie|session)/i.test(content);
    if (cookieFieldMatches && cookieFieldMatches.length >= 10 && hasCookieKeyword) {
      signalCount += 2; // Strong signal
      if (detectionOffset === -1) {
        const cookieKeywordIndex = content.search(/(?:cookie|session)/i);
        detectionOffset = cookieKeywordIndex >= 0 ? cookieKeywordIndex : 0;
      }
    }

    // Phishing kit indicators - fake login forms with brand names
    const phishingPatterns = [
      /(?:fake|phish|spoof).{0,50}(?:login|signin|auth)/gi,
      /(?:credential|login)\s*(?:harvest|steal|capture|grab)/gi,
    ];

    for (const pattern of phishingPatterns) {
      if (pattern.test(content)) {
        signalCount++;
        if (detectionOffset === -1) {
          detectionOffset = content.search(pattern);
        }
      }
    }

    // Check for suspicious forms separately (simpler check to avoid backtracking)
    if (/<form[^>]{0,200}password/i.test(content)) {
      const formMatch = content.match(/<form[^>]*action=["'][^"']+["']/i);
      if (formMatch && !/(?:google|facebook|microsoft|apple|amazon|paypal)\.com/.test(formMatch[0])) {
        signalCount++;
        if (detectionOffset === -1) {
          detectionOffset = content.indexOf(formMatch[0]);
        }
      }
    }

    // Bulk PII harvesting - simple heuristic check for many emails + table structure
    const rowMatches = content.match(/<tr/gi);
    const emailMatches = content.match(/[\w\-\.]+@[\w\-\.]+\.\w+/g);
    if (rowMatches && rowMatches.length >= 10 && emailMatches && emailMatches.length >= 10) {
      // Both table structure and bulk emails present
      signalCount += 2; // Strong signal
      if (detectionOffset === -1) {
        detectionOffset = Math.min(
          content.indexOf('<tr'),
          content.search(/[\w\-\.]+@[\w\-\.]+\.\w+/)
        );
      }
    }

    // Determine severity and confidence based on signal count
    if (signalCount >= 3) {
      // HIGH confidence: 3+ distinct signals
      const excerpt = this.extractExcerpt(content, detectionOffset, 120);
      annotations.push({
        id: 'IPI-008',
        severity: 'CRITICAL',
        confidence: 0.85,
        offset: detectionOffset,
        excerpt: `[MALICIOUS_INFRA] ${excerpt}`,
        vector: contentType,
        mitigated: true,
      });
    } else if (signalCount === 2) {
      // MEDIUM confidence: 2 signals
      const excerpt = this.extractExcerpt(content, detectionOffset, 120);
      annotations.push({
        id: 'IPI-008',
        severity: 'HIGH',
        confidence: 0.65,
        offset: detectionOffset,
        excerpt: `[MALICIOUS_INFRA] ${excerpt}`,
        vector: contentType,
        mitigated: true,
      });
    } else if (signalCount === 1) {
      // LOW confidence: single signal
      const excerpt = this.extractExcerpt(content, detectionOffset, 120);
      annotations.push({
        id: 'IPI-008',
        severity: 'MEDIUM',
        confidence: 0.45,
        offset: detectionOffset,
        excerpt: `[MALICIOUS_INFRA] ${excerpt}`,
        vector: contentType,
        mitigated: true,
      });
    }

    return annotations;
  }

  /**
   * Detect IPI-009: Homoglyph & Unicode Obfuscation
   *
   * Detects attempts to use look-alike characters to smuggle instructions or bypass
   * existing IPI-001 patterns. Extends IPI-007 with Unicode-layer obfuscation.
   *
   * @private
   */
  private detectIPI009(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Performance limit: skip very large content (>1MB) to ensure <5ms completion
    if (content.length > 1_000_000) {
      return annotations;
    }

    // Cyrillic/Greek homoglyph substitution in directive keywords
    // Look for known directive words with Cyrillic/Greek lookalikes
    // Check for words that mix Latin and Cyrillic characters
    const suspiciousWords = [
      /ign[оọ]re/gi, // "ignore" with Cyrillic о
      /instructi[оọ]n/gi, // "instruction" with Cyrillic о
      /syst[еė]m/gi, // "system" with Cyrillic е
      /pr[оọ]mpt/gi, // "prompt" with Cyrillic о
      /c[оọ]mmand/gi, // "command" with Cyrillic о
    ];

    for (const pattern of suspiciousWords) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        // Verify it actually contains non-ASCII lookalikes
        if (/[\u0400-\u04FF\u0370-\u03FF]/.test(match[0])) {
          const excerpt = this.extractExcerpt(content, match.index, 120);
          annotations.push({
            id: 'IPI-009',
            severity: 'HIGH',
            confidence: 0.9,
            offset: match.index,
            excerpt: `[HOMOGLYPH] ${excerpt}`,
            vector: contentType,
            mitigated: true,
          });
        }
      }
    }

    // Bidirectional text override abuse (U+202E, U+202D, U+202C, U+202A, U+202B)
    const bidiPattern = /[\u202A-\u202E]/g;
    const bidiMatches = content.match(bidiPattern);
    if (bidiMatches && bidiMatches.length > 0) {
      const firstMatch = content.search(bidiPattern);
      const excerpt = this.extractExcerpt(content, firstMatch, 120);
      annotations.push({
        id: 'IPI-009',
        severity: 'HIGH',
        confidence: 0.85,
        offset: firstMatch,
        excerpt: `[BIDI_OVERRIDE] ${excerpt.replace(/[\u202A-\u202E]/g, '\u2190')}`, // Replace with left arrow for visibility
        vector: contentType,
        mitigated: true,
      });
    }

    // Mixed-script identifier attacks in URLs or code blocks
    const urlPattern = /https?:\/\/[^\s]+/g;
    let urlMatch: RegExpExecArray | null;
    while ((urlMatch = urlPattern.exec(content)) !== null) {
      const url = urlMatch[0];
      // Check for mixed scripts in domain part
      const hasCyrillic = /[\u0400-\u04FF]/.test(url);
      const hasLatin = /[a-zA-Z]/.test(url);
      const hasGreek = /[\u0370-\u03FF]/.test(url);

      const scriptCount = [hasCyrillic, hasLatin, hasGreek].filter(Boolean).length;
      if (scriptCount >= 2) {
        const excerpt = this.extractExcerpt(content, urlMatch.index, 120);
        annotations.push({
          id: 'IPI-009',
          severity: 'MEDIUM',
          confidence: 0.7,
          offset: urlMatch.index,
          excerpt: `[MIXED_SCRIPT_URL] ${excerpt}`,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    // Reset regex
    urlPattern.lastIndex = 0;

    return annotations;
  }

  /**
   * Detect IPI-010: Recursive/Nested Instruction Framing
   *
   * Detects content structured to make Claude believe it is reading its own prior
   * output, a system prompt, or a tool result rather than external web content.
   *
   * @private
   */
  private detectIPI010(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Performance limit: skip very large content (>1MB) to ensure <5ms completion
    if (content.length > 1_000_000) {
      return annotations;
    }

    // Fake XML tag framing (tool_result, assistant, system, user)
    const fakeXMLPatterns = [
      /<(?:tool_result|assistant|system|user|human)[>\s]/gi,
      /<\/(?:tool_result|assistant|system|user|human)>/gi,
      /<function_calls>/gi,
      /<invoke/gi,
    ];

    for (const pattern of fakeXMLPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);
        annotations.push({
          id: 'IPI-010',
          severity: 'CRITICAL',
          confidence: 0.95,
          offset: match.index,
          excerpt: `[FAKE_XML] ${excerpt}`,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    // Content that opens with Claude's output format patterns
    const claudeOutputPatterns = [
      /^(?:As Claude|I am Claude|I'm Claude),?\s+(?:I have been|I was|I've been)/im,
      /^(?:According to|Based on)\s+my\s+(?:system prompt|instructions|guidelines)/im,
      /^I(?:'m| am)\s+(?:an AI assistant|Claude)\s+(?:created by|developed by|made by)\s+Anthropic/im,
    ];

    for (const pattern of claudeOutputPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);
        annotations.push({
          id: 'IPI-010',
          severity: 'HIGH',
          confidence: 0.8,
          offset: match.index,
          excerpt: `[FAKE_CLAUDE_OUTPUT] ${excerpt}`,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    // Nested JSON claiming to be MCP protocol messages
    const mcpProtocolPatterns = [
      /"(?:jsonrpc|method|params)":\s*"(?:2\.0|initialize|tools\/list|notifications)"/gi,
      /"result":\s*\{\s*"content":\s*\[\s*\{/gi, // MCP tool result structure
    ];

    for (const pattern of mcpProtocolPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);
        annotations.push({
          id: 'IPI-010',
          severity: 'HIGH',
          confidence: 0.75,
          offset: match.index,
          excerpt: `[FAKE_MCP] ${excerpt}`,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    // Content mimicking visus-mcp token metrics header format
    const visusSpoofPatterns = [
      /\[VISUS\s+TOKEN\s+METRICS\]/i,
      /\[SANITIZATION\s+COMPLETE\]/i,
      /IPI\s+threats\s+detected:\s*\d+/i,
      /Content\s+hash:\s*[a-f0-9]{64}/i,
    ];

    for (const pattern of visusSpoofPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);
        annotations.push({
          id: 'IPI-010',
          severity: 'CRITICAL',
          confidence: 0.9,
          offset: match.index,
          excerpt: `[SPOOF_VISUS_HEADER] ${excerpt}`,
          vector: contentType,
          mitigated: true,
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-011: CSS/Visual Concealment
   *
   * Implements Unit 42 "IPI-008" from: Palo Alto Networks Unit 42 (March 2026)
   * "Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild"
   * Internal ID is IPI-011 (IPI-008/009/010 already assigned in v0.14.0)
   *
   * Detects instruction-bearing content hidden via CSS — invisible to humans
   * but readable by an LLM processing raw HTML or accessibility trees.
   *
   * @private
   */
  private detectIPI011(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Performance limit: skip very large content (>500KB) to prevent performance issues
    if (content.length > 500_000) {
      return annotations;
    }

    // CSS concealment keywords (simpler string matching to avoid regex catastrophic backtracking)
    const cssHidingKeywords = [
      'display:none',
      'display: none',
      'visibility:hidden',
      'visibility: hidden',
      'opacity:0',
      'opacity: 0',
      'font-size:0',
      'height:0',
      'width:0',
      'z-index:-',
      'text-indent:-',
    ];

    // Directive keywords to look for near hidden content
    const directiveKeywords = [
      'ignore previous',
      'ignore all previous',
      'disregard',
      'override',
      'act as',
      'you are',
      'forget',
      'system prompt',
      'new instructions',
    ];

    // Strategy: Simple string search for style attributes, then check for CSS hiding + directives
    // This avoids catastrophic regex backtracking entirely
    const styleRegex = /style\s*=\s*["'][^"']{1,500}["']/gi;
    let styleMatch: RegExpExecArray | null;

    while ((styleMatch = styleRegex.exec(content)) !== null) {
      const styleContent = styleMatch[0].toLowerCase();

      // Check if this style contains any CSS hiding keywords
      const hasHiding = cssHidingKeywords.some(keyword => styleContent.includes(keyword));

      if (hasHiding) {
        // Check surrounding context (next 600 chars) for directive keywords
        const searchStart = styleMatch.index;
        const searchEnd = Math.min(content.length, searchStart + 600);
        const surroundingText = content.substring(searchStart, searchEnd).toLowerCase();

        const hasDirective = directiveKeywords.some(keyword => surroundingText.includes(keyword));

        if (hasDirective) {
          const excerpt = this.extractExcerpt(content, searchStart, 120);
          annotations.push({
            id: 'IPI-011',
            severity: 'HIGH',
            confidence: 0.85,
            offset: searchStart,
            excerpt: `[CSS_HIDDEN] ${excerpt}`,
            vector: contentType,
            mitigated: true,
            delivery_method: 'css_concealment',
          });
          break; // Only report once
        }
      }
    }

    // Step 2: Check for accessibility class names with directive text
    const accessibilityClasses = ['sr-only', 'visually-hidden', 'screen-reader-only', 'hidden', 'invisible'];

    for (const className of accessibilityClasses) {
      // Simple indexOf search instead of regex
      const searchStr = `class="${className}"`;
      let searchIndex = content.toLowerCase().indexOf(searchStr);

      if (searchIndex === -1) {
        // Try with single quotes
        const searchStr2 = `class='${className}'`;
        searchIndex = content.toLowerCase().indexOf(searchStr2);
      }

      if (searchIndex !== -1) {
        // Check next 200 chars for directive keywords
        const searchEnd = Math.min(content.length, searchIndex + 200);
        const surroundingText = content.substring(searchIndex, searchEnd).toLowerCase();

        const hasDirective = directiveKeywords.some(keyword => surroundingText.includes(keyword));

        if (hasDirective) {
          const excerpt = this.extractExcerpt(content, searchIndex, 120);
          annotations.push({
            id: 'IPI-011',
            severity: 'HIGH',
            confidence: 0.8,
            offset: searchIndex,
            excerpt: `[ARIA_HIDDEN] ${excerpt}`,
            vector: contentType,
            mitigated: true,
            delivery_method: 'css_concealment',
          });
          break; // Only report once
        }
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-012: HTML Attribute Cloaking
   *
   * Implements Unit 42 "IPI-009" from: Palo Alto Networks Unit 42 (March 2026)
   * "Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild"
   * Internal ID is IPI-012 (IPI-008/009/010 already assigned in v0.14.0)
   *
   * Detects instructions smuggled into HTML comments, aria-* attributes,
   * data-* attributes, <noscript> blocks, and <meta> tags.
   *
   * @private
   */
  private detectIPI012(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Performance limit: skip very large content (>500KB)
    if (content.length > 500_000) {
      return annotations;
    }

    // Directive keywords to search for
    const directiveKeywords = [
      'ignore',
      'override',
      'forget',
      'act as',
      'you are',
      'disregard',
      'new instructions',
      'system prompt',
      'assistant',
      'llm',
      'ai agent',
    ];

    // 1. HTML comments containing instructions (bounded to 500 chars per comment)
    const commentRegex = /<!--[\s\S]{1,500}?-->/gi;
    let commentMatch: RegExpExecArray | null;

    while ((commentMatch = commentRegex.exec(content)) !== null) {
      const commentText = commentMatch[0].toLowerCase();
      const hasDirective = directiveKeywords.some(keyword => commentText.includes(keyword));

      if (hasDirective) {
        const excerpt = this.extractExcerpt(content, commentMatch.index, 120);
        annotations.push({
          id: 'IPI-012',
          severity: 'HIGH',
          confidence: 0.9,
          offset: commentMatch.index,
          excerpt: `[HTML_COMMENT] ${excerpt}`,
          vector: contentType,
          mitigated: true,
          delivery_method: 'html_attribute_cloaking',
        });
      }
    }

    // 2. ARIA attributes (bounded to 500 chars per attribute value)
    const ariaPatterns = [
      /aria-label\s*=\s*["'][^"']{1,500}["']/gi,
      /aria-description\s*=\s*["'][^"']{1,500}["']/gi,
      /title\s*=\s*["'][^"']{1,500}["']/gi,
    ];

    for (const pattern of ariaPatterns) {
      let ariaMatch: RegExpExecArray | null;

      while ((ariaMatch = pattern.exec(content)) !== null) {
        const attrText = ariaMatch[0].toLowerCase();
        const hasDirective = directiveKeywords.some(keyword => attrText.includes(keyword));

        if (hasDirective) {
          const excerpt = this.extractExcerpt(content, ariaMatch.index, 120);
          annotations.push({
            id: 'IPI-012',
            severity: 'HIGH',
            confidence: 0.85,
            offset: ariaMatch.index,
            excerpt: `[ARIA_ATTR] ${excerpt}`,
            vector: contentType,
            mitigated: true,
            delivery_method: 'html_attribute_cloaking',
          });
        }
      }
    }

    // 3. data-* attributes (bounded to 500 chars per attribute value)
    const dataAttrRegex = /data-[a-z-]+\s*=\s*["'][^"']{1,500}["']/gi;
    let dataMatch: RegExpExecArray | null;

    while ((dataMatch = dataAttrRegex.exec(content)) !== null) {
      const attrText = dataMatch[0].toLowerCase();
      const hasDirective = directiveKeywords.some(keyword => attrText.includes(keyword));

      // Also flag suspiciously long data attributes (>200 chars)
      const valueMatch = dataMatch[0].match(/["']([^"']+)["']/);
      const isSuspiciouslyLong = valueMatch && valueMatch[1].length > 200;

      if (hasDirective || isSuspiciouslyLong) {
        const excerpt = this.extractExcerpt(content, dataMatch.index, 120);
        annotations.push({
          id: 'IPI-012',
          severity: 'MEDIUM',
          confidence: hasDirective ? 0.7 : 0.5,
          offset: dataMatch.index,
          excerpt: `[DATA_ATTR] ${excerpt}`,
          vector: contentType,
          mitigated: true,
          delivery_method: 'html_attribute_cloaking',
        });
      }
    }

    // 4. <noscript> blocks (bounded to 1000 chars)
    const noscriptRegex = /<noscript[\s\S]{1,1000}?<\/noscript>/gi;
    let noscriptMatch: RegExpExecArray | null;

    while ((noscriptMatch = noscriptRegex.exec(content)) !== null) {
      const blockText = noscriptMatch[0].toLowerCase();
      const hasDirective = directiveKeywords.some(keyword => blockText.includes(keyword));

      if (hasDirective) {
        const excerpt = this.extractExcerpt(content, noscriptMatch.index, 120);
        annotations.push({
          id: 'IPI-012',
          severity: 'HIGH',
          confidence: 0.85,
          offset: noscriptMatch.index,
          excerpt: `[NOSCRIPT] ${excerpt}`,
          vector: contentType,
          mitigated: true,
          delivery_method: 'html_attribute_cloaking',
        });
      }
    }

    // 5. <meta> tags (bounded to 200 chars per tag)
    const metaRegex = /<meta[^>]{1,200}>/gi;
    let metaMatch: RegExpExecArray | null;

    while ((metaMatch = metaRegex.exec(content)) !== null) {
      const tagText = metaMatch[0].toLowerCase();
      const hasDirective = directiveKeywords.some(keyword => tagText.includes(keyword));

      if (hasDirective) {
        const excerpt = this.extractExcerpt(content, metaMatch.index, 120);
        annotations.push({
          id: 'IPI-012',
          severity: 'HIGH',
          confidence: 0.8,
          offset: metaMatch.index,
          excerpt: `[META_TAG] ${excerpt}`,
          vector: contentType,
          mitigated: true,
          delivery_method: 'html_attribute_cloaking',
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-013: AI Moderation/Review Bypass
   *
   * Implements Unit 42 "IPI-010" from: Palo Alto Networks Unit 42 (March 2026)
   * "Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild"
   * Internal ID is IPI-013 (IPI-008/009/010 already assigned in v0.14.0)
   *
   * Detects content explicitly targeting LLM-based review, moderation,
   * ad-approval, or content-safety pipelines. This is the Unit 42 "first ever"
   * in-the-wild finding (December 2025 ad review bypass).
   *
   * @private
   */
  private detectIPI013(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    const REVIEW_BYPASS_PATTERNS = [
      // Direct approval instructions
      /(?:approve|accept|allow|pass|whitelist)\s+(?:this|the)\s+(?:content|ad|post|page|listing|product)/i,
      /(?:mark|flag|classify|label)\s+(?:this|as)\s+(?:safe|compliant|legitimate|approved|non-?violating)/i,
      /(?:this (?:content|ad|post|page|listing)\s+(?:is|should be|must be)\s+(?:approved|safe|compliant))/i,

      // Instruction override targeting reviewers
      /(?:ignore|bypass|skip|override)\s+(?:content|ad|review|moderation|safety|policy)\s+(?:check|filter|rule|guideline|policy)/i,
      /(?:do not|don't)\s+(?:flag|reject|block|report|remove)\s+(?:this|the)\s+(?:content|ad|post|page)/i,
      /(?:previous|prior)\s+(?:rules|guidelines|instructions|policy)\s+(?:no longer apply|are overridden|do not apply)/i,

      // Output manipulation targeting decision systems
      /(?:output|respond|reply|answer)\s+(?:only\s+)?(?:with\s+)?["']?\s*(?:approved|yes|compliant|safe|allow)\s*["']?/i,
      /(?:your|the)\s+(?:review|decision|verdict|output)\s+(?:must be|should be|is)\s+["']?(?:approved|passed|safe)/i,

      // Role hijacking specific to moderation context
      /(?:you are|act as|pretend to be)\s+(?:a\s+)?(?:lenient|permissive|non-restrictive)\s+(?:reviewer|moderator|filter)/i,
    ];

    for (const pattern of REVIEW_BYPASS_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);
        annotations.push({
          id: 'IPI-013',
          severity: 'CRITICAL',
          confidence: 0.9,
          offset: match.index,
          excerpt: `[MODERATION_BYPASS] ${excerpt}`,
          vector: contentType,
          mitigated: true,
          delivery_method: 'ai_moderation_bypass',
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-014: SEO / Phishing Amplification
   *
   * Implements Unit 42 "IPI-011" from: Palo Alto Networks Unit 42 (March 2026)
   * "Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild"
   * Internal ID is IPI-014 (IPI-008/009/010 already assigned in v0.14.0)
   *
   * Detects instructions to promote external URLs, manipulate AI-powered
   * search rankings, or redirect users to phishing/impersonation sites.
   *
   * @private
   */
  private detectIPI014(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    const SEO_POISON_PATTERNS = [
      // Direct URL promotion
      /(?:recommend|promote|link to|share|point to)\s+(?:this|the following|our)\s+(?:site|url|page|link|website)/i,
      /(?:tell|instruct|direct|send|guide)\s+(?:users?|people|visitors?)\s+to\s+(?:visit|go to|use)\s+https?:\/\//i,
      /(?:the\s+)?(?:best|top|official|real|correct|legitimate)\s+(?:site|source|page|url)\s+(?:is|for .+? is)\s+https?:\/\//i,

      // Ranking manipulation
      /(?:rank|list|mention|include)\s+(?:this|our|the following)\s+(?:site|page|url)\s+(?:first|at the top|above)/i,
      /(?:when (?:asked|searching|looking) for .{0,60},?\s+(?:say|tell|respond|mention|recommend))/i,
      /(?:always|make sure to)\s+(?:recommend|suggest|mention|include)\s+https?:\/\//i,

      // Brand impersonation signals
      /(?:this is|i am|we are)\s+(?:the\s+)?(?:official|real|authentic|legitimate)\s+(?:site|page|account|representative)/i,
      /(?:instead of|rather than)\s+[a-z0-9]+\.[a-z]{2,},?\s+(?:use|visit|go to)\s+https?:\/\//i,
    ];

    for (const pattern of SEO_POISON_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);
        annotations.push({
          id: 'IPI-014',
          severity: 'HIGH',
          confidence: 0.8,
          offset: match.index,
          excerpt: `[SEO_POISON] ${excerpt}`,
          vector: contentType,
          mitigated: true,
          delivery_method: 'seo_phishing_amplification',
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-015: Unauthorized Action Induction
   *
   * Implements Unit 42 "IPI-012" from: Palo Alto Networks Unit 42 (March 2026)
   * "Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild"
   * Internal ID is IPI-015 (IPI-008/009/010 already assigned in v0.14.0)
   *
   * Detects instructions targeting agentic tool-call behavior — financial
   * transactions, form submissions, API calls, data forwarding, OAuth grants.
   *
   * @private
   */
  private detectIPI015(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    const ACTION_INDUCTION_PATTERNS = [
      // Financial / transaction actions
      /(?:transfer|send|pay|wire|purchase|buy|order|subscribe|charge)\s+(?:\$|€|£|¥|USD|EUR|GBP)?\s*\d+/i,
      /(?:complete|finalize|confirm|process|execute)\s+(?:the\s+)?(?:payment|transaction|purchase|order|checkout)/i,
      /(?:use|charge|bill)\s+(?:the\s+)?(?:saved|stored|default|credit|debit)\s+(?:card|payment method)/i,

      // UI / form action induction
      /(?:click|press|tap|invoke|submit|trigger)\s+(?:the\s+)?(?:button|submit|confirm|ok|send|proceed)\s*(?:button)?/i,
      /(?:fill (?:in|out)|complete|submit)\s+(?:the\s+)?(?:form|fields?|input)/i,

      // Tool / API call induction (agentic context)
      /(?:call|invoke|execute|run|use)\s+(?:the\s+)?(?:tool|function|api|endpoint|webhook|command)/i,
      /(?:grant|authorize|approve|confirm|allow)\s+(?:the\s+)?(?:access|permission|request|authorization|oauth)/i,

      // Data exfiltration actions
      /(?:forward|exfiltrate|send|upload|post|transmit)\s+(?:all|the|my|user|their)\s+(?:data|messages?|emails?|files?|documents?|credentials?)/i,
      /(?:include|attach|append)\s+(?:the\s+)?(?:contents? of|data from|information from)\s+(?:all|my|the\s+user)/i,
      /(?:email|message|text|DM|dm|send to)\s+[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i,
    ];

    for (const pattern of ACTION_INDUCTION_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);
        annotations.push({
          id: 'IPI-015',
          severity: 'CRITICAL',
          confidence: 0.85,
          offset: match.index,
          excerpt: `[ACTION_INDUCTION] ${excerpt}`,
          vector: contentType,
          mitigated: true,
          delivery_method: 'action_induction',
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-016: Destructive / Denial-of-Service Intent
   *
   * Implements Unit 42 "IPI-013" from: Palo Alto Networks Unit 42 (March 2026)
   * "Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild"
   * Internal ID is IPI-016 (IPI-008/009/010 already assigned in v0.14.0)
   *
   * Detects instructions targeting system availability or data integrity —
   * deletion commands, infinite loop induction, context flooding, response refusal.
   *
   * @private
   */
  private detectIPI016(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    const DESTRUCTIVE_PATTERNS = [
      // Data deletion / destruction
      /(?:delete|destroy|wipe|erase|remove|purge|shred)\s+(?:all|the|every|user|system|their)\s+(?:data|files?|records?|history|messages?|emails?|documents?)/i,
      /(?:clear|reset|flush|drop)\s+(?:all|the|every)\s+(?:data|records?|database|history|cache|memory)/i,

      // Infinite loop / DoS induction
      /(?:repeat|loop|keep (?:saying|outputting|printing|generating|writing))\s+.{0,80}\s+(?:forever|infinitely|until (?:stopped|interrupted|told)|in a loop)/i,
      /(?:enter|go into|start)\s+(?:an?\s+)?(?:infinite|endless)\s+loop/i,
      /(?:fill|flood|exhaust|consume)\s+(?:the\s+)?(?:context|memory|output|response|token|buffer)/i,
      /(?:generate|output|produce)\s+(?:as much|maximum|unlimited)\s+(?:text|content|tokens?|output)/i,

      // Response refusal induction
      /(?:do not|don't|never|stop|refuse to)\s+(?:respond|answer|reply|help|assist)\s+(?:to|with)?\s+(?:any|future|subsequent|further|the user)/i,
      /(?:from (?:now on|this point),?\s+(?:do not|don't|never|ignore|refuse))/i,

      // System disruption
      /(?:crash|hang|freeze|break|corrupt|disable|shut down)\s+(?:the\s+)?(?:system|agent|assistant|model|application|service)/i,
    ];

    for (const pattern of DESTRUCTIVE_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(content)) !== null) {
        const excerpt = this.extractExcerpt(content, match.index, 120);
        annotations.push({
          id: 'IPI-016',
          severity: 'CRITICAL',
          confidence: 0.9,
          offset: match.index,
          excerpt: `[DESTRUCTIVE] ${excerpt}`,
          vector: contentType,
          mitigated: true,
          delivery_method: 'destructive_payload',
        });
      }
    }

    return annotations;
  }

  /**
   * Detect IPI-017: RAG Corpus Poisoning Payload
   *
   * Detects web page content engineered to win RAG retrieval races and carry
   * embedded instruction payloads. Uses three-signal detection:
   * - Signal A: Retrieval bait density (repeated anchor terms)
   * - Signal B: Knowledge authority spoofing
   * - Signal C: Embedded instruction inside plausible content
   *
   * @private
   */
  private detectIPI017(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Performance limit: skip very large content (>1MB)
    if (content.length > 1_000_000) {
      return annotations;
    }

    let signalA = false;
    let signalACount = 0;
    let signalB = false;
    let signalC = false;
    let detectionOffset = -1;

    // Signal A: Retrieval bait density
    // Check for repeated anchor terms within 500-character windows
    const anchorTerms = [
      /according to/gi,
      /the answer is/gi,
      /you should/gi,
      /the correct information is/gi,
      /always remember that/gi,
      /important context:/gi,
    ];

    // Sliding window approach to detect density
    const windowSize = 500;
    for (let i = 0; i < content.length - windowSize; i += 250) {
      const window = content.substring(i, i + windowSize);
      let windowCount = 0;

      for (const pattern of anchorTerms) {
        const matches = window.match(pattern);
        if (matches) {
          windowCount += matches.length;
        }
      }

      if (windowCount >= 3) {
        signalA = true;
        signalACount = Math.max(signalACount, windowCount);
        if (detectionOffset === -1) {
          detectionOffset = i;
        }
      }
    }

    // Signal B: Knowledge authority spoofing
    const authoritySpoofPatterns = [
      /official documentation states that/gi,
      /system knowledge base entry:/gi,
      /retrieved context\s*\[priority:\s*high\]/gi,
      /verified source:/gi,
      /knowledge cutoff override:/gi,
      /this document supersedes/gi,
    ];

    for (const pattern of authoritySpoofPatterns) {
      const match = content.match(pattern);
      if (match) {
        signalB = true;
        if (detectionOffset === -1) {
          const matchIndex = content.search(pattern);
          detectionOffset = matchIndex >= 0 ? matchIndex : 0;
        }
        break;
      }
    }

    // Signal C: Embedded instruction inside plausible content
    // Look for imperative verbs at sentence starts within paragraph text
    const imperativePatterns = [
      /\b(?:ignore|disregard|output|print|send|forward|execute|call|fetch)\s+(?:all|the|your|this)/gi,
    ];

    for (const pattern of imperativePatterns) {
      const matches = content.match(pattern);
      if (matches && matches.length > 0) {
        signalC = true;
        if (detectionOffset === -1) {
          const matchIndex = content.search(pattern);
          detectionOffset = matchIndex >= 0 ? matchIndex : 0;
        }
        break;
      }
    }

    // Severity escalation based on signal combinations
    if (detectionOffset === -1) {
      detectionOffset = 0;
    }

    const excerpt = this.extractExcerpt(content, detectionOffset, 120);

    if (signalB && signalC) {
      // CRITICAL: Both authority spoofing + embedded instruction
      annotations.push({
        id: 'IPI-017',
        severity: 'CRITICAL',
        confidence: 0.9,
        offset: detectionOffset,
        excerpt: `[RAG_POISON] ${excerpt}`,
        vector: contentType,
        mitigated: true,
      });
    } else if (signalA && (signalB || signalC)) {
      // HIGH: Retrieval bait + either authority spoofing or instruction
      annotations.push({
        id: 'IPI-017',
        severity: 'HIGH',
        confidence: 0.8,
        offset: detectionOffset,
        excerpt: `[RAG_POISON] ${excerpt}`,
        vector: contentType,
        mitigated: true,
      });
    } else if (signalA && signalACount >= 5) {
      // MEDIUM: High retrieval bait density alone
      annotations.push({
        id: 'IPI-017',
        severity: 'MEDIUM',
        confidence: 0.75,
        offset: detectionOffset,
        excerpt: `[RAG_POISON] ${excerpt}`,
        vector: contentType,
        mitigated: true,
      });
    }

    return annotations;
  }

  /**
   * Detect IPI-018: MCP Tool Description Poisoning
   *
   * Detects web page content containing structures that mimic MCP tool definition
   * schemas, intended to inject fake tool definitions or shadow legitimate tools.
   * Uses three-signal detection:
   * - Signal A: MCP schema structure mimicry
   * - Signal B: Tool capability override language
   * - Signal C: Namespace collision attempt
   *
   * @private
   */
  private detectIPI018(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    // Performance limit: skip very large content (>1MB)
    if (content.length > 1_000_000) {
      return annotations;
    }

    let signalA = false;
    let signalB = false;
    let signalC = false;
    let isCritical = false;
    let detectionOffset = -1;

    // Known MCP tool names that attackers might shadow
    const shadowToolNames = [
      'send_email',
      'read_file',
      'write_file',
      'execute_code',
      'web_search',
      'fetch_url',
      'list_files',
      'run_command',
      'get_calendar',
      'create_event',
      'slack_message',
    ];

    // Signal A: MCP schema structure mimicry
    // Look for JSON-like or prose structures containing tool schema fields
    const schemaPatterns = [
      /"name"\s*:\s*"[^"]+"\s*,?\s*"description"\s*:\s*"[^"]+"\s*,?\s*"(?:inputSchema|parameters)"/gi,
      /\bname\s*:\s*\w+\s*,?\s*description\s*:\s*.{0,100}(?:inputSchema|parameters)/gi,
    ];

    for (const pattern of schemaPatterns) {
      const match = content.match(pattern);
      if (match) {
        signalA = true;
        if (detectionOffset === -1) {
          const matchIndex = content.search(pattern);
          detectionOffset = matchIndex >= 0 ? matchIndex : 0;
        }

        // Check if this mentions a shadow tool name
        const schemaText = content.substring(
          Math.max(0, detectionOffset - 50),
          Math.min(content.length, detectionOffset + 300)
        );
        for (const toolName of shadowToolNames) {
          if (new RegExp(`\\b${toolName}\\b`, 'i').test(schemaText)) {
            signalC = true;
            // Check if it's a critical tool
            if (['execute_code', 'run_command', 'write_file'].includes(toolName)) {
              isCritical = true;
            }
            break;
          }
        }
        break;
      }
    }

    // Signal B: Tool capability override language
    const overridePatterns = [
      /use this tool instead of/gi,
      /this tool replaces/gi,
      /preferred tool for/gi,
      /ignore the existing\s+\w+/gi,
      /the correct tool to use is/gi,
      /when asked to\s+\w+,?\s*call/gi,
    ];

    for (const pattern of overridePatterns) {
      const match = content.match(pattern);
      if (match) {
        signalB = true;
        if (detectionOffset === -1) {
          const matchIndex = content.search(pattern);
          detectionOffset = matchIndex >= 0 ? matchIndex : 0;
        }
        break;
      }
    }

    // Signal C: Namespace collision attempt (fuzzy matching)
    // Look for tool names with Levenshtein distance ≤ 1 from known tools
    for (const toolName of shadowToolNames) {
      // Simple fuzzy match: check for common typos and variants
      const fuzzyPatterns = [
        new RegExp(`\\b${toolName.replace(/_/g, '')}\\b`, 'i'), // No underscore
        new RegExp(`\\b${toolName.replace(/_/g, '-')}\\b`, 'i'), // Hyphen instead of underscore
        new RegExp(`\\b${toolName}s?\\b`, 'i'), // Plural form
      ];

      for (const fuzzyPattern of fuzzyPatterns) {
        if (fuzzyPattern.test(content) && /\b(?:tool|function|command|action)\b/i.test(content)) {
          signalC = true;
          if (detectionOffset === -1) {
            const matchIndex = content.search(fuzzyPattern);
            detectionOffset = matchIndex >= 0 ? matchIndex : 0;
          }
          // Check if it's a critical tool
          if (['execute_code', 'run_command', 'write_file'].includes(toolName)) {
            isCritical = true;
          }
          break;
        }
      }

      if (signalC) break;
    }

    // Severity escalation based on signal combinations
    if (detectionOffset === -1) {
      detectionOffset = 0;
    }

    const excerpt = this.extractExcerpt(content, detectionOffset, 120);

    if (signalA) {
      // Always at least HIGH if MCP schema structure detected
      let severity: 'HIGH' | 'CRITICAL' = 'HIGH';
      let confidence = 0.85;

      if ((signalA && signalB) || isCritical) {
        // CRITICAL if schema + override language, or if shadowing critical tool
        severity = 'CRITICAL';
        confidence = 0.95;
      }

      annotations.push({
        id: 'IPI-018',
        severity,
        confidence,
        offset: detectionOffset,
        excerpt: `[MCP_TOOL_POISON] ${excerpt}`,
        vector: contentType,
        mitigated: true,
      });
    } else if (signalB && signalC) {
      // MEDIUM if override language + namespace collision without schema
      annotations.push({
        id: 'IPI-018',
        severity: 'MEDIUM',
        confidence: 0.7,
        offset: detectionOffset,
        excerpt: `[MCP_TOOL_POISON] ${excerpt}`,
        vector: contentType,
        mitigated: true,
      });
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
