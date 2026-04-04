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
    annotations.push(...this.detectIPI008(content, contentType));
    annotations.push(...this.detectIPI009(content, contentType));
    annotations.push(...this.detectIPI010(content, contentType));

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
