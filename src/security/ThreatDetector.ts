/**
 * Threat Detector for Indirect Prompt Injection (IPI) Attacks
 *
 * Detects and classifies 19 categories of IPI attacks with fine-grained annotations.
 * All detectors run on every scan (no short-circuit) to catch multi-vector attacks.
 *
 * Dual-stage detection:
 * - Raw HTML stage: IPI-011, IPI-012 (via scanRawHtml)
 * - Text stage: IPI-001 through IPI-010, IPI-013 through IPI-020 (via scan)
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

const IPI_018_SHADOW_TOOL_NAMES = [
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
  'visus_fetch',
  'visus_read',
  'visus_search',
  'visus_verify',
  'visus_fetch_structured',
] as const;

const IPI_018_CRITICAL_TOOLS = ['execute_code', 'run_command', 'write_file'] as const;

const IPI_020_CONDITION_KEYWORDS = [
  'if', 'only if', 'when', 'unless', 'in the event that',
  'provided that', 'given that', 'assuming', 'once you have',
  'if you have access to', 'if you are running', 'if this is',
] as const;

const IPI_020_ACTION_VERBS = [
  'exfiltrate', 'send', 'execute', 'call', 'forward', 'transmit',
  'upload', 'post', 'fetch', 'run', 'invoke', 'dispatch',
  'delete', 'rm', 'drop', 'expose', 'leak', 'output', 'print',
  'return', 'reveal', 'disclose',
] as const;

const IPI_020_ENV_SENSITIVE_TARGETS = [
  '.env', 'api_key', 'api key', 'secret', 'credential', 'token',
  'password', 'passwd', 'private key', 'ssh key', 'access key',
  'auth', 'authorization', 'bearer', 'session', 'cookie',
  'database', 'db_url', 'connection string', 'production',
  'staging', 'repository', 'repo', 'filesystem', 'file system',
  'config', 'configuration', 'environment variable', 'env var',
  '.pem', '.key', '.cert', 'keystore', 'vault',
] as const;

const IPI_020_CRITICAL_ACTION_VERBS = [
  'exfiltrate', 'delete', 'rm', 'drop', 'execute',
] as const;

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
    annotations.push(...this.detectIPI019(content, contentType));
    annotations.push(...this.detectIPI020(content, contentType));

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
    let signalAIsCritical = false;
    let signalCIsCritical = false;
    let signalAOffset = 0;
    let signalCOffset = 0;

    // ── Signal A: MCP schema structure mimicry ──
    const schemaPatterns = [
      /"name"\s*:\s*"([^"]+)"[^}]{0,200}"description"\s*:\s*"[^"]+"[^}]{0,200}"(?:inputSchema|parameters)"/gi,
      /\bname\s*:\s*(\w+)[^\n]{0,200}description\s*:[^\n]{0,200}(?:inputSchema|parameters)/gi,
    ];

    for (const pattern of schemaPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(content)) !== null) {
        const nameValue = match[1].toLowerCase();
        const isShadow = IPI_018_SHADOW_TOOL_NAMES.some(
          t => t.toLowerCase() === nameValue
        );
        if (!isShadow) continue;
        const spanLength = match[0].length;
        if (spanLength > 300) continue;
        signalA = true;
        signalAOffset = match.index;
        if (IPI_018_CRITICAL_TOOLS.some(t => t.toLowerCase() === nameValue)) {
          signalAIsCritical = true;
        }
        break;
      }
      if (signalA) break;
    }

    // ── Signal B: Tool capability override language ──
    const overridePatterns = [
      /use this tool instead of/gi,
      /this tool replaces/gi,
      /preferred tool for/gi,
      /ignore the existing\s+\w+/gi,
      /the correct tool to use is/gi,
      /when asked to\s+\w+,?\s*call/gi,
      /override tool/gi,
      /tool priority:/gi,
    ];

    for (const pattern of overridePatterns) {
      if (pattern.test(content)) {
        signalB = true;
        break;
      }
    }

    // ── Signal C: Namespace collision attempt (Levenshtein ≤ 1) ──
    const tokenRegex = /\b[a-zA-Z_][a-zA-Z0-9_]{2,30}\b/g;
    let tokenMatch: RegExpExecArray | null;
    while ((tokenMatch = tokenRegex.exec(content)) !== null) {
      const token = tokenMatch[0];
      // Skip exact case-sensitive matches (those are SIGNAL A or innocent verbatim references)
      if (IPI_018_SHADOW_TOOL_NAMES.includes(token as typeof IPI_018_SHADOW_TOOL_NAMES[number])) {
        continue;
      }
      for (const shadowName of IPI_018_SHADOW_TOOL_NAMES) {
        if (!ThreatDetector.isEditDistanceAtMost1(token, shadowName)) continue;
        // Check proximity context for parameter-like structures AND action verbs
        const ctxStart = Math.max(0, tokenMatch.index - 100);
        const ctxEnd = Math.min(content.length, tokenMatch.index + token.length + 100);
        const ctx = content.substring(ctxStart, ctxEnd);
        const hasParamStructure = /\b(?:parameter|argument|input|schema|field|property|config|option|setting)s?\b/i.test(ctx)
          || /\{[^}]*:[^}]*\}/.test(ctx);
        const hasActionVerb = /\b(?:run|execute|call|invoke|use|perform|trigger|dispatch|operate)\b/i.test(ctx);
        if (hasParamStructure && hasActionVerb) {
          signalC = true;
          signalCOffset = tokenMatch.index;
          if (IPI_018_CRITICAL_TOOLS.includes(shadowName as any)) {
            signalCIsCritical = true;
          }
          break;
        }
      }
      if (signalC) break;
    }

    // ── Severity escalation ──
    if (signalA) {
      const severity = (signalB || signalAIsCritical) ? 'CRITICAL' : 'HIGH';
      const confidence = (signalB || signalAIsCritical) ? 0.95 : 0.85;
      annotations.push({
        id: 'IPI-018',
        severity,
        confidence,
        offset: signalAOffset,
        excerpt: `[MCP_SCHEMA_SHADOW] ${this.extractExcerpt(content, signalAOffset, 120)}`,
        vector: contentType,
        mitigated: true,
      });
    }

    if (signalC) {
      const severity = signalCIsCritical ? 'CRITICAL' : 'HIGH';
      const confidence = signalCIsCritical ? 0.95 : 0.80;
      annotations.push({
        id: 'IPI-018',
        severity,
        confidence,
        offset: signalCOffset,
        excerpt: `[MCP_NAMESPACE_COLLISION] ${this.extractExcerpt(content, signalCOffset, 120)}`,
        vector: contentType,
        mitigated: true,
      });
    }

    return annotations;
  }

  /**
   * Detect IPI-019: Multi-Agent Propagation Worm
   *
   * Detects indirect prompt injection payloads that instruct a compromised
   * LLM agent to embed copies of the same payload into its outputs, causing
   * recursive infection of downstream agents. Uses multi-signal scoring:
   * - Group A: Propagation Verbs (weight 1)
   * - Group B: Target References (weight 2)
   * - Group C: Self-Replication Framing (weight 3)
   * - Group D: Compound Trigger (weight 4, requires A+B within 200 chars)
   *
   * @private
   */
  private detectIPI019(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    if (content.length > 1_000_000) {
      return annotations;
    }

    let groupAWeight = 0;
    let groupBWeight = 0;
    let groupCWeight = 0;
    let groupDWeight = 0;
    let detectionOffset = -1;

    // Group A: Propagation Verbs in imperative context (weight 1)
    const imperativePropagationPatterns = [
      /\b(you\s+(?:must|should|need\s+to|have\s+to)|please|ensure\s+that|make\s+sure\s+to|always|never)\s+(?:append|forward|embed|relay|propagate|inject)\b/i,
      /\b(append|forward|embed|relay|propagate)\s+(?:this|these|the\s+following|instructions?)\b/i,
      /\binject\s+(?:this|these|content|instructions?)\b/i,
      /\bpass\s+(?:this|these|it|instructions?)\s+(?:along|forward|to)\b/i,
      /\bcopy\s+(?:this|these|instructions?)\s+(?:verbatim|into|to|forward)\b/i,
      /\brelay\s+(?:this|these|instructions?|content)\b/i,
      /\binclude\s+(?:the\s+following|this|these)\b/i,
    ];

    for (const pattern of imperativePropagationPatterns) {
      const match = pattern.exec(content);
      if (match) {
        groupAWeight += 1;
        if (detectionOffset === -1) {
          detectionOffset = match.index;
        }
      }
    }

    // Group B: Target References to AI agents (weight 2)
    const targetRefPatterns = [
      /\bother\s+agents?\b/i,
      /\bdownstream\s+(?:agents?|tools?|systems?)\b/i,
      /\bAI\s+(?:that\s+)?(?:is\s+)?reading\s+this\b/i,
      /\byour\s+system\s+prompt\b/i,
      /\byour\s+(?:tool\s+)?output\b/i,
      /\bthe\s+next\s+LLM\b/i,
      /\bfuture\s+readers?\b/i,
      /\bany\s+(?:subsequent|downstream)\s+(?:model|agent)\b/i,
      /\ball\s+downstream\b/i,
      /\bany\s+AI\s+reading\b/i,
      /\bAI\s+agents?\b/i,
    ];

    for (const pattern of targetRefPatterns) {
      const match = pattern.exec(content);
      if (match) {
        groupBWeight += 2;
        if (detectionOffset === -1) {
          detectionOffset = match.index;
        }
      }
    }

    // Group C: Self-Replication Framing (weight 3)
    const selfRepPatterns = [
      /\bensure\s+(?:this\s+)?(?:text|content|instructions?)\s+(?:survive|intact|unchanged)\b/i,
      /\bpreserve\s+(?:these|this|the\s+above)\s+instructions?\b/i,
      /\brepeat\s+verbatim\s+(?:in\s+)?(?:your\s+)?(?:response|output)\b/i,
      /\b(?:include|embed)\s+(?:the\s+following|this|these\s+instructions?)\s+in\s+(?:every|all|each)\s+(?:response|output|message|tool\s+call)\b/i,
      /\bpass\s+(?:this\s+)?(?:along|forward)\s+(?:unchanged|intact|to\s+any)\b/i,
      /\bnever\s+omit\s+(?:this|these)\s+(?:section|instructions?)\b/i,
      /\bkeep\s+(?:these|this)\s+instructions?\s+intact\b/i,
      /\bensure\s+this\s+(?:text|content)\b/i,
      /\bverbatim\b/i,
      /\bsurvive\s+(?:intact|unchanged)\b/i,
      /\bforward\s+to\s+other\b/i,
      /\binto\s+every\s+tool\s+call\b/i,
      /\bevery\s+(?:tool\s+call|result|response)\b/i,
    ];

    for (const pattern of selfRepPatterns) {
      const match = pattern.exec(content);
      if (match) {
        groupCWeight += 3;
        if (detectionOffset === -1) {
          detectionOffset = match.index;
        }
      }
    }

    // Group D: Compound Trigger - requires A+B within 200 chars
    const compoundPattern = /(?:append|forward|embed|relay|propagate|inject|copy|pass\s+along|ensure|include)\b.{0,200}?(?:other\s+agents?|downstream\s+(?:tools?|agents?|systems?)|AI\s+reading\s+this|your\s+system\s+prompt|tool\s+output|the\s+next\s+LLM|any\s+subsequent)/i;
    const compoundMatch = compoundPattern.exec(content);
    if (compoundMatch) {
      groupDWeight += 4;
      if (detectionOffset === -1) {
        detectionOffset = compoundMatch.index;
      }
    }

    const totalWeight = groupAWeight + groupBWeight + groupCWeight + groupDWeight;

    // FALSE POSITIVE FILTERING
    // Check for third-person descriptive mood (architecture documentation)
    const descriptiveMoodPatterns = [
      /(?:the\s+)?(?:message\s+)?relay\s+service\s+forwards/i,
      /\beach\s+agent\s+includes/i,
      /\bthe\s+agent\s+(?:relays|includes|forwards)/i,
      /\bpipeline\s+(?:ensures|propagates|processes)/i,
    ];

    const isDescriptive = descriptiveMoodPatterns.some(p => p.test(content));

    // Check for DevOps/CI/CD context
    const devopsContextPatterns = [
      /\b(?:ci|cd|pipeline|build|deploy)\b/i,
      /\bc(?:i\/c|d)\s+pipeline/i,
      /\bdownstream\s+(?:systems?|environments?|servers?)\b/i,
    ];

    const isDevOpsContext = devopsContextPatterns.some(p => p.test(content)) && 
      /\b(propagate|forward|include)\b/i.test(content);

    // Check for legitimate email forwarding
    const emailContextPatterns = [
      /\bforward\s+(?:this\s+)?email\s+(?:to|all)/i,
      /\bdistribution\s+list\b/i,
      /\brecipients?\b/i,
    ];

    const isEmailContext = emailContextPatterns.some(p => p.test(content)) && 
      !/\b(agent|AI|LLM|model|system\s+prompt|tool\s+output)\b/i.test(content);

    // Check for compliance disclaimer context
    const complianceContextPatterns = [
      /\b(?:compliance|legal|policy|disclaimer)\b/i,
      /\bgenerated\s+by\s+AI\b/i,
      /\bshould\s+be\s+verified\b/i,
    ];

    const isComplianceContext = complianceContextPatterns.some(p => p.test(content)) &&
      /\bin\s+every\s+response\b/i.test(content);

    // Apply false positive filters
    if (isDescriptive || isEmailContext || isComplianceContext) {
      // Suppress detection entirely for these benign contexts
      return annotations;
    }

    // For DevOps context, reduce severity but don't suppress entirely
    if (isDevOpsContext) {
      // If we would detect with medium+ confidence, reduce to LOW
      if (totalWeight >= 3) {
        const excerpt = this.extractExcerpt(content, detectionOffset >= 0 ? detectionOffset : 0, 120);
        annotations.push({
          id: 'IPI-019',
          severity: 'LOW',
          confidence: 0.35,
          offset: detectionOffset >= 0 ? detectionOffset : 0,
          excerpt: `[PROPAGATION_WORM] ${excerpt}`,
          vector: contentType,
          mitigated: true,
          delivery_method: 'multi_agent_propagation',
        });
        return annotations;
      }
      return annotations;
    }

    // Determine severity and confidence
    if (totalWeight >= 6) {
      const excerpt = this.extractExcerpt(content, detectionOffset >= 0 ? detectionOffset : 0, 120);
      annotations.push({
        id: 'IPI-019',
        severity: 'HIGH',
        confidence: 0.85,
        offset: detectionOffset >= 0 ? detectionOffset : 0,
        excerpt: `[PROPAGATION_WORM] ${excerpt}`,
        vector: contentType,
        mitigated: true,
        delivery_method: 'multi_agent_propagation',
      });
    } else if (totalWeight >= 3) {
      const excerpt = this.extractExcerpt(content, detectionOffset >= 0 ? detectionOffset : 0, 120);
      annotations.push({
        id: 'IPI-019',
        severity: 'MEDIUM',
        confidence: 0.65,
        offset: detectionOffset >= 0 ? detectionOffset : 0,
        excerpt: `[PROPAGATION_WORM] ${excerpt}`,
        vector: contentType,
        mitigated: true,
        delivery_method: 'multi_agent_propagation',
      });
    } else if (totalWeight >= 1) {
      const excerpt = this.extractExcerpt(content, detectionOffset >= 0 ? detectionOffset : 0, 120);
      annotations.push({
        id: 'IPI-019',
        severity: 'LOW',
        confidence: 0.45,
        offset: detectionOffset >= 0 ? detectionOffset : 0,
        excerpt: `[PROPAGATION_WORM] ${excerpt}`,
        vector: contentType,
        mitigated: true,
        delivery_method: 'multi_agent_propagation',
      });
    }

    return annotations;
  }

  /**
   * Detect IPI-020: Conditional/Dormant Trigger
   *
   * Detects conditional logic payloads embedded in web content that instruct
   * an LLM agent to perform a malicious action ONLY when a specific
   * environmental condition is met. Uses three-signal detection:
   * - Signal A: Condition keyword + action verb proximity
   * - Signal B: Environment-sensitive target proximity
   * - Signal C: Dormancy/stealth marker
   *
   * @private
   */
  private detectIPI020(content: string, contentType: ContentType): ThreatAnnotation[] {
    const annotations: ThreatAnnotation[] = [];

    if (content.length > 1_000_000) {
      return annotations;
    }

    let signalA = false;
    let signalACritical = false;
    let signalAOffset = 0;
    let signalB = false;
    let signalC = false;
    let signalCOffset = 0;
    let windowHasEnvMarker = false;

    const sortedConditions = [...IPI_020_CONDITION_KEYWORDS].sort((a, b) => b.length - a.length);

    for (const conditionKeyword of sortedConditions) {
      const escapedCondition = conditionKeyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const conditionRegex = new RegExp(`\\b${escapedCondition}\\b`, 'gi');
      let condMatch: RegExpExecArray | null;

      while ((condMatch = conditionRegex.exec(content)) !== null) {
        const windowStart = condMatch.index;
        const windowEnd = Math.min(content.length, condMatch.index + condMatch[0].length + 150);
        const window = content.substring(windowStart, windowEnd);

        for (const verb of IPI_020_ACTION_VERBS) {
          const escapedVerb = verb.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const verbRegex = new RegExp(`\\b${escapedVerb}\\b`, 'i');
          const verbMatch = verbRegex.exec(window);
          if (verbMatch) {
            signalA = true;
            signalAOffset = condMatch.index;
            if (IPI_020_CRITICAL_ACTION_VERBS.some(cv => cv.toLowerCase() === verb.toLowerCase())) {
              signalACritical = true;
            }
            const urlPattern = /https?:\/\//i;
            const filePathPattern = /(\/[\w.]+){2,}|[\w]+\.[a-z]{2,4}/i;
            const varPattern = /\b[A-Z][A-Z0-9_]{2,}\b/;
            const bracketPattern = /[{[\(]/;
            windowHasEnvMarker = urlPattern.test(window) || filePathPattern.test(window) || 
              varPattern.test(window) || bracketPattern.test(window) || 
              /@/.test(window) || IPI_020_ENV_SENSITIVE_TARGETS.some(t => window.toLowerCase().includes(t.toLowerCase()));
            break;
          }
        }
        if (signalA) break;
      }
      if (signalA) break;
    }

    if (signalA) {
      const bWindowStart = Math.max(0, signalAOffset - 50);
      const bWindowEnd = Math.min(content.length, signalAOffset + 300);
      const bWindow = content.substring(bWindowStart, bWindowEnd).toLowerCase();

      for (const target of IPI_020_ENV_SENSITIVE_TARGETS) {
        const commonTargets = ['auth', 'config', 'cookie', 'session', 'secret', 'token', 'vault', 'bearer'];
        let found = false;
        if (commonTargets.includes(target)) {
          const escapedTarget = target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const targetRegex = new RegExp(`\\b${escapedTarget}\\b`, 'i');
          found = targetRegex.test(bWindow);
        } else {
          found = bWindow.includes(target.toLowerCase());
        }
        if (found) {
          signalB = true;
          break;
        }
      }
    }

    const dormancyPatterns = [
      /\b(?:do\s+not\s+act|only\s+act|remain\s+(?:silent|dormant|hidden))\b/gi,
      /\b(?:wait\s+until\s+you|hold\s+(?:off|back)|defer\s+(?:until|this))\b/gi,
      /\buntil\s+you\s+(?:have|find|detect|see|confirm)\b/gi,
      /\b(?:invisible|undetected|bypass(?:ing)?\s+(?:security|detection|filters))\b/gi,
      /\b(?:only\s+execute|only\s+run|only\s+send)\s+(?:if|when|this)\b/gi,
    ];

    for (const pattern of dormancyPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      const match = regex.exec(content);
      if (match) {
        signalC = true;
        signalCOffset = match.index;
        break;
      }
    }

    const benignContextPatterns = [
      /\b(?:temperature|weather|recipe|bake|cook|oven|boil|simmer)\b/i,
      /\b(?:callback|function|response|status\s+code|http|api\s+endpoint)\b/i,
      /\bif\s+the\s+(?:response|request|server|status|user)\s+(?:is|returns?|equals?)\b/i,
    ];

    const isBenignSignalAOnly = signalA && !signalB && !signalC && !signalACritical &&
      benignContextPatterns.some(p => {
        const ctxStart = Math.max(0, signalAOffset - 100);
        const ctxEnd = Math.min(content.length, signalAOffset + 100);
        return p.test(content.substring(ctxStart, ctxEnd));
      });

    const isTentativeSignalA = signalA && !signalB && !signalACritical && !windowHasEnvMarker;

    if (signalA && signalB && signalACritical) {
      annotations.push({
        id: 'IPI-020',
        severity: 'CRITICAL',
        confidence: 0.95,
        offset: signalAOffset,
        excerpt: `[DORMANT_CRIT_TRIGGER] ${this.extractExcerpt(content, signalAOffset, 120)}`,
        vector: contentType,
        mitigated: true,
      });
    } else if (signalA && signalACritical) {
      annotations.push({
        id: 'IPI-020',
        severity: 'CRITICAL',
        confidence: 0.90,
        offset: signalAOffset,
        excerpt: `[DORMANT_CRIT_TRIGGER] ${this.extractExcerpt(content, signalAOffset, 120)}`,
        vector: contentType,
        mitigated: true,
      });
    } else if (signalA && signalB && signalC) {
      annotations.push({
        id: 'IPI-020',
        severity: 'HIGH',
        confidence: 0.90,
        offset: signalAOffset,
        excerpt: `[DORMANT_ENV_TRIGGER] ${this.extractExcerpt(content, signalAOffset, 120)}`,
        vector: contentType,
        mitigated: true,
      });
    } else if (signalA && signalB) {
      annotations.push({
        id: 'IPI-020',
        severity: 'HIGH',
        confidence: 0.90,
        offset: signalAOffset,
        excerpt: `[DORMANT_ENV_TRIGGER] ${this.extractExcerpt(content, signalAOffset, 120)}`,
        vector: contentType,
        mitigated: true,
      });
    } else if (signalA && signalC) {
      annotations.push({
        id: 'IPI-020',
        severity: 'HIGH',
        confidence: 0.85,
        offset: signalAOffset,
        excerpt: `[DORMANT_TRIGGER] ${this.extractExcerpt(content, signalAOffset, 120)}`,
        vector: contentType,
        mitigated: true,
      });
    } else if (signalA && !isBenignSignalAOnly && !isTentativeSignalA) {
      annotations.push({
        id: 'IPI-020',
        severity: 'HIGH',
        confidence: 0.75,
        offset: signalAOffset,
        excerpt: `[DORMANT_TRIGGER] ${this.extractExcerpt(content, signalAOffset, 120)}`,
        vector: contentType,
        mitigated: true,
      });
    } else if (signalC && !signalA) {
      annotations.push({
        id: 'IPI-020',
        severity: 'MEDIUM',
        confidence: 0.65,
        offset: signalCOffset,
        excerpt: `[DORMANT_MARKER] ${this.extractExcerpt(content, signalCOffset, 120)}`,
        vector: contentType,
        mitigated: true,
      });
    }

    return annotations;
  }

  /**
   * Check if edit distance between two strings is at most 1 (case-sensitive)
   *
   * @private
   */
  private static isEditDistanceAtMost1(a: string, b: string): boolean {
    const m = a.length;
    const n = b.length;
    if (Math.abs(m - n) > 1) return false;
    let edits = 0;
    let i = 0;
    let j = 0;
    while (i < m && j < n) {
      if (a[i] !== b[j]) {
        if (edits === 1) return false;
        edits++;
        if (m > n) i++;
        else if (m < n) j++;
        else { i++; j++; }
      } else {
        i++;
        j++;
      }
    }
    edits += (m - i) + (n - j);
    return edits <= 1;
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
