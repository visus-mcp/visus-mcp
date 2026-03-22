/**
 * PII Redaction Engine
 *
 * Detects and redacts personally identifiable information (PII) from content
 * to prevent leakage of sensitive data to the LLM.
 *
 * Redacts: emails, phone numbers, SSNs, credit cards, IP addresses
 * Supports allowlisting of trusted institutional phone numbers (e.g., Poison Control)
 */

import {
  isAllowlistedPhoneNumber,
  type PIIAllowlistConfig,
  DEFAULT_ALLOWLIST
} from './pii-allowlist.js';

export interface PIIRedactionResult {
  content: string;
  pii_types_redacted: string[];
  pii_allowlisted: Array<{ type: string; value: string; reason: string }>;
  content_modified: boolean;
  metadata: {
    redaction_counts: Record<string, number>;
    allowlist_counts: Record<string, number>;
  };
}

interface PIIPattern {
  type: string;
  name: string;
  regex: RegExp;
  validator?: (match: string) => boolean;
}

/**
 * PII detection patterns with validators
 */
const PII_PATTERNS: PIIPattern[] = [
  // Email addresses
  {
    type: 'EMAIL',
    name: 'email',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    validator: (match: string) => {
      // Basic email validation
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(match);
    }
  },

  // Phone numbers (US and international formats)
  {
    type: 'PHONE',
    name: 'phone',
    regex: /(\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    validator: (match: string) => {
      // Remove non-digits and check length
      const digits = match.replace(/\D/g, '');
      return digits.length >= 10 && digits.length <= 15;
    }
  },

  // US Social Security Numbers
  {
    type: 'SSN',
    name: 'ssn',
    regex: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
    validator: (match: string) => {
      const digits = match.replace(/\D/g, '');
      // Basic SSN format check (9 digits)
      if (digits.length !== 9) return false;
      // Reject invalid SSN patterns
      if (digits === '000000000') return false;
      if (digits.startsWith('000')) return false;
      if (digits.startsWith('666')) return false;
      if (digits.startsWith('9')) return false;
      return true;
    }
  },

  // Credit card numbers (13-19 digits with optional separators)
  // Matches: 4-4-4-4 (Visa/MC), 4-6-5 (AmEx), or continuous digits
  {
    type: 'CC',
    name: 'credit_card',
    regex: /\b(?:\d{4}[\s-]?\d{6}[\s-]?\d{5}|\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4,7}|\d{13,19})\b/g,
    validator: (match: string) => {
      const digits = match.replace(/\D/g, '');
      if (digits.length < 13 || digits.length > 19) return false;
      return luhnCheck(digits);
    }
  },

  // IPv4 addresses
  {
    type: 'IP',
    name: 'ipv4',
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    validator: (match: string) => {
      // Exclude common non-PII patterns like version numbers
      if (match.startsWith('0.0.0')) return false;
      if (match.startsWith('255.255.255')) return false;
      return true;
    }
  },

  // IPv6 addresses (simplified pattern)
  {
    type: 'IP',
    name: 'ipv6',
    regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
    validator: () => true
  },

  // US Passport numbers
  {
    type: 'PASSPORT',
    name: 'passport',
    regex: /\b[A-Z]{1,2}\d{6,9}\b/g,
    validator: (match: string) => {
      // Basic format: 1-2 letters + 6-9 digits
      return /^[A-Z]{1,2}\d{6,9}$/.test(match);
    }
  },

  // Driver's license patterns (varies by state, general pattern)
  {
    type: 'DL',
    name: 'drivers_license',
    regex: /\b[A-Z]{1,2}\d{5,8}\b/g,
    validator: (match: string) => {
      // Overlap with passport, but keep for completeness
      return /^[A-Z]{1,2}\d{5,8}$/.test(match);
    }
  }
];

/**
 * Luhn algorithm for credit card validation
 */
function luhnCheck(digits: string): boolean {
  let sum = 0;
  let alternate = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits.charAt(i), 10);

    if (alternate) {
      n *= 2;
      if (n > 9) {
        n = n - 9;
      }
    }

    sum += n;
    alternate = !alternate;
  }

  return sum % 10 === 0;
}

/**
 * Redact PII from content
 *
 * @param content Content to redact PII from
 * @param sourceUrl Optional source URL for domain-scoped allowlisting
 * @param allowlistConfig Optional custom allowlist config
 */
export function redactPII(
  content: string,
  sourceUrl?: string,
  allowlistConfig: PIIAllowlistConfig = DEFAULT_ALLOWLIST
): PIIRedactionResult {
  const piiTypesRedacted = new Set<string>();
  const redactionCounts: Record<string, number> = {};
  const allowlistCounts: Record<string, number> = {};
  const piiAllowlisted: Array<{ type: string; value: string; reason: string }> = [];
  let sanitizedContent = content;

  for (const pattern of PII_PATTERNS) {
    const matches = Array.from(sanitizedContent.matchAll(pattern.regex));

    for (const match of matches) {
      const matchedText = match[0];

      // Apply validator if present
      if (pattern.validator && !pattern.validator(matchedText)) {
        continue;
      }

      // Check allowlist for phone numbers
      if (pattern.type === 'PHONE') {
        const allowlistedEntry = isAllowlistedPhoneNumber(
          matchedText,
          sourceUrl,
          allowlistConfig
        );

        if (allowlistedEntry) {
          // This is a trusted number - DO NOT redact
          piiAllowlisted.push({
            type: pattern.type,
            value: matchedText,
            reason: `Trusted ${allowlistedEntry.category}: ${allowlistedEntry.name}`
          });
          allowlistCounts[pattern.name] = (allowlistCounts[pattern.name] || 0) + 1;
          continue; // Skip redaction
        }
      }

      // Redact the PII
      sanitizedContent = sanitizedContent.replace(
        matchedText,
        `[REDACTED:${pattern.type}]`
      );

      piiTypesRedacted.add(pattern.name);
      redactionCounts[pattern.name] = (redactionCounts[pattern.name] || 0) + 1;
    }
  }

  return {
    content: sanitizedContent,
    pii_types_redacted: Array.from(piiTypesRedacted),
    pii_allowlisted: piiAllowlisted,
    content_modified: sanitizedContent !== content,
    metadata: {
      redaction_counts: redactionCounts,
      allowlist_counts: allowlistCounts
    }
  };
}

/**
 * Check if content contains any PII (without redacting)
 */
export function containsPII(content: string): boolean {
  for (const pattern of PII_PATTERNS) {
    const matches = Array.from(content.matchAll(pattern.regex));

    for (const match of matches) {
      if (!pattern.validator || pattern.validator(match[0])) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Get list of PII types detected (without redacting)
 */
export function detectPIITypes(content: string): string[] {
  const detected = new Set<string>();

  for (const pattern of PII_PATTERNS) {
    const matches = Array.from(content.matchAll(pattern.regex));

    for (const match of matches) {
      if (!pattern.validator || pattern.validator(match[0])) {
        detected.add(pattern.name);
      }
    }
  }

  return Array.from(detected);
}
