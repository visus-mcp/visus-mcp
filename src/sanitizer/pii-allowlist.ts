/**
 * PII Allowlist Configuration
 *
 * Defines trusted phone numbers that should NOT be redacted from web content.
 * Primarily for verified health authority and government emergency numbers.
 *
 * CRITICAL: Only add numbers that are:
 * 1. Publicly published institutional/government numbers
 * 2. Verified health/safety authorities
 * 3. Not personal contact information
 */

export interface TrustedPhoneNumber {
  /** Display name for logging */
  name: string;
  /** Normalized phone number variants (all formats this number might appear in) */
  numbers: string[];
  /** Optional: domains where this number is trusted (empty = trusted everywhere) */
  trustedDomains?: string[];
  /** Category for audit logging */
  category: 'emergency' | 'health_authority' | 'government' | 'helpline';
}

export interface PIIAllowlistConfig {
  /** When true, trusted numbers only preserved if source domain matches trustedDomains */
  strictDomainMode: boolean;
  /** List of verified trusted phone numbers */
  trustedPhoneNumbers: TrustedPhoneNumber[];
}

/**
 * Normalize a phone number to digits-only format for comparison
 */
export function normalizePhoneNumber(phone: string): string {
  return phone.replace(/\D/g, '');
}

/**
 * Extract domain from URL (returns hostname without www.)
 */
export function extractDomain(url: string): string {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return '';
  }
}

/**
 * Built-in allowlist of verified health authority and emergency numbers
 */
export const DEFAULT_ALLOWLIST: PIIAllowlistConfig = {
  strictDomainMode: false, // Default: trust globally, not domain-scoped

  trustedPhoneNumbers: [
    // Emergency Services
    {
      name: 'Emergency Services (911)',
      numbers: ['911'],
      category: 'emergency'
    },

    // Poison Control
    {
      name: 'Poison Control Center',
      numbers: [
        '18002221222',
        '8002221222',
        '1-800-222-1222',
        '800-222-1222'
      ],
      trustedDomains: [
        'medlineplus.gov',
        'cdc.gov',
        'fda.gov',
        'aapcc.org',
        'poison.org',
        'nih.gov',
        'nlm.nih.gov'
      ],
      category: 'health_authority'
    },

    // FDA MedWatch (adverse event reporting)
    {
      name: 'FDA MedWatch',
      numbers: [
        '18003321088',
        '8003321088',
        '1-800-332-1088',
        '800-332-1088'
      ],
      trustedDomains: [
        'fda.gov',
        'medlineplus.gov',
        'cdc.gov',
        'nih.gov'
      ],
      category: 'health_authority'
    },

    // CDC INFO
    {
      name: 'CDC INFO',
      numbers: [
        '18002324636',
        '8002324636',
        '1-800-232-4636',
        '800-232-4636'
      ],
      trustedDomains: [
        'cdc.gov',
        'medlineplus.gov',
        'nih.gov'
      ],
      category: 'health_authority'
    },

    // SAMHSA National Helpline (substance abuse/mental health)
    {
      name: 'SAMHSA National Helpline',
      numbers: [
        '18006624357',
        '8006624357',
        '1-800-662-4357',
        '800-662-4357'
      ],
      trustedDomains: [
        'samhsa.gov',
        'medlineplus.gov',
        'cdc.gov',
        'nih.gov'
      ],
      category: 'helpline'
    },

    // National Suicide Prevention Lifeline
    {
      name: 'National Suicide Prevention Lifeline',
      numbers: [
        '18002738255',
        '8002738255',
        '1-800-273-8255',
        '800-273-8255',
        '988' // New 3-digit code
      ],
      trustedDomains: [
        'suicidepreventionlifeline.org',
        'samhsa.gov',
        'medlineplus.gov',
        'cdc.gov',
        'nih.gov'
      ],
      category: 'helpline'
    },

    // National Domestic Violence Hotline
    {
      name: 'National Domestic Violence Hotline',
      numbers: [
        '18007997233',
        '8007997233',
        '1-800-799-7233',
        '800-799-7233'
      ],
      trustedDomains: [
        'thehotline.org',
        'cdc.gov',
        'medlineplus.gov',
        'nih.gov'
      ],
      category: 'helpline'
    },

    // Medicare
    {
      name: 'Medicare',
      numbers: [
        '18006331795',
        '8006331795',
        '1-800-633-1795',
        '800-633-1795'
      ],
      trustedDomains: [
        'medicare.gov',
        'cms.gov',
        'medlineplus.gov',
        'nih.gov'
      ],
      category: 'government'
    },

    // Veterans Crisis Line
    {
      name: 'Veterans Crisis Line',
      numbers: [
        '18002738255',
        '8002738255',
        '1-800-273-8255',
        '800-273-8255'
      ],
      trustedDomains: [
        'va.gov',
        'veteranscrisisline.net',
        'medlineplus.gov',
        'nih.gov'
      ],
      category: 'helpline'
    }
  ]
};

/**
 * Check if a phone number should be allowlisted (not redacted)
 *
 * @param phoneNumber The phone number to check (in any format)
 * @param sourceUrl Optional source URL for domain-scoped allowlisting
 * @param config Optional custom config (defaults to DEFAULT_ALLOWLIST)
 * @returns The trusted number entry if allowlisted, null otherwise
 */
export function isAllowlistedPhoneNumber(
  phoneNumber: string,
  sourceUrl?: string,
  config: PIIAllowlistConfig = DEFAULT_ALLOWLIST
): TrustedPhoneNumber | null {
  const normalized = normalizePhoneNumber(phoneNumber);
  const sourceDomain = sourceUrl ? extractDomain(sourceUrl) : '';

  for (const trustedEntry of config.trustedPhoneNumbers) {
    // Check if any variant of this trusted number matches
    const matchesNumber = trustedEntry.numbers.some(variant => {
      const normalizedVariant = normalizePhoneNumber(variant);
      return normalized === normalizedVariant;
    });

    if (!matchesNumber) {
      continue; // Number doesn't match, check next entry
    }

    // Number matches - now check domain restrictions
    const hasDomainRestrictions = trustedEntry.trustedDomains && trustedEntry.trustedDomains.length > 0;

    if (!hasDomainRestrictions) {
      // No domain restrictions - trust globally
      return trustedEntry;
    }

    // Has domain restrictions
    if (config.strictDomainMode && !sourceUrl) {
      // Strict mode requires domain match, but no URL provided
      continue;
    }

    if (sourceUrl && trustedEntry.trustedDomains) {
      // Check if source domain matches any trusted domain
      const isDomainTrusted = trustedEntry.trustedDomains.some(trustedDomain => {
        return sourceDomain.endsWith(trustedDomain);
      });

      if (isDomainTrusted) {
        return trustedEntry;
      }
    }

    // In non-strict mode, trust the number even if domain doesn't match
    if (!config.strictDomainMode) {
      return trustedEntry;
    }
  }

  return null; // No match found
}
