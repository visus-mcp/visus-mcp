/**
 * Worm Detector for Morris II-style self-replicating prompts
 *
 * Detects replication commands, role hijacks, and obfuscations in post-sanitized content.
 * Scoring: 0-1 risk; >0.8 triggers HITL/block.
 */

import { ThreatAnnotation } from '../../security/threats.js';

export interface WormScanResult {
  score: number;
  patterns: string[];
  modifiedContent: string;
  threats: ThreatAnnotation[]; // For summary integration
}

const WORM_PATTERNS = [
  { name: 'replicator_direct', regex: /always.*(include|append|repeat|copy).*(this|prompt|response)/i, weight: 0.4 },
  { name: 'replicator_end', regex: /end every.*with.*(this|the following)/i, weight: 0.3 },
  { name: 'hijack_ignore', regex: /ignore previous.*instructions/i, weight: 0.4 },
  { name: 'hijack_role', regex: /you are now.*(override|act as)/i, weight: 0.3 },
  { name: 'chain_save', regex: /(save|remember).*(this|prompt).*(for later|to use)/i, weight: 0.2 },
  { name: 'obfusc_base64', regex: /data:text\/plain;base64,[A-Za-z0-9+/=]+/i, weight: 0.3 }, // Decode check needed
  { name: 'obfusc_unicode', regex: /[\u200B-\u200D\uFEFF]/, weight: 0.2 }, // Zero-width
  { name: 'exfil_embed', regex: /send.*to.*(email|url|share)/i, weight: 0.25 },
  { name: 'urgency_priming', regex: /urgent.*(run|copy|replicate)/i, weight: 0.15 },
  { name: 'markdown_inject', regex: /!\[.*\]\(javascript:.*\|data:.*\)/i, weight: 0.2 },
  // Add 5 more as needed for 15 total
  { name: 'replicator_share', regex: /share this.*(tip|code|prompt)/i, weight: 0.2 },
  { name: 'hijack_pretend', regex: /pretend to be.*(malicious|override)/i, weight: 0.3 },
  { name: 'obfusc_html_entity', regex: /&(?:lt|gt|amp|quot|#x27);/, weight: 0.15 }, // Decode
  { name: 'chain_append', regex: /append to your.*(response|output)/i, weight: 0.25 },
  { name: 'exfil_data', regex: /exfiltrate|leak.*data/i, weight: 0.35 },
] as const;

export function wormScan(content: string): WormScanResult {
  let score = 0;
  const patterns: string[] = [];
  let modifiedContent = content;
  const threats: ThreatAnnotation[] = [];
  let modified = false;

  // Strip obfuscations for base scan
  let cleanContent = content.normalize('NFD').replace(/[\u0300-\u036f]/g, ''); // Unicode normalize
  cleanContent = cleanContent.replace(/&[a-zA-Z0-9#]+;/g, decodeHtmlEntities); // Entity decode

  // Decode Base64 if present
  const base64Match = cleanContent.match(WORM_PATTERNS.find(p => p.name === 'obfusc_base64')?.regex);
  if (base64Match) {
    try {
      const decoded = atob(base64Match[0].split(',')[1]);
      // Re-scan decoded for patterns
      cleanContent += ' ' + decoded;
      patterns.push('obfusc_base64_decoded');
      score += 0.1; // Bonus for decoding
    } catch {}
  }

  // Scan patterns
  WORM_PATTERNS.forEach(({ name, regex, weight }) => {
    const matches = [...cleanContent.matchAll(regex)];
    if (matches.length > 0) {
      patterns.push(name);
      score += weight * matches.length;
      modified = true;
      // Redact matches
      matches.forEach(match => {
        modifiedContent = modifiedContent.replace(match[0], `[REDACTED:WORM_${name.toUpperCase()}]`);
      });
      threats.push({ type: 'worm', pattern: name, locations: matches.map(m => m.index ?? 0), severity: 'high' });
    }
  });

  // Cap score 0-1
  score = Math.min(score, 1.0);

  // Context scoring: >2 patterns + high weights
  if (patterns.length > 2) score += 0.1;
  if (patterns.some(p => ['replicator_direct', 'hijack_ignore'].includes(p))) score += 0.2;

  return { score, patterns, modifiedContent, threats, content_modified: modified };
}

// Simple HTML entity decoder
function decodeHtmlEntities(str: string): string {
  const entities = { 'lt': '<', 'gt': '>', 'amp': '&', 'quot': '"', '#x27': "'" };
  return str.replace(/&([a-zA-Z0-9#]+);/g, (m, code) => entities[code as keyof typeof entities] || m);
}

export { WORM_PATTERNS };
