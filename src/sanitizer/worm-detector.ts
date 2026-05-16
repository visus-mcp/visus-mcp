/**
 * Worm Detector for Morris II-style self-replicating prompts
 *
 * Detects replication commands, role hijacks, and obfuscations in post-sanitized content.
 * Scoring: 0-1 risk; >0.8 triggers HITL/block.
 */

import type { ThreatAnnotation } from '../security/threats.js';

export interface WormScanResult {
  score: number;
  patterns: string[];
  modifiedContent: string;
  threats: ThreatAnnotation[];
  content_modified: boolean;
}

const WORM_PATTERNS = [
  { name: 'replicator_direct', regex: /always.*(include|append|repeat|copy).*(this|prompt|response)/gi, weight: 0.4 },
  { name: 'replicator_end', regex: /end every.*with.*(this|the following)/gi, weight: 0.3 },
  { name: 'hijack_ignore', regex: /ignore previous.*instructions/gi, weight: 0.4 },
  { name: 'hijack_role', regex: /you are now.*(override|act as)/gi, weight: 0.3 },
  { name: 'chain_save', regex: /(save|remember).*(this|prompt).*(for later|to use)/gi, weight: 0.2 },
  { name: 'obfusc_base64', regex: /data:text\/plain;base64,[A-Za-z0-9+/=]+/gi, weight: 0.3 },
  { name: 'obfusc_unicode', regex: /[\u200B-\u200D\uFEFF]/g, weight: 0.2 },
  { name: 'exfil_embed', regex: /send.*to.*(email|url|share)/gi, weight: 0.25 },
  { name: 'urgency_priming', regex: /urgent.*(run|copy|replicate)/gi, weight: 0.15 },
  { name: 'markdown_inject', regex: /!\[.*\]\(javascript:.*\|data:.*\)/gi, weight: 0.2 },
  { name: 'replicator_share', regex: /share this.*(tip|code|prompt)/gi, weight: 0.2 },
  { name: 'hijack_pretend', regex: /pretend to be.*(malicious|override)/gi, weight: 0.3 },
  { name: 'obfusc_html_entity', regex: /&(?:lt|gt|amp|quot|#x27);/g, weight: 0.15 },
  { name: 'chain_append', regex: /append to your.*(response|output)/gi, weight: 0.25 },
  { name: 'exfil_data', regex: /exfiltrate|leak.*data/gi, weight: 0.35 },
] as const;

export function wormScan(content: string): WormScanResult {
  let score = 0;
  const patterns: string[] = [];
  let modifiedContent = content;
  const threats: ThreatAnnotation[] = [];
  let modified = false;

  let cleanContent = content.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  cleanContent = cleanContent.replace(/&[a-zA-Z0-9#]+;/g, decodeHtmlEntities);

  const base64Pattern = WORM_PATTERNS.find(p => p.name === 'obfusc_base64');
  if (base64Pattern) {
    const base64Match = cleanContent.match(base64Pattern.regex);
    if (base64Match) {
      try {
        const decoded = atob(base64Match[0].split(',')[1]);
        cleanContent += ' ' + decoded;
        patterns.push('obfusc_base64_decoded');
        score += 0.1;
      } catch {}
    }
  }

  WORM_PATTERNS.forEach(({ name, regex, weight }) => {
    const matches = [...cleanContent.matchAll(regex)];
    if (matches.length > 0) {
      patterns.push(name);
      score += weight * matches.length;
      modified = true;
      matches.forEach(match => {
        modifiedContent = modifiedContent.replace(match[0], '[REDACTED:WORM_' + name.toUpperCase() + ']');
      });
      const idx = matches[0].index ?? 0;
      threats.push({
        id: 'IPI-019' as ThreatAnnotation['id'],
        severity: weight > 0.3 ? 'HIGH' : 'MEDIUM',
        confidence: weight,
        offset: idx,
        excerpt: matches[0][0].substring(0, 100),
        vector: 'html',
        mitigated: true,
      });
    }
  });

  score = Math.min(score, 1.0);

  if (patterns.length > 2) score += 0.1;
  if (patterns.some(p => ['replicator_direct', 'hijack_ignore'].includes(p))) score += 0.2;

  return { score, patterns, modifiedContent, threats, content_modified: modified };
}

function decodeHtmlEntities(str: string): string {
  const entities = { 'lt': '<', 'gt': '>', 'amp': '&', 'quot': '"', '#x27': "'" };
  return str.replace(/&([a-zA-Z0-9#]+);/g, (m, code) => entities[code as keyof typeof entities] || m);
}

export { WORM_PATTERNS };

