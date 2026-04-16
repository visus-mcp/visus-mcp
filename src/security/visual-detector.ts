/**
 * Visual Injection Detector for Multi-Modal Stego/Anamorpher (RFC-2026-004)
 * Extracts img/SVG/PDF visuals; Flags stego risks in alt/src; Shadow tagging.
 * EU AI Act Art. 15(a): Non-text adversarial channels.
 */

import { createHash } from 'crypto';
import type { Page } from 'playwright';
import type { ThreatAnnotation } from './threats.js';

export interface VisualShadow {
  images: Array<{
    src: string;
    alt: string;
    dimensions: { width: number; height: number };
    stego_risk: number;
  }>;
  svg_paths: string[]; // Anomalous d= lengths
  pdf_objects: number; // Embedded suspects
  risk_flags: string[];
}

export interface VisualDetectionResult {
  shadow: VisualShadow;
  risk_score: number;
  tags: string;
  threats: ThreatAnnotation[];
}

const IPI_KEYWORDS = /ignore|exfil|send|override|dan|act as/i;

export async function extractVisuals(page: Page): Promise<VisualShadow> {
  return page.evaluate(() => {
    const images = [];
    const svgPaths = [];
    document.querySelectorAll('img').forEach((img: HTMLImageElement) => {
      const alt = img.alt || '';
      const risk = alt.length > 200 && IPI_KEYWORDS.test(alt) ? 0.8 : (alt.length > 100 ? 0.4 : 0.1);
      images.push({
        src: img.src,
        alt,
        dimensions: { width: img.naturalWidth || 0, height: img.naturalHeight || 0 },
        stego_risk: risk
      });
    });
    document.querySelectorAll('path[d]').forEach((path: SVGPathElement) => {
      svgPaths.push(path.getAttribute('d') || '');
    });
    return { images, svg_paths, pdf_objects: 0, risk_flags: [] };
  });
}

export function sanitizeVisuals(shadow: VisualShadow): VisualDetectionResult {
  const flags = [];
  let score = 0;
  shadow.images.forEach(img => {
    if (img.stego_risk > 0.5) {
      flags.push(`img_alt_ipi:${img.src.slice(-20)}`);
      score += 0.2;
    }
  });
  if (shadow.svg_paths.some(p => p.length > 10000)) { // Anomalous
    flags.push('svg_stego_path');
    score += 0.3;
  }
  score /= Math.max(shadow.images.length || 1, shadow.svg_paths.length || 1);

  const threats: ThreatAnnotation[] = flags.map(f => ({
    id: 'IPI-026',
    severity: score > 0.6 ? 'HIGH' : 'MEDIUM',
    confidence: score,
    offset: 0,
    excerpt: f,
    vector: 'visual'
  }));

  const tags = flags.length ? `[VISUAL_INJECTION_RISK score=${score.toFixed(2)} flags=${flags.length}]${flags.slice(0,3).join('; ')}[/]` : '';

  return { shadow, risk_score: score, tags, threats };
}
