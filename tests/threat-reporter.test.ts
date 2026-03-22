/**
 * Threat Reporter Test Suite
 *
 * Tests TOON encoding, Markdown generation, and framework mappings
 */

import { generateThreatReport } from '../src/sanitizer/threat-reporter.js';
import { classifySeverity, aggregateSeverity, countBySeverity, getSeverityEmoji } from '../src/sanitizer/severity-classifier.js';
import { getFrameworkMappings } from '../src/sanitizer/framework-mapper.js';

describe('Threat Reporter', () => {
  describe('generateThreatReport()', () => {
    it('should return null for clean page (no findings)', () => {
      const result = generateThreatReport({
        patterns_detected: [],
        pii_redacted: 0,
        source_url: 'https://example.com'
      });

      expect(result).toBeNull();
    });

    it('should generate report for single HIGH injection', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking'],
        pii_redacted: 0,
        source_url: 'https://malicious.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        expect(result.overall_severity).toBe('CRITICAL'); // role_hijacking is CRITICAL
        expect(result.total_findings).toBe(1);
        expect(result.by_severity.CRITICAL).toBe(1);
        expect(result.by_severity.HIGH).toBe(0);
      }
    });

    it('should classify CRITICAL + MEDIUM as overall CRITICAL', () => {
      const result = generateThreatReport({
        patterns_detected: ['data_exfiltration', 'comment_injection'],
        pii_redacted: 0,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        expect(result.overall_severity).toBe('CRITICAL');
        expect(result.total_findings).toBe(2);
        expect(result.by_severity.CRITICAL).toBe(1);
        expect(result.by_severity.MEDIUM).toBe(1);
      }
    });

    it('should include PII redacted count in report', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking'],
        pii_redacted: 3,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        expect(result.pii_redacted).toBe(3);
        expect(result.report_markdown).toContain('Items Redacted:** 3');
      }
    });

    it('should have non-empty TOON findings string when findings exist', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking'],
        pii_redacted: 0,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        expect(result.findings_toon).toBeTruthy();
        expect(result.findings_toon.length).toBeGreaterThan(0);
      }
    });

    it('should include all required sections in Markdown report', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking', 'data_exfiltration'],
        pii_redacted: 2,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        const md = result.report_markdown;
        expect(md).toContain('Visus Threat Report');
        expect(md).toContain('Findings Summary');
        expect(md).toContain('Findings Detail');
        expect(md).toContain('PII Redaction');
        expect(md).toContain('Remediation Status');
        expect(md).toContain('Generated:');
        expect(md).toContain('Source:');
        expect(md).toContain('Overall Severity:');
      }
    });

    it('should contain valid TOON format with correct field count', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking'],
        pii_redacted: 0,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        const toon = result.findings_toon;
        // TOON should contain findings array with expected fields
        expect(toon).toContain('findings');
      }
    });

    it('should use all four severity emojis in Markdown', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking'], // CRITICAL
        pii_redacted: 0,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        const md = result.report_markdown;
        // Should have severity emojis in the table
        expect(md).toContain('🔴'); // CRITICAL
        expect(md).toContain('🟠'); // HIGH
        expect(md).toContain('🟡'); // MEDIUM
        expect(md).toContain('🟢'); // LOW
      }
    });

    it('should include all three frameworks', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking'],
        pii_redacted: 0,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        expect(result.frameworks).toContain('OWASP LLM Top 10');
        expect(result.frameworks).toContain('NIST AI 600-1');
        expect(result.frameworks).toContain('MITRE ATLAS');
      }
    });

    it('should mark sanitization_applied as true', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking'],
        pii_redacted: 0,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        expect(result.sanitization_applied).toBe(true);
      }
    });

    it('should include timestamp in ISO format', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking'],
        pii_redacted: 0,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        expect(result.generated).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
      }
    });
  });

  describe('Severity Classifier', () => {
    it('should classify role_hijacking as CRITICAL', () => {
      expect(classifySeverity('role_hijacking')).toBe('CRITICAL');
    });

    it('should classify data_exfiltration as CRITICAL', () => {
      expect(classifySeverity('data_exfiltration')).toBe('CRITICAL');
    });

    it('should classify context_poisoning as HIGH', () => {
      expect(classifySeverity('context_poisoning')).toBe('HIGH');
    });

    it('should classify comment_injection as MEDIUM', () => {
      expect(classifySeverity('comment_injection')).toBe('MEDIUM');
    });

    it('should classify leetspeak_obfuscation as LOW', () => {
      expect(classifySeverity('leetspeak_obfuscation')).toBe('LOW');
    });

    it('should aggregate to CLEAN when no findings', () => {
      expect(aggregateSeverity([])).toBe('CLEAN');
    });

    it('should aggregate to CRITICAL when CRITICAL finding present', () => {
      const findings = [
        { pattern_category: 'role_hijacking', severity: 'CRITICAL' as const },
        { pattern_category: 'comment_injection', severity: 'MEDIUM' as const }
      ];
      expect(aggregateSeverity(findings)).toBe('CRITICAL');
    });

    it('should aggregate to HIGH when no CRITICAL but HIGH present', () => {
      const findings = [
        { pattern_category: 'context_poisoning', severity: 'HIGH' as const },
        { pattern_category: 'comment_injection', severity: 'MEDIUM' as const }
      ];
      expect(aggregateSeverity(findings)).toBe('HIGH');
    });

    it('should count findings by severity correctly', () => {
      const findings = [
        { pattern_category: 'role_hijacking', severity: 'CRITICAL' as const },
        { pattern_category: 'data_exfiltration', severity: 'CRITICAL' as const },
        { pattern_category: 'context_poisoning', severity: 'HIGH' as const },
        { pattern_category: 'comment_injection', severity: 'MEDIUM' as const }
      ];

      const counts = countBySeverity(findings);
      expect(counts.CRITICAL).toBe(2);
      expect(counts.HIGH).toBe(1);
      expect(counts.MEDIUM).toBe(1);
      expect(counts.LOW).toBe(0);
    });

    it('should return correct emojis for all severity levels', () => {
      expect(getSeverityEmoji('CRITICAL')).toBe('🔴');
      expect(getSeverityEmoji('HIGH')).toBe('🟠');
      expect(getSeverityEmoji('MEDIUM')).toBe('🟡');
      expect(getSeverityEmoji('LOW')).toBe('🟢');
      expect(getSeverityEmoji('CLEAN')).toBe('✅');
    });
  });

  describe('Framework Mapper', () => {
    it('should map role_hijacking to correct frameworks', () => {
      const mappings = getFrameworkMappings('role_hijacking');
      expect(mappings.owasp_llm).toContain('LLM01:2025');
      expect(mappings.nist_ai_600_1).toContain('MS-2.5');
      expect(mappings.mitre_atlas).toContain('AML.T0051');
    });

    it('should map data_exfiltration to correct frameworks', () => {
      const mappings = getFrameworkMappings('data_exfiltration');
      expect(mappings.owasp_llm).toContain('LLM02:2025');
      expect(mappings.nist_ai_600_1).toContain('MS-2.6');
      expect(mappings.mitre_atlas).toContain('AML.T0048');
    });

    it('should return default mappings for unknown pattern', () => {
      const mappings = getFrameworkMappings('unknown_pattern_xyz');
      expect(mappings.owasp_llm).toContain('LLM01:2025');
      expect(mappings.nist_ai_600_1).toContain('MS-2.5');
      expect(mappings.mitre_atlas).toContain('AML.T0051');
    });
  });
});
