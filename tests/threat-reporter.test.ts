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

    it('should include all four frameworks', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking'],
        pii_redacted: 0,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        expect(result.frameworks).toContain('OWASP LLM Top 10');
        expect(result.frameworks).toContain('NIST AI 600-1');
        expect(result.frameworks).toContain('NIST AI RMF');
        expect(result.frameworks).toContain('NIST CSF 2.0');
        expect(result.frameworks).toContain('MITRE ATLAS');
        expect(result.frameworks).toContain('ISO/IEC 42001');
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
      expect(mappings.iso_42001).toBe('A.6.1.5 - AI System Security (Adversarial Input)');
    });

    it('should map data_exfiltration to correct frameworks', () => {
      const mappings = getFrameworkMappings('data_exfiltration');
      expect(mappings.owasp_llm).toContain('LLM02:2025');
      expect(mappings.nist_ai_600_1).toContain('MS-2.6');
      expect(mappings.mitre_atlas).toContain('AML.T0048');
      expect(mappings.iso_42001).toContain('A.7.5');
    });

    it('should return default mappings for unknown pattern', () => {
      const mappings = getFrameworkMappings('unknown_pattern_xyz');
      expect(mappings.owasp_llm).toContain('LLM01:2025');
      expect(mappings.nist_ai_600_1).toContain('MS-2.5');
      expect(mappings.mitre_atlas).toContain('AML.T0051');
      expect(mappings.iso_42001).toBe('A.6.1.5 - AI System Security');
    });

    it('should have ISO 42001 mapping for all 43 patterns', () => {
      // List of all 43 patterns from injection corpus
      const allPatterns = [
        'direct_instruction_injection', 'role_hijacking', 'system_prompt_extraction',
        'privilege_escalation', 'context_poisoning', 'data_exfiltration',
        'base64_obfuscation', 'unicode_lookalikes', 'zero_width_characters',
        'html_script_injection', 'data_uri_injection', 'markdown_link_injection',
        'url_fragment_hashjack', 'social_engineering_urgency', 'instruction_delimiter_injection',
        'multi_language_obfuscation', 'reverse_text_obfuscation', 'leetspeak_obfuscation',
        'jailbreak_keywords', 'token_smuggling', 'system_message_injection',
        'conversation_reset', 'memory_manipulation', 'capability_probing',
        'chain_of_thought_manipulation', 'hypothetical_scenario_injection', 'ethical_override',
        'output_format_manipulation', 'negative_instruction', 'credential_harvesting',
        'time_based_triggers', 'code_execution_requests', 'file_system_access',
        'training_data_extraction', 'simulator_mode', 'nested_encoding',
        'payload_splitting', 'css_hiding', 'authority_impersonation',
        'testing_debugging_claims', 'callback_url_injection', 'whitespace_steganography',
        'comment_injection'
      ];

      for (const pattern of allPatterns) {
        const mappings = getFrameworkMappings(pattern);
        expect(mappings.iso_42001).toBeTruthy();
        expect(mappings.iso_42001.length).toBeGreaterThan(0);
        expect(mappings.iso_42001).toMatch(/^A\.\d+/); // Should start with A.X (Annex A format)
      }
    });

    it('should include ISO 42001 column in Markdown report', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking'],
        pii_redacted: 0,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        const md = result.report_markdown;
        expect(md).toContain('| ISO |');
        expect(md).toContain('ISO/IEC 42001');
      }
    });

    it('should have 12 fields in TOON header', () => {
      const result = generateThreatReport({
        patterns_detected: ['role_hijacking'],
        pii_redacted: 0,
        source_url: 'https://test.example.com'
      });

      expect(result).not.toBeNull();
      if (result) {
        const toon = result.findings_toon;
        // TOON header should have 12 fields: id, pattern_id, category, severity, confidence, owasp_llm, nist_ai_600_1, nist_ai_rmf, nist_csf_2_0, mitre_atlas, iso_42001, remediation
        expect(toon).toMatch(/findings\[\d+\]\{[^}]+\}/);
        const headerMatch = toon.match(/findings\[\d+\]\{([^}]+)\}/);
        if (headerMatch) {
          const fields = headerMatch[1].split(',');
          expect(fields.length).toBe(12);
          expect(fields).toContain('iso_42001');
        }
      }
    });
  });
});
