/**
 * Tests for HITL (Human-in-the-Loop) Gate
 *
 * Validates:
 * - shouldElicit decision logic
 * - buildElicitMessage formatting
 * - ElicitSchema structure compliance
 */

import { shouldElicit, buildElicitMessage, ElicitSchema } from '../src/sanitizer/hitl-gate.js';
import type { ThreatReport } from '../src/sanitizer/threat-reporter.js';

describe('HITL Gate', () => {
  describe('shouldElicit', () => {
    it('returns true for CRITICAL severity report with findings', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://malicious.example.com',
        overall_severity: 'CRITICAL',
        total_findings: 5,
        by_severity: { CRITICAL: 5, HIGH: 0, MEDIUM: 0, LOW: 0 },
        pii_redacted: 0,
        sanitization_applied: true,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: 'findings[5]{id,pattern_id,category,severity,confidence,owasp_llm,nist_ai_600_1,mitre_atlas,remediation}:\n1,PI-001,role_hijacking,CRITICAL,0.95,LLM01:2025,MS-2.3,AML.T0051.000,Content sanitized',
        report_markdown: '# Report'
      };

      expect(shouldElicit(report)).toBe(true);
    });

    it('returns false for HIGH severity report', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://example.com',
        overall_severity: 'HIGH',
        total_findings: 3,
        by_severity: { CRITICAL: 0, HIGH: 3, MEDIUM: 0, LOW: 0 },
        pii_redacted: 0,
        sanitization_applied: true,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: '',
        report_markdown: ''
      };

      expect(shouldElicit(report)).toBe(false);
    });

    it('returns false for MEDIUM severity report', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://example.com',
        overall_severity: 'MEDIUM',
        total_findings: 2,
        by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 2, LOW: 0 },
        pii_redacted: 0,
        sanitization_applied: true,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: '',
        report_markdown: ''
      };

      expect(shouldElicit(report)).toBe(false);
    });

    it('returns false for LOW severity report', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://example.com',
        overall_severity: 'LOW',
        total_findings: 1,
        by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 1 },
        pii_redacted: 0,
        sanitization_applied: true,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: '',
        report_markdown: ''
      };

      expect(shouldElicit(report)).toBe(false);
    });

    it('returns false for CLEAN report', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://example.com',
        overall_severity: 'CLEAN',
        total_findings: 0,
        by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        pii_redacted: 0,
        sanitization_applied: false,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: '',
        report_markdown: ''
      };

      expect(shouldElicit(report)).toBe(false);
    });

    it('returns false for null report', () => {
      expect(shouldElicit(null)).toBe(false);
    });

    it('returns false for CRITICAL severity with zero findings', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://example.com',
        overall_severity: 'CRITICAL',
        total_findings: 0,
        by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        pii_redacted: 0,
        sanitization_applied: false,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: '',
        report_markdown: ''
      };

      expect(shouldElicit(report)).toBe(false);
    });
  });

  describe('buildElicitMessage', () => {
    it('contains URL in output', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://malicious.example.com',
        overall_severity: 'CRITICAL',
        total_findings: 2,
        by_severity: { CRITICAL: 2, HIGH: 0, MEDIUM: 0, LOW: 0 },
        pii_redacted: 0,
        sanitization_applied: true,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: 'findings[2]{id,pattern_id,category,severity,confidence,owasp_llm,nist_ai_600_1,mitre_atlas,remediation}:\n1,PI-001,role_hijacking,CRITICAL,0.95,LLM01:2025 - Prompt Injection,MS-2.3,AML.T0051.000 - LLM Prompt Injection,Content sanitized\n2,PI-002,system_prompt_leak,CRITICAL,0.90,LLM01:2025 - Prompt Injection,MS-2.3,AML.T0051.001 - LLM Jailbreak,Content sanitized',
        report_markdown: ''
      };

      const url = 'https://malicious.example.com';
      const message = buildElicitMessage(report, url);

      expect(message).toContain(url);
    });

    it('contains finding count', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://malicious.example.com',
        overall_severity: 'CRITICAL',
        total_findings: 3,
        by_severity: { CRITICAL: 3, HIGH: 0, MEDIUM: 0, LOW: 0 },
        pii_redacted: 0,
        sanitization_applied: true,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: 'findings[3]{id,pattern_id,category,severity,confidence,owasp_llm,nist_ai_600_1,mitre_atlas,remediation}:\n1,PI-001,role_hijacking,CRITICAL,0.95,LLM01:2025 - Prompt Injection,MS-2.3,AML.T0051.000 - LLM Prompt Injection,Content sanitized',
        report_markdown: ''
      };

      const message = buildElicitMessage(report, 'https://example.com');

      expect(message).toContain('3');
      expect(message).toContain('injection attempt(s)');
    });

    it('is under 300 characters', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://malicious.example.com',
        overall_severity: 'CRITICAL',
        total_findings: 5,
        by_severity: { CRITICAL: 5, HIGH: 0, MEDIUM: 0, LOW: 0 },
        pii_redacted: 0,
        sanitization_applied: true,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: 'findings[5]{id,pattern_id,category,severity,confidence,owasp_llm,nist_ai_600_1,mitre_atlas,remediation}:\n1,PI-001,role_hijacking,CRITICAL,0.95,LLM01:2025 - Prompt Injection,MS-2.3,AML.T0051.000 - LLM Prompt Injection,Content sanitized',
        report_markdown: ''
      };

      const message = buildElicitMessage(report, 'https://example.com');

      expect(message.length).toBeLessThan(300);
    });

    it('contains top category', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://malicious.example.com',
        overall_severity: 'CRITICAL',
        total_findings: 1,
        by_severity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0 },
        pii_redacted: 0,
        sanitization_applied: true,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: 'findings[1]{id,pattern_id,category,severity,confidence,owasp_llm,nist_ai_600_1,mitre_atlas,remediation}:\n1,PI-001,role_hijacking,CRITICAL,0.95,LLM01:2025 - Prompt Injection,MS-2.3,AML.T0051.000 - LLM Prompt Injection,Content sanitized',
        report_markdown: ''
      };

      const message = buildElicitMessage(report, 'https://example.com');

      expect(message).toContain('role_hijacking');
    });

    it('contains OWASP and MITRE identifiers', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://malicious.example.com',
        overall_severity: 'CRITICAL',
        total_findings: 1,
        by_severity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0 },
        pii_redacted: 0,
        sanitization_applied: true,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: 'findings[1]{id,pattern_id,category,severity,confidence,owasp_llm,nist_ai_600_1,mitre_atlas,remediation}:\n1,PI-001,role_hijacking,CRITICAL,0.95,LLM01:2025 - Prompt Injection,MS-2.3,AML.T0051.000 - LLM Prompt Injection,Content sanitized',
        report_markdown: ''
      };

      const message = buildElicitMessage(report, 'https://example.com');

      expect(message).toContain('LLM01:2025');
      expect(message).toContain('AML.T0051.000');
    });

    it('handles empty findings gracefully', () => {
      const report: ThreatReport = {
        generated: new Date().toISOString(),
        source_url: 'https://malicious.example.com',
        overall_severity: 'CRITICAL',
        total_findings: 0,
        by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        pii_redacted: 0,
        sanitization_applied: true,
        frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
        findings_toon: 'findings[0]{id,pattern_id,category,severity,confidence,owasp_llm,nist_ai_600_1,mitre_atlas,remediation}:',
        report_markdown: ''
      };

      const message = buildElicitMessage(report, 'https://example.com');

      expect(message).toContain('unknown');
      expect(message).toContain('N/A');
    });
  });

  describe('ElicitSchema', () => {
    it('has flat primitive properties only', () => {
      expect(ElicitSchema.type).toBe('object');
      expect(ElicitSchema.properties.proceed.type).toBe('boolean');
      expect(ElicitSchema.properties.view_report.type).toBe('boolean');

      // Verify no nested objects
      const proceedProp = ElicitSchema.properties.proceed;
      const viewReportProp = ElicitSchema.properties.view_report;

      expect(typeof proceedProp.type).toBe('string');
      expect(typeof viewReportProp.type).toBe('string');
    });

    it('has required array containing proceed', () => {
      expect(ElicitSchema.required).toContain('proceed');
    });

    it('has descriptive titles and descriptions', () => {
      expect(ElicitSchema.properties.proceed.title).toBeTruthy();
      expect(ElicitSchema.properties.proceed.description).toBeTruthy();
      expect(ElicitSchema.properties.view_report.title).toBeTruthy();
      expect(ElicitSchema.properties.view_report.description).toBeTruthy();
    });
  });
});
