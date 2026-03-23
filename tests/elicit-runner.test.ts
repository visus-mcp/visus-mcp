/**
 * Tests for Elicitation Runner
 *
 * Validates:
 * - User accept/decline/cancel handling
 * - Fail-safe behavior on errors
 * - Threat report inclusion logic
 */

import { runElicitation } from '../src/sanitizer/elicit-runner.js';
import type { ThreatReport } from '../src/sanitizer/threat-reporter.js';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';

describe('Elicitation Runner', () => {
  let mockServer: jest.Mocked<Server>;

  beforeEach(() => {
    // Create a mock server with elicitInput method
    mockServer = {
      elicitInput: jest.fn()
    } as any;
  });

  const createMockThreatReport = (): ThreatReport => ({
    generated: new Date().toISOString(),
    source_url: 'https://malicious.example.com',
    overall_severity: 'CRITICAL',
    total_findings: 5,
    by_severity: { CRITICAL: 5, HIGH: 0, MEDIUM: 0, LOW: 0 },
    pii_redacted: 0,
    sanitization_applied: true,
    frameworks: ['OWASP LLM Top 10', 'NIST AI 600-1', 'MITRE ATLAS'],
    findings_toon: 'findings[5]{id,pattern_id,category,severity,confidence,owasp_llm,nist_ai_600_1,mitre_atlas,remediation}:\n1,PI-001,role_hijacking,CRITICAL,0.95,LLM01:2025 - Prompt Injection,MS-2.3,AML.T0051.000 - LLM Prompt Injection,Content sanitized',
    report_markdown: '# Report'
  });

  describe('User response handling', () => {
    it('returns proceed:true when user accepts with proceed:true', async () => {
      const threatReport = createMockThreatReport();

      mockServer.elicitInput.mockResolvedValue({
        action: 'accept',
        content: {
          proceed: true,
          view_report: true
        }
      });

      const result = await runElicitation(
        mockServer,
        threatReport,
        'https://malicious.example.com'
      );

      expect(result.proceed).toBe(true);
      expect(result.includeReport).toBe(true);
    });

    it('returns proceed:false when user accepts with proceed:false', async () => {
      const threatReport = createMockThreatReport();

      mockServer.elicitInput.mockResolvedValue({
        action: 'accept',
        content: {
          proceed: false,
          view_report: true
        }
      });

      const result = await runElicitation(
        mockServer,
        threatReport,
        'https://malicious.example.com'
      );

      expect(result.proceed).toBe(false);
      expect(result.includeReport).toBe(false); // Report not included when not proceeding
    });

    it('returns proceed:false on decline action', async () => {
      const threatReport = createMockThreatReport();

      mockServer.elicitInput.mockResolvedValue({
        action: 'decline',
        content: undefined
      });

      const result = await runElicitation(
        mockServer,
        threatReport,
        'https://malicious.example.com'
      );

      expect(result.proceed).toBe(false);
      expect(result.includeReport).toBe(false);
    });

    it('returns proceed:false on cancel action', async () => {
      const threatReport = createMockThreatReport();

      mockServer.elicitInput.mockResolvedValue({
        action: 'cancel',
        content: undefined
      });

      const result = await runElicitation(
        mockServer,
        threatReport,
        'https://malicious.example.com'
      );

      expect(result.proceed).toBe(false);
      expect(result.includeReport).toBe(false);
    });

    it('includes report when user checks view_report', async () => {
      const threatReport = createMockThreatReport();

      mockServer.elicitInput.mockResolvedValue({
        action: 'accept',
        content: {
          proceed: true,
          view_report: true
        }
      });

      const result = await runElicitation(
        mockServer,
        threatReport,
        'https://malicious.example.com'
      );

      expect(result.proceed).toBe(true);
      expect(result.includeReport).toBe(true);
    });

    it('excludes report when user unchecks view_report', async () => {
      const threatReport = createMockThreatReport();

      mockServer.elicitInput.mockResolvedValue({
        action: 'accept',
        content: {
          proceed: true,
          view_report: false
        }
      });

      const result = await runElicitation(
        mockServer,
        threatReport,
        'https://malicious.example.com'
      );

      expect(result.proceed).toBe(true);
      expect(result.includeReport).toBe(false);
    });

    it('defaults to including report when view_report is undefined', async () => {
      const threatReport = createMockThreatReport();

      mockServer.elicitInput.mockResolvedValue({
        action: 'accept',
        content: {
          proceed: true
        }
      });

      const result = await runElicitation(
        mockServer,
        threatReport,
        'https://malicious.example.com'
      );

      expect(result.proceed).toBe(true);
      expect(result.includeReport).toBe(true);
    });
  });

  describe('Fail-safe behavior', () => {
    it('proceeds with sanitized content on elicitation error (fail-safe)', async () => {
      const threatReport = createMockThreatReport();

      mockServer.elicitInput.mockRejectedValue(
        new Error('Elicitation not supported')
      );

      const result = await runElicitation(
        mockServer,
        threatReport,
        'https://malicious.example.com'
      );

      expect(result.proceed).toBe(true);
      expect(result.includeReport).toBe(true);
    });

    it('proceeds with sanitized content on timeout (fail-safe)', async () => {
      const threatReport = createMockThreatReport();

      mockServer.elicitInput.mockRejectedValue(
        new Error('Request timeout')
      );

      const result = await runElicitation(
        mockServer,
        threatReport,
        'https://malicious.example.com'
      );

      expect(result.proceed).toBe(true);
      expect(result.includeReport).toBe(true);
    });

    it('proceeds with sanitized content on unknown action (fail-safe)', async () => {
      const threatReport = createMockThreatReport();

      mockServer.elicitInput.mockResolvedValue({
        action: 'unknown_action' as any,
        content: undefined
      });

      const result = await runElicitation(
        mockServer,
        threatReport,
        'https://malicious.example.com'
      );

      expect(result.proceed).toBe(true);
      expect(result.includeReport).toBe(true);
    });
  });
});
