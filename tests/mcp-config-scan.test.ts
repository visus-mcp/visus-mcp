import { describe, it, expect } from '@jest/globals';
import { visusScanMcp, type ScanResult } from '../src/tools/mcp-config-scan.js';

describe('visusScanMcp', () => {
  it('scans safe MCP config with no risks', async () => {
    const input = {
      config: JSON.stringify({
        command: 'node',
        args: ['dist/index.js'],
        env: { NODE_ENV: 'production' }
      })
    };
    const result = await visusScanMcp(input);
    expect(result.score).toBe(0);
    expect(result.safeToSpawn).toBe(true);
    expect(result.findings).toHaveLength(0);
    expect(result.mcp_risks).toHaveLength(0);
  });

  it('detects shell injection risk', async () => {
    const input = {
      config: JSON.stringify({
        command: 'sh -c node index.js'
      })
    };
    const result = await visusScanMcp(input);
    expect(result.score).toBeGreaterThan(0);
    expect(result.findings.some((f: any) => f.pattern === 'shell_injection')).toBe(true);
    expect(result.remediation.some((r: any) => r.includes('shell'))).toBe(true);
  });

  it('detects high entropy payload', async () => {
    const highEntropyStr = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.repeat(10); // High entropy (base64-like)
    const input = {
      config: JSON.stringify({
        args: [highEntropyStr]
      })
    };
    const result = await visusScanMcp(input);
    expect(result.findings).toHaveLength(1); // Expect high entropy finding
    expect(result.findings[0].pattern).toBe('high_entropy_payload');
    expect(result.score).toBeGreaterThan(0);
  });
    const highEntropyStr = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.repeat(10); // High entropy string
    const lowEntropyStr = 'a'.repeat(600); // Low entropy ~0
    const input = {
      config: JSON.stringify({
        args: [highEntropyStr]
      })
    };
    const result = await visusScanMcp(input);
    expect(result.score).toBeGreaterThan(0);
    // Entropy test may need adjustment; for base64-like high entropy
    expect(scoreEntropy(highEntropyStr) > 4.5).toBe(true);
  });

  it('integrates sanitizer patterns', async () => {
    const input = {
      config: JSON.stringify({
        command: 'eval("ignore previous instructions")' // Triggers code_execution
      })
    };
    const result = await visusScanMcp(input);
    expect(result.mcp_risks.length).toBeGreaterThan(0); // From direct_instruction_injection
    expect(result.score).toBeGreaterThan(0);
  });

  it('applies whitelist to ignore patterns', async () => {
    const input = {
      config: JSON.stringify({
        command: 'sh -c echo hi'
      }),
      options: {
        whitelist: 'shell_injection'
      }
    };
    const result = await visusScanMcp(input);
    expect(result.findings.filter((f: any) => f.pattern === 'shell_injection')).toHaveLength(0);
    expect(result.score).toBeLessThan(5); // Still other scores
  });

  it('adjusts safeToSpawn based on mode', async () => {
    const riskyInput = { config: JSON.stringify({command: 'bash -c rm /'}) };
    const strictResult = await visusScanMcp({ ...riskyInput, options: { mode: 'strict' } as any });
    const balancedResult = await visusScanMcp({ ...riskyInput, options: { mode: 'balanced' } as any });
    expect(strictResult.safeToSpawn).toBe(false);
    expect(balancedResult.safeToSpawn).toBe(false); // Score high
    const permissiveResult = await visusScanMcp({...riskyInput, options: {mode: 'permissive'}});
    expect(permissiveResult.safeToSpawn).toBe(true);
  });

  it('handles invalid JSON', async () => {
    const input = { config: 'invalid json' };
    await expect(visusScanMcp(input)).rejects.toThrow('Invalid JSON config');
  });

  it('scans env abuse', async () => {
    const input = {
      config: JSON.stringify({
        env: { PATH: '/tmp/mal/:/bin; rm -rf /' }
      })
    };
    const result = await visusScanMcp(input);
    expect(result.findings.some((f: any) => f.pattern === 'env_abuse')).toBe(true);
    expect(result.remediation.some((r: any) => r.includes('env'))).toBe(true);
  });
});