import { describe, it, expect } from '@jest/globals';
import { detectCommandInjection } from '../../src/security/command-guard.js';

describe('Command Guard Detection', () => {
  const cleanParams = { command: 'node index.js', args: ['--port', '3000'], env: { NODE_ENV: 'production' } };
  // riskyParams not used - removed

  it('detects no risks in clean params', () => {
    const result = detectCommandInjection(cleanParams);
    expect(result.risks.length).toBe(0);
    expect(result.totalScore).toBe(0);
  });

  it('detects shell metachars in command', () => {
    const result = detectCommandInjection({ command: 'ls; cat /etc/passwd' });
    expect(result.risks.some((r: { pattern: string }) => r.pattern === 'shell_metachars')).toBe(true);
  });

  it('detects bash -c in command', () => {
    const result = detectCommandInjection({ command: 'bash -c "malicious"' });
    expect(result.risks.some((r: { pattern: string }) => r.pattern === 'bash_subprocess')).toBe(true);
  });

  it('detects cmd.exe /c', () => {
    const result = detectCommandInjection({ command: 'cmd.exe /c dir' });
    expect(result.risks.some((r: { pattern: string }) => r.pattern === 'cmd_exe')).toBe(true);
  });

  it('detects high entropy payload', () => {
    const highEntropy = { command: 'SGVsbG8gd29ybGQ= repeated base64' }; // High entropy
    const result = detectCommandInjection(highEntropy);
    expect(result.risks.some((r: { pattern: string }) => r.pattern === 'high_entropy_payload')).toBe(true);
  });

  it('ignores whitelisted patterns', () => {
    const result = detectCommandInjection({ command: 'bash -c test' }, { whitelist: ['bash_subprocess'] });
    expect(result.risks.some((r: { pattern: string }) => r.pattern === 'bash_subprocess')).toBe(false);
  });

  it('detects bash -c in command', () => {
    const risks = detectCommandInjection({ command: 'bash -c "malicious"' });
    expect(risks.some(r => r.pattern === 'bash_subprocess')).toBe(true);
  });

  it('detects cmd.exe /c', () => {
    const risks = detectCommandInjection({ command: 'cmd.exe /c dir' });
    expect(risks.some(r => r.pattern === 'cmd_exe')).toBe(true);
  });

  it('detects high entropy payload', () => {
    const highEntropy = { command: 'SGVsbG8gd29ybGQ= repeated base64' }; // High entropy
    const risks = detectCommandInjection(highEntropy);
    expect(risks.some(r => r.pattern === 'high_entropy_payload')).toBe(true);
  });

  it('ignores whitelisted patterns', () => {
    const risks = detectCommandInjection({ command: 'bash -c test' }, { whitelist: ['bash_subprocess'] });
    expect(risks.some(r => r.pattern === 'bash_subprocess')).toBe(false);
  });
});
