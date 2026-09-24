import { describe, expect, it } from 'vitest';
import { computeAggregateVerdict, getThreatIntelCandidates } from './multiAgentAnalysis';

describe('computeAggregateVerdict', () => {
  it('returns Unknown when no specialist produced a score', () => {
    expect(computeAggregateVerdict([{ agentId: 'verification-agent', agentName: 'Verification', status: 'complete', stepProgress: 100 }])).toEqual({
      maliciousScore: 0,
      verdict: 'Unknown',
    });
  });

  it('averages scored specialists and preserves threshold semantics', () => {
    expect(computeAggregateVerdict([
      { agentId: 'malware-analysis', agentName: 'Malware', status: 'complete', stepProgress: 100, maliciousScore: 80 },
      { agentId: 'ioc-extraction', agentName: 'IOC', status: 'complete', stepProgress: 100, maliciousScore: 60 },
    ])).toEqual({ maliciousScore: 70, verdict: 'Malicious' });
  });
});

describe('threat-intel candidate preparation', () => {
  it('keeps every discovered IOC for provider evaluation', () => {
    const candidates = getThreatIntelCandidates({
      id: 'artifact-1',
      name: 'report.txt',
      type: 'file',
      uploadedAt: '2026-09-17T00:00:00.000Z',
      uploadedBy: 'test',
      status: 'Ingested',
      tags: [],
      previewContent: [
        '0123456789abcdef0123456789abcdef01234567',
        ...Array.from({ length: 13 }, (_, index) => `https://host-${index}.example/payload.exe`),
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
      ].join('\n'),
    });

    expect(candidates.length).toBeGreaterThan(12);
    expect(candidates.map((ioc) => ioc.type)).toEqual(expect.arrayContaining(['sha1', 'url', 'registry_path']));
  });
});