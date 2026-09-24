import { describe, expect, it } from 'vitest';
import { extractIOCs, summarizeIOCsByType, categorizeExtractedIOCs } from './iocExtraction';

describe('extractIOCs', () => {
  it('extracts and normalizes defanged indicators with provenance', () => {
    const iocs = extractIOCs({
      fileName: 'evidence.txt',
      previewContent: 'hxxps://evil[.]example/path\n8[.]8[.]8[.]8\nCVE-2024-12345',
    });

    expect(iocs.map((ioc) => ioc.type)).toEqual(expect.arrayContaining(['url', 'ipv4', 'cve']));
    expect(iocs.find((ioc) => ioc.type === 'url')?.normalizedValue).toBe('https://evil.example/path');
    const ipv4 = iocs.find((ioc) => ioc.type === 'ipv4');
    expect(ipv4?.normalizedValue || ipv4?.value).toBe('8.8.8.8');
    expect(iocs.every((ioc) => ioc.source === 'preview content')).toBe(true);
    expect(iocs.every((ioc) => ioc.agent === 'ioc-extraction')).toBe(true);
    expect(iocs.every((ioc) => !!ioc.location)).toBe(true);
  });

  it('filters private addresses and deduplicates canonical forms', () => {
    const iocs = extractIOCs({
      previewContent: '8.8.8.8 8[.]8[.]8[.]8 192.168.1.10 10.0.0.1',
    });

    expect(iocs.filter((ioc) => ioc.type === 'ipv4')).toHaveLength(1);
    expect(summarizeIOCsByType(iocs)).toEqual({ ipv4: 1 });
  });

  it('extracts granular indicators: ssdeep, tlsh, pdb_path, scheduled_task, and campaign_id', () => {
    const sampleText = [
      '384:9fK...:c91', // short pseudo ssdeep
      '1536:12345678901234567890123456789012:abcdefghijklmn',
      'T10123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567',
      'C:\\dev\\malware\\loader.pdb',
      'schtasks /create /tn "Updater" /tr "C:\\temp\\beacon.exe"',
      'campaign = "Operation_NightDragon"',
      'c2_server = "evil-c2.net"',
      'powershell -enc JABjAGwAaQBlAG4AdAA... -nop',
      'IN A 198.51.100.25',
    ].join('\n');

    const iocs = extractIOCs({
      fileName: 'analysis.log',
      previewContent: sampleText,
    });

    const types = iocs.map((i) => i.type);
    expect(types).toContain('ssdeep');
    expect(types).toContain('tlsh');
    expect(types).toContain('pdb_path');
    expect(types).toContain('scheduled_task');
    expect(types).toContain('campaign_id');
    expect(types).toContain('config_indicator');
    expect(types).toContain('cmdline_indicator');
    expect(types).toContain('dns_record');

    const categorized = categorizeExtractedIOCs(iocs);
    expect(categorized.hashes.length).toBeGreaterThan(0);
    expect(categorized.files.length).toBeGreaterThan(0);
    expect(categorized.malwareArtifacts.length).toBeGreaterThan(0);
  });
});
