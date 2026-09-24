import { describe, expect, it } from 'vitest';
import { extractIOCs, summarizeIOCsByType } from './iocExtraction';

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
  });

  it('filters private addresses and deduplicates canonical forms', () => {
    const iocs = extractIOCs({
      previewContent: '8.8.8.8 8[.]8[.]8[.]8 192.168.1.10 10.0.0.1',
    });

    expect(iocs.filter((ioc) => ioc.type === 'ipv4')).toHaveLength(1);
    expect(summarizeIOCsByType(iocs)).toEqual({ ipv4: 1 });
  });
});
