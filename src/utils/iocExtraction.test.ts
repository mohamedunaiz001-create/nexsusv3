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

  it('identifies all 12+ real IOCs across all categories with exact provenance and offsets', () => {
    // UTF-16LE encoded 'http://hidden-c2.net:8080/stage' in base64:
    // "aAB0AHQAcAA6AC8ALwBoAGkAZABkAGUAbgAtAGMAMgAuAG4AZQB0ADoAOAAwADgAMAAvAHMAdABhAGcAZQA="
    const multiIocText = [
      '// Sample Analysis Artifact',
      'IP: 185.220.101.44',
      'Domain: update-windows-defender.online',
      'URL: https://update-windows-defender.online/en/check.php',
      'Contact: operator@darknet-nexus.org',
      'MD5: ecbcf7d19e3f6fede32321aaebf6547f',
      'SHA256: 5f428e084fe4097d9fd2fcb8f4869065ebc9aa9c62be552819ef8559f9f083ff',
      'Payload Path: C:\\Windows\\Temp\\beacon_x64.dll',
      'Persistence: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WinDefenderUpdate',
      'Named Mutex: Global\\ZoneTransfer_Mutex',
      'C2 Socket: c2-relay-vault.darknet-nexus.org:8443',
      'Listening Port: port 8443',
      'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) CobaltStrike/4.8',
      'Evasion: vssadmin.exe delete shadows /all /quiet',
      'Cert: ServerCertificateValidationCallback CN=Microsoft Corporation',
      'Cradle: powershell -nop -w hidden -enc aAB0AHQAcAA6AC8ALwBoAGkAZABkAGUAbgAtAGMAMgAuAG4AZQB0ADoAOAAwADgAMAAvAHMAdABhAGcAZQA=',
    ].join('\n');

    const iocs = extractIOCs({
      fileName: 'stager_script.ps1',
      previewContent: multiIocText,
    });

    const types = iocs.map((i) => i.type);
    expect(types).toContain('ipv4');
    expect(types).toContain('domain');
    expect(types).toContain('url');
    expect(types).toContain('email');
    expect(types).toContain('md5');
    expect(types).toContain('sha256');
    expect(types).toContain('windows_path');
    expect(types).toContain('registry_path');
    expect(types).toContain('mutex');
    expect(types).toContain('c2_address');
    expect(types).toContain('port');
    expect(types).toContain('user_agent');
    expect(types).toContain('shell_cmd');
    expect(types).toContain('cert_info');
    expect(types).toContain('powershell_cmd');

    // Also verify that the decoded payload within the base64 cradle was extracted!
    const decodedUrl = iocs.find((i) => (i.normalizedValue || i.value).includes('hidden-c2.net'));
    expect(decodedUrl).toBeDefined();

    // Verify all IOCs carry provenance and hex offset
    expect(iocs.every((i) => !!i.location && i.location.includes('offset 0x'))).toBe(true);
    expect(iocs.length).toBeGreaterThanOrEqual(12);
  });
});
