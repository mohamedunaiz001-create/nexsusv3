import { evaluateIOCRecall, IOCRecallResult } from './iocExtraction';

/**
 * Standard Ground Truth Evaluation Dataset for IOC Recall Testing.
 * Every indicator here is placed in realistic context (defanged, embedded in logs,
 * configuration blocks, command-line arguments, or execution cradles).
 */
export const KNOWN_IOC_BENCHMARK_TEXT = `
# Adversarial Triage Log - Operation NightDragon
# Incident ID: INC-2026-9812
Artifact SHA512: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
Artifact SHA256: d41d8cd98f00b204e9800998ecf8427e0123456789abcdef0123456789abcdef
Artifact SHA1: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
Artifact MD5: c4ca4238a0b923820dcc509a6f75849b
Fuzzy SSDEEP: 1536:12345678901234567890123456789012:abcdefghijklmn
Fuzzy TLSH: T10123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567

Vulnerability exploited: CVE-2024-38077
Adversary attribution: APT29 (Cozy Bear)
MITRE Technique: T1059.001

Execution Vector:
powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=

Dropped Components:
C:\\Windows\\Temp\\beacon_stage2.exe
C:\\Users\\Public\\loader.dll
/var/tmp/linux_backdoor.bin
PDB debug symbol: C:\\Projects\\Malware\\build\\loader.pdb

Persistence Created:
schtasks /create /tn "MicrosoftEdgeUpdateTaskMachineCore" /tr "C:\\Windows\\Temp\\beacon_stage2.exe" /sc minute /mo 15
sc create WinDefenderSvc binPath= "C:\\Users\\Public\\loader.dll"

Configuration Block:
c2_server = "c2-relay-vault.darknet-nexus.org"
c2_port = 8443
campaign = "Operation_RedStorm"
encryption_key = "a8f3b219e48c12a76f5b9d3e1a0b4c8d"

Network Telemetry:
Defanged URL: hxxps://evil-attacker-drop[.]net/payloads/dropper.exe
Raw URL: https://direct-c2-beacon.org/gateway/sync
Defanged IPv4: 198[.]51[.]100[.]42
Raw IPv4: 203.0.113.88
IPv6 Beacon: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
DNS Query: IN A evil-attacker-drop.net
Named Pipe: \\\\.\\pipe\\status_service_pipe
Mutex: Global\\Windows_Update_Sync_Mutex_8921
Contact: operator@threat-syndicate.io
`;

export const KNOWN_IOC_GROUND_TRUTH = [
  { type: 'sha512', value: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e' },
  { type: 'sha256', value: 'd41d8cd98f00b204e9800998ecf8427e0123456789abcdef0123456789abcdef' },
  { type: 'sha1', value: '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12' },
  { type: 'md5', value: 'c4ca4238a0b923820dcc509a6f75849b' },
  { type: 'ssdeep', value: '1536:12345678901234567890123456789012:abcdefghijklmn' },
  { type: 'tlsh', value: 'T10123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567' },
  { type: 'cve', value: 'CVE-2024-38077' },
  { type: 'attack_group', value: 'APT29' },
  { type: 'attack_technique', value: 'T1059.001' },
  { type: 'cmdline_indicator', value: 'powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=' },
  { type: 'windows_path', value: 'C:\\Windows\\Temp\\beacon_stage2.exe' },
  { type: 'linux_path', value: '/var/tmp/linux_backdoor.bin' },
  { type: 'pdb_path', value: 'C:\\Projects\\Malware\\build\\loader.pdb' },
  { type: 'scheduled_task', value: 'schtasks /create /tn "MicrosoftEdgeUpdateTaskMachineCore" /tr "C:\\Windows\\Temp\\beacon_stage2.exe" /sc minute /mo 15' },
  { type: 'service_name', value: 'sc create WinDefenderSvc' },
  { type: 'c2_indicator', value: 'c2-relay-vault.darknet-nexus.org' },
  { type: 'campaign_id', value: 'Operation_RedStorm' },
  { type: 'encryption_key_artifact', value: 'a8f3b219e48c12a76f5b9d3e1a0b4c8d' },
  { type: 'url', value: 'https://evil-attacker-drop.net/payloads/dropper.exe' },
  { type: 'url', value: 'https://direct-c2-beacon.org/gateway/sync' },
  { type: 'ipv4', value: '198.51.100.42' },
  { type: 'ipv4', value: '203.0.113.88' },
  { type: 'ipv6', value: '2001:0db8:85a3:0000:0000:8a2e:0370:7334' },
  { type: 'dns_record', value: 'IN A evil-attacker-drop.net' },
  { type: 'named_pipe', value: '\\\\.\\pipe\\status_service_pipe' },
  { type: 'mutex', value: 'Global\\Windows_Update_Sync_Mutex_8921' },
  { type: 'email', value: 'operator@threat-syndicate.io' },
];

export function runBenchmarkIOCRecall(): IOCRecallResult {
  return evaluateIOCRecall(KNOWN_IOC_BENCHMARK_TEXT, KNOWN_IOC_GROUND_TRUTH);
}
