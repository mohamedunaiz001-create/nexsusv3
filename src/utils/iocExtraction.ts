/**
 * Comprehensive Context-Aware IOC Extraction Engine.
 *
 * Runs specialized detectors over actual artifact text — the artifact's
 * file name, preview/paste content, and printable-string findings surfaced
 * by static analysis.
 *
 * Supported indicator types:
 * - Hashes: SHA512, SHA256, SHA1, MD5
 * - Network: IPv4, IPv6, URL (including defanged hxxp/hxxps), Domain/FQDN,
 *   Email, ASN, JA3/JA3S fingerprint, User-Agent, Certificate Fingerprint
 * - Crypto: Bitcoin (BTC) address, Monero (XMR) address
 * - Host/System: Windows path, Linux path, Registry key, Mutex, Named pipe
 * - Threat Intel: CVE, MITRE ATT&CK technique, MITRE software, MITRE group
 *
 * Context-aware:
 * - Differentiates software version numbers (e.g. "Version 185.1.2.3") from C2 IPs.
 * - Extracts semantic role: C2, Exfiltration, Download/Staging, Payload/Dropper,
 *   Phishing, Persistence, Execution, Reconnaissance, Legitimate Reference.
 * - Retains full provenance: source, location, line number, surrounding context, confidence.
 */
import { ExtractedIOC, ExtractedIOCType } from '../types';

interface Detector {
  type: ExtractedIOCType;
  re: RegExp;
  confidence: number;
  /** Optional post-match validator to filter out false positives regex alone can't catch. */
  validate?: (value: string, fullContext?: string) => boolean;
}

function isPrivateOrReservedIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true; // Link-local
  if (a >= 224) return true; // Multicast / reserved
  if (a === 0 || a === 255) return true;
  return false;
}

function isSemanticVersion(value: string, context?: string): boolean {
  if (!context) return false;
  // If preceded by "v", "ver", "version", "build", "release"
  const re = new RegExp(`(?:version|ver|v|build|release|sdk|runtime|v\\.?)\\s*:?\\s*${value.replace(/\./g, '\\.')}`, 'i');
  return re.test(context);
}

function normalizeDefangedValue(raw: string): string {
  let normalized = raw.trim();
  normalized = normalized.replace(/hxxp/gi, 'http');
  normalized = normalized.replace(/hxxps/gi, 'https');
  normalized = normalized.replace(/\[\.\]/gi, '.');
  normalized = normalized.replace(/\[\@\]/gi, '@');
  normalized = normalized.replace(/\(\.?\)/gi, '.');
  normalized = normalized.replace(/\(\[\]\)/gi, '');
  normalized = normalized.replace(/\s+/g, '');
  normalized = normalized.replace(/\[(?:\.|@)\]/g, (m) => (m === '[.]' ? '.' : '@'));
  normalized = normalized.replace(/(?<=\w)\[\.\](?=\w)/g, '.');
  if (/^\d\[\.\]\d/.test(normalized)) normalized = normalized.replace(/\[\.\]/g, '.');
  if (/^https?:\/\//i.test(normalized) && /\[\.\]/.test(raw)) normalized = normalized.replace(/\[\.\]/g, '.');
  if (/^https?:\/\//i.test(normalized)) {
    normalized = normalized.replace(/\[\.\]/g, '.');
  }
  normalized = normalized.replace(/\[@\]/g, '@');
  normalized = normalized.replace(/\[\]\./g, '.');
  normalized = normalized.replace(/\[\]\@/g, '@');
  normalized = normalized.replace(/\[\]/g, '');
  return normalized;
}

function defangForScanning(text: string): string {
  return text
    .replace(/hxxps?/gi, (protocol) => (protocol.toLowerCase().startsWith('hxxps') ? 'https' : 'http'))
    .replace(/\[\.\]|\(\.\)|\[\]\./gi, '.')
    .replace(/\[@\]|\(@\)/gi, '@');
}

function contextAround(text: string, value: string): { lineNumber: number; context: string } {
  const idx = text.indexOf(value);
  if (idx === -1) return { lineNumber: 1, context: '' };
  const before = text.slice(Math.max(0, idx - 120), idx);
  const after = text.slice(idx + value.length, idx + value.length + 120);
  const lineNumber = text.slice(0, idx).split(/\r?\n/).length;
  const snippet = `${before}${value}${after}`.replace(/\s+/g, ' ').trim();
  return { lineNumber, context: snippet.length > 0 ? snippet : value };
}

/**
 * Infer semantic role and confidence boost from surrounding text.
 */
function inferRoleAndEvidence(context: string, type: ExtractedIOCType): {
  role?: ExtractedIOC['role'];
  roleEvidence?: string;
  confidenceAdjustment: number;
} {
  const ctx = context.toLowerCase();

  // False positive check: Documentation / Example
  if (ctx.includes('example.com') || ctx.includes('documentation') || ctx.includes('rfc1918') || ctx.includes('test ip')) {
    return {
      role: 'legitimate_ref',
      roleEvidence: 'Surrounding text refers to documentation, testing, or example domain/IP',
      confidenceAdjustment: -0.3,
    };
  }

  // C2 Server / Callback
  if (
    ctx.includes('c2') ||
    ctx.includes('command and control') ||
    ctx.includes('command-and-control') ||
    ctx.includes('beacon') ||
    ctx.includes('callback') ||
    ctx.includes('listener') ||
    ctx.includes('listening on') ||
    ctx.includes('botnet') ||
    ctx.includes('heartbeat') ||
    ctx.includes('operator')
  ) {
    return {
      role: 'c2',
      roleEvidence: 'Context indicates Command & Control (C2) / beaconing destination',
      confidenceAdjustment: 0.1,
    };
  }

  // Exfiltration
  if (
    ctx.includes('exfil') ||
    ctx.includes('stolen') ||
    ctx.includes('upload') ||
    ctx.includes('data leak') ||
    ctx.includes('archive sent to') ||
    ctx.includes('exfiltrat')
  ) {
    return {
      role: 'exfiltration',
      roleEvidence: 'Context indicates data exfiltration or staging destination',
      confidenceAdjustment: 0.1,
    };
  }

  // Download / Staging
  if (
    ctx.includes('download') ||
    ctx.includes('stage') ||
    ctx.includes('dropper url') ||
    ctx.includes('hosted on') ||
    ctx.includes('fetch') ||
    ctx.includes('wget') ||
    ctx.includes('curl') ||
    ctx.includes('invoke-webrequest')
  ) {
    return {
      role: 'download_staging',
      roleEvidence: 'Context indicates payload hosting or download staging',
      confidenceAdjustment: 0.08,
    };
  }

  // Payload Drop / Dropper
  if (
    ctx.includes('dropped') ||
    ctx.includes('payload') ||
    ctx.includes('implant') ||
    ctx.includes('sample') ||
    ctx.includes('binary') ||
    ctx.includes('executable')
  ) {
    return {
      role: 'payload_drop',
      roleEvidence: 'Context indicates dropped executable or payload file',
      confidenceAdjustment: 0.08,
    };
  }

  // Phishing / Lure
  if (
    ctx.includes('phish') ||
    ctx.includes('lure') ||
    ctx.includes('credential') ||
    ctx.includes('fake login') ||
    ctx.includes('spoof') ||
    ctx.includes('sender')
  ) {
    return {
      role: 'phishing',
      roleEvidence: 'Context indicates phishing campaign, credential harvester, or malicious lure',
      confidenceAdjustment: 0.08,
    };
  }

  // Persistence
  if (
    ctx.includes('run key') ||
    ctx.includes('persistence') ||
    ctx.includes('startup') ||
    ctx.includes('schtasks') ||
    ctx.includes('autorun') ||
    ctx.includes('service installed')
  ) {
    return {
      role: 'persistence',
      roleEvidence: 'Context indicates system persistence mechanism',
      confidenceAdjustment: 0.08,
    };
  }

  // Execution
  if (
    ctx.includes('execute') ||
    ctx.includes('spawn') ||
    ctx.includes('inject') ||
    ctx.includes('process hollowing') ||
    ctx.includes('powershell')
  ) {
    return {
      role: 'execution',
      roleEvidence: 'Context indicates process execution or injection mechanism',
      confidenceAdjustment: 0.05,
    };
  }

  // Reconnaissance
  if (
    ctx.includes('recon') ||
    ctx.includes('scan') ||
    ctx.includes('probe') ||
    ctx.includes('nmap') ||
    ctx.includes('whois') ||
    ctx.includes('enumerate')
  ) {
    return {
      role: 'reconnaissance',
      roleEvidence: 'Context indicates reconnaissance or enumeration activity',
      confidenceAdjustment: 0.05,
    };
  }

  // Default role by type if no specific keywords matched
  if (type === 'ipv4' || type === 'ipv6' || type === 'domain' || type === 'url') {
    return { role: 'informational', roleEvidence: 'Network indicator discovered in artifact', confidenceAdjustment: 0 };
  }
  if (type === 'registry_key') {
    return { role: 'persistence', roleEvidence: 'Registry key identified', confidenceAdjustment: 0 };
  }
  if (type === 'windows_path' || type === 'linux_path') {
    return { role: 'payload_drop', roleEvidence: 'File path identified', confidenceAdjustment: 0 };
  }
  return { role: 'informational', confidenceAdjustment: 0 };
}

// Well-known MITRE ATT&CK Software (Cobalt Strike, Mimikatz, etc.)
const KNOWN_ATTACK_SOFTWARE_REGEX = /\b(?:S\d{4}|Cobalt\s*Strike|Mimikatz|PsExec|BloodHound|Empire|Metasploit|Qakbot|Emotet|TrickBot|AgentTesla|RedLine|IcedID|BlackCat|LockBit|Conti|DarkSide|REvil|Ryuk|BazarLoader|AsyncRAT|Remcos|Sliver|Havoc|Brute\s*Ratel)\b/gi;

// Well-known MITRE ATT&CK Groups (APT28, Lazarus, etc.)
const KNOWN_ATTACK_GROUPS_REGEX = /\b(?:G\d{4}|APT28|APT29|APT33|APT34|APT38|APT41|Lazarus(?:\s*Group)?|FIN7|FIN8|Sandworm|Cozy\s*Bear|Fancy\s*Bear|Turla|Volt\s*Typhoon|Salt\s*Typhoon|Scattered\s*Spider|Silence|Wizard\s*Spider|TA505|TA551|Kimsuky|Mustang\s*Panda)\b/gi;

// Order matters: specific patterns and longer hex hashes before general domains
const DETECTORS: Detector[] = [
  // Hashes
  { type: 'sha512', re: /\b[a-fA-F0-9]{128}\b/g, confidence: 0.99 },
  { type: 'sha256', re: /\b[a-fA-F0-9]{64}\b/g, confidence: 0.98 },
  { type: 'sha1', re: /\b[a-fA-F0-9]{40}\b/g, confidence: 0.9 },
  { type: 'md5', re: /\b[a-fA-F0-9]{32}\b/g, confidence: 0.85 },

  // Threat Intel & Vulnerabilities
  { type: 'cve', re: /\bCVE-\d{4}-\d{4,7}\b/gi, confidence: 0.99 },
  { type: 'attack_technique', re: /\bT\d{4}(?:\.\d{3})?\b/g, confidence: 0.85 },
  { type: 'attack_software', re: KNOWN_ATTACK_SOFTWARE_REGEX, confidence: 0.9 },
  { type: 'attack_group', re: KNOWN_ATTACK_GROUPS_REGEX, confidence: 0.9 },

  // Crypto Wallets
  {
    type: 'btc_address',
    re: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{38,59})\b/g,
    confidence: 0.92,
  },
  {
    type: 'monero_address',
    re: /\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g,
    confidence: 0.95,
  },

  // URLs & Defanged URLs
  {
    type: 'url',
    re: /\b(?:https?|ftp|hxxp(?:s?)):\/\/[^\s"'<>()]+|\b(?:https?|hxxp(?:s?))\s*:\s*\/\/[^\s"'<>()]+/gi,
    confidence: 0.95,
  },

  // Email
  {
    type: 'email',
    re: /\b[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g,
    confidence: 0.9,
  },

  // IPv4 Addresses (with semantic version filter & private/reserved filter)
  {
    type: 'ipv4',
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    confidence: 0.9,
    validate: (v, ctx) => !isPrivateOrReservedIPv4(v) && !isSemanticVersion(v, ctx),
  },

  // IPv6 Addresses
  {
    type: 'ipv6',
    re: /\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b|\b(?:[a-fA-F0-9]{1,4}:){1,7}:[a-fA-F0-9]{1,4}\b/g,
    confidence: 0.85,
  },

  // Autonomous System Number (ASN)
  {
    type: 'asn',
    re: /\bAS\d{2,6}\b/gi,
    confidence: 0.9,
  },

  // Mutexes (Windows Named Mutexes)
  {
    type: 'mutex',
    re: /\b(?:Global\\|Local\\)[A-Za-z0-9_.\-{}]{4,64}\b/g,
    confidence: 0.95,
  },

  // Named Pipes
  {
    type: 'named_pipe',
    re: /\\\\(?:\.|[a-zA-Z0-9.\-_]+)\\pipe\\[a-zA-Z0-9.\-_\\/]+/gi,
    confidence: 0.95,
  },

  // Windows Registry Paths
  {
    type: 'registry_path',
    re: /\bHK(?:EY_)?(?:LOCAL_MACHINE|LM|CURRENT_USER|CU|CLASSES_ROOT|USERS)\\[^\s"'<>|]+/gi,
    confidence: 0.95,
  },

  // Windows Filesystem Paths
  {
    type: 'windows_path',
    re: /\b(?:[A-Za-z]:\\|%[A-Za-z_]+%\\)(?:[^\s"'<>|:*?]+\\)*[^\s"'<>|:*?]+\.[A-Za-z0-9]{1,5}\b/g,
    confidence: 0.75,
  },

  // Linux / UNIX Filesystem Paths
  {
    type: 'linux_path',
    re: /(?:\/etc\/|\/tmp\/|\/var\/(?:run|log|tmp)\/|\/bin\/|\/usr\/(?:bin|sbin|local)\/)[a-zA-Z0-9._\-\/]+/g,
    confidence: 0.75,
  },

  // User-Agent Strings
  {
    type: 'user_agent',
    re: /\b(?:Mozilla\/5\.0\s*\([^)]+\)\s*[^\r\n]{10,80}|curl\/\d+\.\d+(?:\.\d+)?|Wget\/\d+\.\d+(?:\.\d+)?|python-requests\/\d+\.\d+)\b/gi,
    confidence: 0.88,
  },

  // Domains & FQDNs
  {
    type: 'domain',
    re: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|ru|cn|info|biz|xyz|top|club|online|site|dev|app|to|cc|tk|ml|ga|cf|icu|shop|buzz|rest|wiki|click|link|su|pro|live)\b/gi,
    confidence: 0.65,
    validate: (v) => !/^\d+(\.\d+){3}$/.test(v) && !/^[a-fA-F0-9]{32,}$/.test(v),
  },
];

/**
 * Extract IOCs from one labeled block of text with full provenance and context-awareness.
 */
function extractFromText(text: string, source: string): ExtractedIOC[] {
  if (!text) return [];
  const out: ExtractedIOC[] = [];
  const scanTexts = [text];
  const normalizedScanText = defangForScanning(text);
  if (normalizedScanText !== text) scanTexts.push(normalizedScanText);

  for (const scanText of scanTexts) {
    for (const det of DETECTORS) {
      det.re.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = det.re.exec(scanText)) !== null) {
        const rawValue = match[0];
        const normalizedValue = normalizeDefangedValue(rawValue);
        const { lineNumber, context } = contextAround(scanText, rawValue);

        if (det.validate && !det.validate(normalizedValue || rawValue, context)) continue;

        // Context-aware role & confidence inference
        const roleInfo = inferRoleAndEvidence(context, det.type);
        const calibratedConfidence = Math.max(0.1, Math.min(1.0, det.confidence + roleInfo.confidenceAdjustment));

        out.push({
          type: det.type,
          value: rawValue,
          normalizedValue: normalizedValue !== rawValue ? normalizedValue : undefined,
          source,
          location: source,
          lineNumber,
          context,
          confidence: Number(calibratedConfidence.toFixed(2)),
          role: roleInfo.role,
          roleEvidence: roleInfo.roleEvidence,
          firstSeen: new Date().toISOString(),
        });
        if (out.length > 500) return out;
      }
    }
  }

  const deduped = new Map<string, ExtractedIOC>();
  for (const ioc of out) {
    const key = `${ioc.type}:${(ioc.normalizedValue || ioc.value).toLowerCase()}`;
    const existing = deduped.get(key);
    if (!existing || ioc.confidence > existing.confidence) {
      deduped.set(key, ioc);
    }
  }

  return Array.from(deduped.values());
}

export interface IOCExtractionInput {
  fileName?: string;
  previewContent?: string;
  /** Strings already surfaced by the Malware Intelligence Engine's static analysis, if this artifact went through it. */
  staticStrings?: {
    suspicious?: string[];
    network?: string[];
    persistence?: string[];
  };
}

export function extractIOCs(input: IOCExtractionInput): ExtractedIOC[] {
  const found: ExtractedIOC[] = [];
  if (input.fileName) found.push(...extractFromText(input.fileName, 'artifact filename'));
  if (input.previewContent) found.push(...extractFromText(input.previewContent, 'preview content'));
  if (input.staticStrings) {
    const { suspicious = [], network = [], persistence = [] } = input.staticStrings;
    found.push(...extractFromText(network.join('\n'), 'static analysis: network strings'));
    found.push(...extractFromText(persistence.join('\n'), 'static analysis: persistence strings'));
    found.push(...extractFromText(suspicious.join('\n'), 'static analysis: suspicious strings'));
  }

  // De-dupe by type+value, keeping the highest-confidence / richest provenance.
  const byKey = new Map<string, ExtractedIOC>();
  for (const ioc of found) {
    const key = `${ioc.type}:${(ioc.normalizedValue || ioc.value).toLowerCase()}`;
    const existing = byKey.get(key);
    if (!existing || ioc.confidence > existing.confidence) {
      byKey.set(key, ioc);
    }
  }
  return Array.from(byKey.values());
}

export function summarizeIOCsByType(iocs: ExtractedIOC[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const ioc of iocs) {
    counts[ioc.type] = (counts[ioc.type] || 0) + 1;
  }
  return counts;
}

export function summarizeIOCsByRole(iocs: ExtractedIOC[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const ioc of iocs) {
    if (ioc.role) {
      counts[ioc.role] = (counts[ioc.role] || 0) + 1;
    }
  }
  return counts;
}
