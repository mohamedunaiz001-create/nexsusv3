/**
 * Real IOC Extraction Engine.
 *
 * Runs a set of independent detectors (hashes, network indicators, CVEs,
 * ATT&CK technique IDs, filesystem/registry paths) over actual artifact
 * text — the artifact's file name, any preview/paste content the operator
 * supplied, and the printable-string findings already surfaced by the
 * Malware Intelligence Engine's static analysis (suspiciousStrings,
 * networkIndicatorStrings, persistenceIndicatorStrings — see
 * python-server/app/malware_intel/features.py).
 *
 * This never invents an indicator count: if there's no text to scan, it
 * returns an empty list, and the caller (multiAgentAnalysis.ts) is
 * responsible for reporting that honestly rather than substituting a
 * plausible-looking random number.
 */
import { ExtractedIOC, ExtractedIOCType } from '../types';

interface Detector {
  type: ExtractedIOCType;
  re: RegExp;
  confidence: number;
  /** Optional post-match validator to cut down on false positives regex alone can't catch. */
  validate?: (value: string) => boolean;
}

function isPrivateOrReservedIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 0 || a === 255) return true;
  return false;
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
    .replace(/hxxps?/gi, (protocol) => protocol.toLowerCase().startsWith('hxxps') ? 'https' : 'http')
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

// Order matters: hashes and CVEs/ATT&CK IDs are checked before the looser
// domain pattern so a 64-char hex hash never gets misread as a "domain".
const DETECTORS: Detector[] = [
  { type: 'sha256', re: /\b[a-fA-F0-9]{64}\b/g, confidence: 0.98 },
  { type: 'sha1', re: /\b[a-fA-F0-9]{40}\b/g, confidence: 0.9 },
  { type: 'md5', re: /\b[a-fA-F0-9]{32}\b/g, confidence: 0.85 },
  { type: 'cve', re: /\bCVE-\d{4}-\d{4,7}\b/gi, confidence: 0.99 },
  { type: 'attack_technique', re: /\bT\d{4}(?:\.\d{3})?\b/g, confidence: 0.75 },
  { type: 'url', re: /\b(?:https?|hxxp(?:s?)):\/\/[^\s"'<>()]+|\b(?:https?|hxxp(?:s?))\s*:\s*\/\/[^\s"'<>()]+/gi, confidence: 0.95 },
  { type: 'email', re: /\b[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g, confidence: 0.9 },
  {
    type: 'ipv4',
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    confidence: 0.9,
    validate: (v) => !isPrivateOrReservedIPv4(v),
  },
  {
    type: 'ipv6',
    re: /\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b/g,
    confidence: 0.85,
  },
  {
    type: 'registry_path',
    re: /\bHK(?:EY_)?(?:LOCAL_MACHINE|LM|CURRENT_USER|CU|CLASSES_ROOT|USERS)\\[^\s"'<>|]+/gi,
    confidence: 0.95,
  },
  {
    type: 'file_path',
    re: /\b[A-Za-z]:\\(?:[^\s"'<>|:*?]+\\)*[^\s"'<>|:*?]+\.[A-Za-z0-9]{1,5}\b/g,
    confidence: 0.7,
  },
  {
    type: 'domain',
    re: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|ru|cn|info|biz|xyz|top|club|online|site|dev|app|to|cc|tk|ml|ga|cf|icu|shop|buzz|rest|wiki|click|link)\b/gi,
    confidence: 0.6,
    validate: (v) => !/^\d+(\.\d+){3}$/.test(v),
  },
];

/**
 * Extract IOCs from one labeled block of text. `source` is recorded as
 * provenance on every hit so downstream consumers can show "found in
 * filename" vs "found in preview content" vs "found in static string scan".
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
        if (det.validate && !det.validate(normalizedValue || rawValue)) continue;
        const { lineNumber, context } = contextAround(scanText, rawValue);
        out.push({
          type: det.type,
          value: rawValue,
          normalizedValue: normalizedValue !== rawValue ? normalizedValue : undefined,
          source,
          location: source,
          lineNumber,
          context,
          confidence: det.confidence,
        });
        if (out.length > 500) return out;
      }
    }
  }

  const deduped = new Map<string, ExtractedIOC>();
  for (const ioc of out) {
    const key = `${ioc.type}:${(ioc.normalizedValue || ioc.value).toLowerCase()}`;
    const existing = deduped.get(key);
    if (!existing || ioc.confidence > existing.confidence) deduped.set(key, ioc);
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

  // De-dupe by type+value, keeping the highest-confidence / first provenance.
  const byKey = new Map<string, ExtractedIOC>();
  for (const ioc of found) {
    const key = `${ioc.type}:${(ioc.normalizedValue || ioc.value).toLowerCase()}`;
    const existing = byKey.get(key);
    if (!existing || ioc.confidence > existing.confidence) byKey.set(key, ioc);
  }
  return Array.from(byKey.values());
}

export function summarizeIOCsByType(iocs: ExtractedIOC[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const ioc of iocs) counts[ioc.type] = (counts[ioc.type] || 0) + 1;
  return counts;
}
