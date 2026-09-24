/**
 * Real static code-review heuristics for script/source artifacts.
 *
 * Pattern-matches actual source text for well-documented dangerous
 * constructs (dynamic eval/exec, encoded PowerShell, download-and-execute
 * chains, obfuscation via heavy encoding). This is deliberately a
 * conservative, explainable rule set — every hit carries the exact snippet
 * that triggered it — rather than a black-box "malicious/safe" coin flip.
 * It does not execute the reviewed code.
 */
import { EvidenceFinding } from '../types';

interface CodePattern {
  id: string;
  re: RegExp;
  severity: 'low' | 'medium' | 'high';
  label: string;
}

const PATTERNS: CodePattern[] = [
  { id: 'powershell-command', re: /\b(?:powershell|pwsh)\b(?:[^\n;]{0,100})/gi, severity: 'low', label: 'PowerShell command or invocation' },
  { id: 'remote-download', re: /\b(?:Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|WebClient|curl|wget)\b/gi, severity: 'medium', label: 'Remote resource download primitive' },
  { id: 'ps-encoded-command', re: /-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}/gi, severity: 'high', label: 'Base64-encoded PowerShell command (-EncodedCommand)' },
  { id: 'ps-hidden-window', re: /-w(?:indowstyle)?\s+hidden/gi, severity: 'medium', label: 'PowerShell launched with a hidden window' },
  { id: 'ps-bypass', re: /-ExecutionPolicy\s+Bypass/gi, severity: 'medium', label: 'PowerShell execution-policy bypass' },
  { id: 'download-execute', re: /(?:Invoke-WebRequest|Invoke-Expression|IEX|wget|curl)\s*\(?[^\n;]{0,120}(?:iex|invoke-expression|\|\s*sh\b|\|\s*bash\b)/gi, severity: 'high', label: 'Download-and-execute chain' },
  { id: 'js-eval', re: /\beval\s*\(/g, severity: 'medium', label: 'Dynamic eval() of a string' },
  { id: 'py-exec', re: /\bexec\s*\(\s*(?:base64|compile|__import__)/g, severity: 'high', label: 'exec() of decoded/compiled input' },
  { id: 'py-pickle-loads', re: /\bpickle\.loads?\s*\(/g, severity: 'medium', label: 'Deserializing untrusted data with pickle' },
  { id: 'shell-download-pipe', re: /curl\s+[^\n|]+\|\s*(?:sh|bash)\b/gi, severity: 'high', label: 'Shell download piped directly into bash/sh' },
  { id: 'reverse-shell', re: /\/dev\/tcp\/\d/g, severity: 'high', label: 'Bash /dev/tcp reverse-shell pattern' },
  { id: 'base64-decode-run', re: /(?:FromBase64String|base64\.b64decode|atob\()/g, severity: 'low', label: 'Base64 decode of embedded payload' },
  { id: 'process-hollowing-api', re: /\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection)\b/g, severity: 'high', label: 'Process-injection API reference' },
  { id: 'amsi-bypass', re: /\bAmsiScanBuffer\b|\[Ref\]\.Assembly\.GetType\(['"]System\.Management\.Automation\.AmsiUtils/gi, severity: 'high', label: 'AMSI-bypass indicator' },
  { id: 'obfuscated-charcode', re: /(?:String\.fromCharCode|chr\(\d+\)\s*\+\s*chr\(\d+\))(?:\s*[,+]\s*(?:String\.fromCharCode|chr\(\d+\)))+/gi, severity: 'low', label: 'Character-code obfuscation' },
  { id: 'disable-defender', re: /Set-MpPreference\s+-DisableRealtimeMonitoring/gi, severity: 'high', label: 'Disables Windows Defender real-time monitoring' },
  { id: 'delete-shadow-copies', re: /vssadmin\s+delete\s+shadows/gi, severity: 'high', label: 'Deletes volume shadow copies (common ransomware precursor)' },
  { id: 'csharp-tcp-client', re: /\b(?:System\.Net\.)?Sockets\.TCPClient\b/gi, severity: 'medium', label: 'C# TCP client network connection' },
  { id: 'csharp-web-client', re: /\bSystem\.Net\.WebClient\b/gi, severity: 'medium', label: 'C# WebClient download capability' },
  { id: 'powershell-web-client', re: /\bNew-Object\s+System\.Net\.WebClient\b/gi, severity: 'medium', label: 'PowerShell WebClient downloader' },
  { id: 'python-os-system', re: /\bos\.system\s*\(/g, severity: 'medium', label: 'Python shell command execution via os.system()' },
  { id: 'python-subprocess-shell', re: /\bsubprocess\.Popen\s*\([\s\S]{0,160}?shell\s*=\s*True/gi, severity: 'high', label: 'Python subprocess launched with shell=True' },
];

/** Rough obfuscation signal: long runs of hex/unicode escapes or base64-looking blobs relative to code length. */
function obfuscationRatio(text: string): number {
  if (!text) return 0;
  const escapeChars = (text.match(/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g) || []).join('').length;
  const longBase64 = (text.match(/[A-Za-z0-9+/]{60,}={0,2}/g) || []).join('').length;
  return Math.min(1, (escapeChars + longBase64) / Math.max(200, text.length));
}

export interface CodeReviewResult {
  verdict: 'Malicious' | 'Suspicious' | 'Safe';
  maliciousScore: number;
  findings: EvidenceFinding[];
  summary: string;
}

export function analyzeCode(source: string): CodeReviewResult {
  const findings: EvidenceFinding[] = [];
  let highHits = 0;
  let mediumHits = 0;
  let lowHits = 0;

  for (const pattern of PATTERNS) {
    pattern.re.lastIndex = 0;
    const matches = [...source.matchAll(pattern.re)];
    if (matches.length === 0) continue;
    if (pattern.severity === 'high') highHits += matches.length;
    else if (pattern.severity === 'medium') mediumHits += matches.length;
    else lowHits += matches.length;
    const snippet = matches[0][0].length > 80 ? `${matches[0][0].slice(0, 80)}…` : matches[0][0];
    findings.push({
      claim: pattern.label,
      evidence: snippet,
      source: `static.code_pattern.${pattern.id}`,
      confidence: pattern.severity === 'high' ? 0.9 : pattern.severity === 'medium' ? 0.7 : 0.5,
    });
  }

  const obf = obfuscationRatio(source);
  if (obf > 0.15) {
    findings.push({
      claim: 'Elevated encoding/obfuscation density',
      evidence: `${Math.round(obf * 100)}% of scanned content is hex/unicode-escaped or long base64-like runs`,
      source: 'static.code_pattern.obfuscation_ratio',
      confidence: Math.min(0.85, 0.4 + obf),
    });
  }

  const score = Math.min(100, highHits * 30 + mediumHits * 15 + lowHits * 6 + Math.round(obf * 20));
  const verdict: CodeReviewResult['verdict'] = score >= 55 ? 'Malicious' : score >= 20 ? 'Suspicious' : 'Safe';

  const summary = findings.length
    ? `Static review found ${findings.length} indicator(s): ${findings.slice(0, 3).map((f) => f.claim).join('; ')}${findings.length > 3 ? '; …' : ''}.`
    : 'Static review found no known dangerous constructs, download-and-execute chains, or obfuscation patterns in this source.';

  return { verdict, maliciousScore: score, findings, summary };
}
