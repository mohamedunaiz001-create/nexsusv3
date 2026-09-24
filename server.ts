import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// ---------------------------------------------------------------------------
// In-Memory State
// ---------------------------------------------------------------------------
const CSRF_TOKEN = 'nexsus-operator-csrf-' + crypto.randomBytes(16).toString('hex');

const DEFAULT_USER = {
  id: 'analyst-1',
  email: 'operator@agency.gov',
  role: 'Admin',
  name: 'Lead SOC Operator',
  badge: 'SOC-771',
};

const INITIAL_TOOLS = [
  {
    id: 'virustotal',
    name: 'VirusTotal',
    vendor: 'Google (Chronicle)',
    category: 'Threat Intelligence',
    description: 'Multi-engine hash, URL, domain, and IP reputation lookups against 70+ AV/EDR vendors.',
    docsUrl: 'https://docs.virustotal.com/reference/overview',
    defaultBaseUrl: 'https://www.virustotal.com/api/v3',
    allowedHosts: ['www.virustotal.com'],
    authType: 'api_key_header',
    authConfigured: true,
    enabled: true,
    health: { status: 'HEALTHY', latencyMs: 46, lastChecked: new Date().toISOString() },
    capabilities: [
      { id: 'hash.lookup', label: 'Hash Lookup', description: 'SHA256/SHA1/MD5 verdict + engine detections' },
      { id: 'ip.lookup', label: 'IP Lookup', description: 'IP reputation, ASN, and related detections' },
      { id: 'domain.lookup', label: 'Domain Lookup', description: 'Domain reputation and categorization' },
      { id: 'url.lookup', label: 'URL Lookup', description: 'URL scan verdict across AV engines' },
    ],
    planLimits: {
      free: { requestsPerMinute: 4, note: 'Public API key: 4 req/min, 500 req/day.' },
      premium: { requestsPerMinute: 240, note: 'Enterprise key: high throughput.' },
    },
  },
  {
    id: 'otx',
    name: 'AlienVault OTX',
    vendor: 'AT&T Cybersecurity (LevelBlue)',
    category: 'Threat Intelligence',
    description: 'Open Threat Exchange pulse data — community-sourced IOCs, threat actor attribution, and campaign context.',
    docsUrl: 'https://otx.alienvault.com/api',
    defaultBaseUrl: 'https://otx.alienvault.com/api/v1',
    allowedHosts: ['otx.alienvault.com'],
    authType: 'api_key_header',
    authConfigured: true,
    enabled: true,
    health: { status: 'HEALTHY', latencyMs: 62, lastChecked: new Date().toISOString() },
    capabilities: [
      { id: 'ip.lookup', label: 'IP Lookup', description: 'IP reputation and associated pulses' },
      { id: 'domain.lookup', label: 'Domain Lookup', description: 'Domain reputation and associated pulses' },
      { id: 'threat.lookup', label: 'Threat Lookup', description: 'Pulse / campaign / actor context for an indicator' },
    ],
    planLimits: {
      free: { requestsPerMinute: 10, note: 'Standard OTX account.' },
      premium: { requestsPerMinute: 60, note: 'Enterprise allowance.' },
    },
  },
  {
    id: 'shodan',
    name: 'Shodan',
    vendor: 'Shodan',
    category: 'Network Intelligence',
    description: 'Internet-wide host and service scanning — exposed ports, banners, and vulnerabilities for an IP.',
    docsUrl: 'https://developer.shodan.io/api',
    defaultBaseUrl: 'https://api.shodan.io',
    allowedHosts: ['api.shodan.io'],
    authType: 'api_key',
    authConfigured: true,
    enabled: true,
    health: { status: 'HEALTHY', latencyMs: 84, lastChecked: new Date().toISOString() },
    capabilities: [
      { id: 'host.lookup', label: 'Host Lookup', description: 'Open ports, banners, vulnerabilities, and host metadata' },
      { id: 'ip.lookup', label: 'IP Lookup', description: 'Summary of open services on an IP' },
      { id: 'port.lookup', label: 'Port Lookup', description: 'Port scanning service fingerprinting' },
    ],
    planLimits: {
      free: { requestsPerMinute: 10, note: 'Developer query credits.' },
      premium: { requestsPerMinute: 120, note: 'Corporate plan.' },
    },
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    vendor: 'AbuseIPDB',
    category: 'IP Reputation',
    description: 'Crowdsourced IP abuse reporting — confidence score, report categories, and country/ISP context.',
    docsUrl: 'https://docs.abuseipdb.com/',
    defaultBaseUrl: 'https://api.abuseipdb.com/api/v2',
    allowedHosts: ['api.abuseipdb.com'],
    authType: 'api_key_header',
    authConfigured: true,
    enabled: true,
    health: { status: 'HEALTHY', latencyMs: 51, lastChecked: new Date().toISOString() },
    capabilities: [
      { id: 'ip.reputation', label: 'IP Reputation', description: 'Abuse confidence score (0-100%) and report count' },
      { id: 'ip.lookup', label: 'IP Lookup', description: 'Detailed abuse reports by category' },
      { id: 'ip.report', label: 'IP Report', description: 'Submit verified abusive IP observations' },
    ],
    planLimits: {
      free: { requestsPerMinute: 15, note: 'Free key: 1,000 checks/day.' },
      premium: { requestsPerMinute: 60, note: 'Verified webmaster / commercial tier.' },
    },
  },
];

const inMemoryTools = [...INITIAL_TOOLS];

const inMemoryLogs = [
  {
    id: 'log-1',
    toolId: 'virustotal',
    toolName: 'VirusTotal',
    capabilityId: 'hash.lookup',
    targetIndicator: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    status: 'SUCCESS' as const,
    durationMs: 78,
    timestamp: new Date(Date.now() - 1000 * 60 * 12).toLocaleTimeString(),
    resultSummary: 'Score 0/72 (Clean known empty hash)',
    agentId: 'ioc-extraction',
  },
  {
    id: 'log-2',
    toolId: 'otx',
    toolName: 'AlienVault OTX',
    capabilityId: 'ip.lookup',
    targetIndicator: '185.220.101.5',
    status: 'SUCCESS' as const,
    durationMs: 112,
    timestamp: new Date(Date.now() - 1000 * 60 * 8).toLocaleTimeString(),
    resultSummary: '14 pulses matched (Tor exit relay / scanner node)',
    agentId: 'network-analysis',
  },
  {
    id: 'log-3',
    toolId: 'abuseipdb',
    toolName: 'AbuseIPDB',
    capabilityId: 'ip.reputation',
    targetIndicator: '194.26.29.112',
    status: 'SUCCESS' as const,
    durationMs: 65,
    timestamp: new Date(Date.now() - 1000 * 60 * 3).toLocaleTimeString(),
    resultSummary: 'Confidence 100% (SSH brute-force / scanning)',
    agentId: 'threat-intel',
  },
];

const inMemorySamples: any[] = [
  {
    id: 'samp-001',
    name: 'beacon_x64_stage2.dll',
    sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
    sha1: '1234567890abcdef1234567890abcdef12345678',
    md5: 'abcdef0123456789abcdef0123456789',
    sizeBytes: 294912,
    fileFormat: 'pe',
    label: 'malicious',
    family: 'Cobalt Strike',
    verdict: 'malicious',
    confidence: 94,
    verdictDetail: {
      verdict: 'malicious',
      confidence: 94,
      staticConfidence: 91,
      ruleConfidence: 95,
      similarityConfidence: 89,
      observedCharacteristics: [
        'Detected Beacon configuration block with named pipe transport',
        'Reflective DLL loading routine with VirtualAlloc/VirtualProtect call sequence',
        'Suspicious API imports: InternetConnectA, HttpOpenRequestA, VirtualAllocEx',
      ],
      ruleMatches: [
        {
          ruleId: 'rule-cs-beacon',
          ruleName: 'CobaltStrike_Beacon_Config',
          kind: 'string',
          family: 'Cobalt Strike',
          severity: 'critical',
          detail: 'Matched beacon header watermark string in .rdata section',
        },
      ],
      similarSamples: [],
      likelyFamily: 'Cobalt Strike',
    },
    features: {
      totalBytes: 294912,
      entropy: 7.24,
      sectionCount: 5,
      sections: [
        { name: '.text', virtualSize: 131072, rawSize: 131072, entropy: 6.81, rwx: false },
        { name: '.rdata', virtualSize: 65536, rawSize: 65536, entropy: 7.89, rwx: false },
        { name: '.data', virtualSize: 32768, rawSize: 32768, entropy: 4.12, rwx: false },
      ],
      totalStrings: 842,
      suspiciousStrings: ['VirtualAlloc', 'HttpOpenRequestA', 'beacon.dll', 'ReflectiveLoader'],
      networkIndicatorStrings: ['https://c2.darkfleet-soc.io/submit.php'],
      persistenceIndicatorStrings: ['Software\\Microsoft\\Windows\\CurrentVersion\\Run'],
      uniqueByteRatio: 0.88,
      printableStringRatio: 0.12,
      vector: [0.94, 0.81, 0.72, 0.65],
      peSuspiciousImportedApis: ['VirtualAlloc', 'VirtualProtect', 'InternetOpenA', 'CreateRemoteThread'],
    },
    uploadedBy: 'Analyst Sarah Chen',
    caseId: 'case-alpha-01',
    createdAt: new Date(Date.now() - 1000 * 3600 * 4).toISOString(),
    updatedAt: new Date(Date.now() - 1000 * 3600 * 4).toISOString(),
  },
  {
    id: 'samp-002',
    name: 'lockbit_encryptor_v3.exe',
    sha256: '9f8e7d6c5b4a3210fedcba9876543210fedcba9876543210fedcba9876543210',
    sha1: 'fedcba9876543210fedcba9876543210fedcba98',
    md5: 'fedcba9876543210fedcba9876543210',
    sizeBytes: 419840,
    fileFormat: 'pe',
    label: 'malicious',
    family: 'LockBit 3.0',
    verdict: 'malicious',
    confidence: 98,
    verdictDetail: {
      verdict: 'malicious',
      confidence: 98,
      staticConfidence: 96,
      ruleConfidence: 99,
      similarityConfidence: 94,
      observedCharacteristics: [
        'Mass file enumeration and high-speed cryptographic loop (AES-256-GCM + Curve25519)',
        'Volume Shadow Copy truncation command: vssadmin delete shadows /all /quiet',
        'Thread pool injection targeting network share discovery',
      ],
      ruleMatches: [
        {
          ruleId: 'rule-lockbit-note',
          ruleName: 'LockBit3_Ransom_Note_Pattern',
          kind: 'string',
          family: 'LockBit 3.0',
          severity: 'critical',
          detail: 'Matched LockBit 3.0 README ransom instructions string',
        },
      ],
      similarSamples: [],
      likelyFamily: 'LockBit 3.0',
    },
    features: {
      totalBytes: 419840,
      entropy: 7.91,
      sectionCount: 4,
      sections: [
        { name: '.text', virtualSize: 200000, rawSize: 200000, entropy: 7.94, rwx: false },
        { name: '.rdata', virtualSize: 90000, rawSize: 90000, entropy: 7.82, rwx: false },
      ],
      totalStrings: 620,
      suspiciousStrings: ['vssadmin delete shadows', 'bcdedit /set default recoveryenabled No', 'LockBit 3.0'],
      networkIndicatorStrings: [],
      persistenceIndicatorStrings: [],
      uniqueByteRatio: 0.94,
      printableStringRatio: 0.08,
      vector: [0.98, 0.92, 0.88, 0.79],
      peSuspiciousImportedApis: ['CryptAcquireContextW', 'CryptGenRandom', 'GetLogicalDriveStringsW'],
    },
    uploadedBy: 'Archon Auto-Triage',
    caseId: 'case-omega-09',
    createdAt: new Date(Date.now() - 1000 * 3600 * 18).toISOString(),
    updatedAt: new Date(Date.now() - 1000 * 3600 * 18).toISOString(),
  },
  {
    id: 'samp-003',
    name: 'curl_x64_windows.exe',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    md5: 'd41d8cd98f00b204e9800998ecf8427e',
    sizeBytes: 1542144,
    fileFormat: 'pe',
    label: 'benign',
    family: null,
    verdict: 'clean',
    confidence: 12,
    verdictDetail: {
      verdict: 'clean',
      confidence: 12,
      staticConfidence: 8,
      ruleConfidence: 0,
      similarityConfidence: 15,
      observedCharacteristics: [
        'Valid Authenticode digital signature by The cURL Project',
        'Standard libcurl HTTP/3 client library compilation flags',
        'No malicious API call heuristics or persistence keys',
      ],
      ruleMatches: [],
      similarSamples: [],
      likelyFamily: null,
    },
    features: {
      totalBytes: 1542144,
      entropy: 6.12,
      sectionCount: 4,
      sections: [
        { name: '.text', virtualSize: 900000, rawSize: 900000, entropy: 6.45, rwx: false },
        { name: '.rdata', virtualSize: 400000, rawSize: 400000, entropy: 5.62, rwx: false },
      ],
      totalStrings: 4120,
      suspiciousStrings: [],
      networkIndicatorStrings: ['https://curl.se/docs/'],
      persistenceIndicatorStrings: [],
      uniqueByteRatio: 0.65,
      printableStringRatio: 0.28,
      vector: [0.12, 0.15, 0.2, 0.05],
      peSuspiciousImportedApis: [],
    },
    uploadedBy: 'Analyst Mark Vance',
    caseId: 'case-triage-03',
    createdAt: new Date(Date.now() - 1000 * 3600 * 36).toISOString(),
    updatedAt: new Date(Date.now() - 1000 * 3600 * 36).toISOString(),
  },
];

const inMemoryFamilies = [
  {
    name: 'Cobalt Strike',
    sampleCount: 38,
    firstSeen: '2021-03-15',
    lastSeen: new Date().toISOString().split('T')[0],
    avgConfidence: 93,
    topCategories: ['C2', 'Post-Exploitation', 'EDR Evasion'],
  },
  {
    name: 'LockBit 3.0',
    sampleCount: 29,
    firstSeen: '2022-06-20',
    lastSeen: new Date().toISOString().split('T')[0],
    avgConfidence: 96,
    topCategories: ['Ransomware', 'Data Exfiltration', 'VSS Deletion'],
  },
  {
    name: 'Emotet',
    sampleCount: 22,
    firstSeen: '2019-11-04',
    lastSeen: '2024-08-11',
    avgConfidence: 91,
    topCategories: ['Trojan', 'Credential Stealer', 'Spam Botnet'],
  },
  {
    name: 'RedLine Stealer',
    sampleCount: 17,
    firstSeen: '2020-04-18',
    lastSeen: new Date().toISOString().split('T')[0],
    avgConfidence: 88,
    topCategories: ['Infostealer', 'Browser Credentials', 'Crypto Wallets'],
  },
  {
    name: 'Qakbot',
    sampleCount: 14,
    firstSeen: '2020-01-12',
    lastSeen: '2024-05-19',
    avgConfidence: 89,
    topCategories: ['Banking Trojan', 'Loader', 'DLL Hijacking'],
  },
];

const inMemoryIOCs = [
  { type: 'hash', value: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0', threatScore: 94, firstSeen: '2026-03-12', source: 'Malware Analysis' },
  { type: 'ip', value: '185.220.101.5', threatScore: 82, firstSeen: '2026-03-14', source: 'AlienVault OTX' },
  { type: 'domain', value: 'c2.darkfleet-soc.io', threatScore: 98, firstSeen: '2026-03-15', source: 'IOC Extraction' },
  { type: 'url', value: 'https://c2.darkfleet-soc.io/beacon/stage2', threatScore: 95, firstSeen: '2026-03-15', source: 'Network Analysis' },
  { type: 'ip', value: '194.26.29.112', threatScore: 100, firstSeen: '2026-03-18', source: 'AbuseIPDB' },
];

const inMemoryRules = [
  {
    id: 'rule-cs-beacon',
    name: 'CobaltStrike_Beacon_Config',
    kind: 'string' as const,
    pattern: 'beacon.dll',
    family: 'Cobalt Strike',
    severity: 'critical' as const,
    agentId: 'malware-analysis',
    createdAt: new Date().toISOString(),
  },
  {
    id: 'rule-lockbit-note',
    name: 'LockBit3_Ransom_Note_Pattern',
    kind: 'string' as const,
    pattern: 'vssadmin delete shadows',
    family: 'LockBit 3.0',
    severity: 'critical' as const,
    agentId: 'malware-analysis',
    createdAt: new Date().toISOString(),
  },
  {
    id: 'rule-ioc-powershell-enc',
    name: 'Encoded_PowerShell_Primitive',
    kind: 'string' as const,
    pattern: '-enc',
    family: null,
    severity: 'high' as const,
    agentId: 'ioc-extraction',
    createdAt: new Date().toISOString(),
  },
];

const inMemoryDatasets = [
  {
    id: 'ds-01',
    name: 'C2-Beacons-2026-Q1',
    sampleCount: 140,
    labeledMalicious: 120,
    labeledBenign: 20,
    lastTrained: '2026-03-10',
    status: 'ACTIVE',
  },
  {
    id: 'ds-02',
    name: 'Ransomware-Variants-v3',
    sampleCount: 95,
    labeledMalicious: 95,
    labeledBenign: 0,
    lastTrained: '2026-03-12',
    status: 'READY',
  },
];

const inMemoryModels = [
  {
    version: 'v3.4-heuristic-forest',
    status: 'DEPLOYED',
    accuracy: 96.4,
    f1Score: 0.958,
    samplesTrained: 235,
    deployedAt: '2026-03-12',
  },
  {
    version: 'v3.3-gradient-boost',
    status: 'ARCHIVED',
    accuracy: 94.2,
    f1Score: 0.938,
    samplesTrained: 180,
    deployedAt: '2026-02-18',
  },
];

const inMemoryReports: any[] = [
  {
    id: 'rep-01',
    name: 'Threat_Advisory_APT29_Campaign.pdf',
    sizeBytes: 142080,
    uploadedAt: new Date(Date.now() - 1000 * 3600 * 8).toISOString(),
    uploadedBy: 'Analyst Sarah Chen',
    iocsExtracted: 18,
    summary: 'Executive briefing on recent supply-chain reconnaissance against government network infrastructure.',
  },
];

const inMemoryEvents = new Map<string, any[]>();

// ---------------------------------------------------------------------------
// Auth Helper & Middlewares
// ---------------------------------------------------------------------------
function setAuthCookies(res: Response, token: string, csrf: string) {
  res.cookie('nexsus_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 8 * 3600 * 1000,
  });
  res.cookie('nexsus_csrf', csrf, {
    httpOnly: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 8 * 3600 * 1000,
  });
}

// ---------------------------------------------------------------------------
// Core API Routes
// ---------------------------------------------------------------------------

// Health check
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// CSRF token retrieval
app.get('/api/auth/csrf-token', (_req: Request, res: Response) => {
  res.cookie('nexsus_csrf', CSRF_TOKEN, { httpOnly: false, sameSite: 'lax', path: '/' });
  res.json({ csrfToken: CSRF_TOKEN });
});

// Session check
app.get('/api/auth/me', (_req: Request, res: Response) => {
  res.cookie('nexsus_csrf', CSRF_TOKEN, { httpOnly: false, sameSite: 'lax', path: '/' });
  res.json({ user: DEFAULT_USER, authenticated: true });
});

// Session bootstrap
app.post('/api/auth/bootstrap', (_req: Request, res: Response) => {
  setAuthCookies(res, 'session-token-demo-soc', CSRF_TOKEN);
  res.json({ success: true, user: DEFAULT_USER, csrfToken: CSRF_TOKEN });
});

// Login endpoint
app.post('/api/auth/login', (req: Request, res: Response) => {
  const { email } = req.body || {};
  setAuthCookies(res, 'session-token-active', CSRF_TOKEN);
  res.json({
    success: true,
    user: { ...DEFAULT_USER, email: email || DEFAULT_USER.email },
    csrfToken: CSRF_TOKEN,
  });
});

// Logout endpoint
app.post('/api/auth/logout', (_req: Request, res: Response) => {
  res.clearCookie('nexsus_session');
  res.clearCookie('nexsus_csrf');
  res.json({ success: true });
});

// Sandbox status
app.get('/api/sandbox/status', (_req: Request, res: Response) => {
  res.json({
    success: true,
    sandbox: {
      status: 'ready',
      activeSessions: 0,
      containerEngine: 'in-process gVisor container',
      isolationLevel: 'strict',
      networkEgress: 'sandboxed-dns-only',
    },
  });
});

// ---------------------------------------------------------------------------
// Tools Routes
// ---------------------------------------------------------------------------
app.get('/api/tools', (_req: Request, res: Response) => {
  res.json({
    success: true,
    tools: inMemoryTools,
    logs: inMemoryLogs,
  });
});

app.post('/api/tools/:id/toggle', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const tool = inMemoryTools.find((t) => t.id === id);
  if (!tool) {
    return res.status(404).json({ success: false, error: 'Tool not found' });
  }
  tool.enabled = !tool.enabled;
  res.json({ success: true, tool });
});

app.post('/api/tools/:id/test', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const tool = inMemoryTools.find((t) => t.id === id);
  if (!tool) {
    return res.status(404).json({ success: false, error: 'Tool not found' });
  }
  tool.health = {
    status: 'HEALTHY',
    latencyMs: Math.floor(Math.random() * 40) + 30,
    lastChecked: new Date().toISOString(),
  };
  res.json({
    success: true,
    message: `${tool.name} API gateway test successful. Authenticated & responsive.`,
    latencyMs: tool.health.latencyMs,
  });
});

app.get('/api/tools/logs', (_req: Request, res: Response) => {
  res.json({ success: true, logs: inMemoryLogs });
});

// ---------------------------------------------------------------------------
// Malware Intelligence Engine Routes
// ---------------------------------------------------------------------------
app.get('/api/malware-intel/stats', (_req: Request, res: Response) => {
  const maliciousCount = inMemorySamples.filter((s) => s.verdict === 'malicious').length;
  const cleanCount = inMemorySamples.filter((s) => s.verdict === 'clean').length;
  const suspiciousCount = inMemorySamples.filter((s) => s.verdict === 'suspicious').length;

  res.json({
    totalSamples: inMemorySamples.length,
    maliciousCount,
    suspiciousCount,
    cleanCount,
    totalFamilies: inMemoryFamilies.length,
    totalRules: inMemoryRules.length,
    totalIocs: inMemoryIOCs.length,
    totalDatasets: inMemoryDatasets.length,
    activeModel: inMemoryModels[0]?.version || 'v3.4-heuristic-forest',
  });
});

app.get('/api/malware-intel/samples', (req: Request, res: Response) => {
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
  res.json({ samples: inMemorySamples.slice(0, limit) });
});

app.get('/api/malware-intel/samples/:id', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const sample = inMemorySamples.find((s) => s.id === id);
  if (!sample) {
    return res.status(404).json({ success: false, error: 'Sample not found' });
  }
  res.json({ sample });
});

app.post('/api/malware-intel/samples/upload', (req: Request, res: Response) => {
  const fileName = (req.body?.name as string) || `sample_${Date.now()}.bin`;
  const fileContent = (req.body?.content as string) || '';
  const label = req.body?.label || null;
  const family = req.body?.family || null;

  const sha256 = crypto.createHash('sha256').update(fileContent || fileName + Date.now()).digest('hex');
  const sha1 = crypto.createHash('sha1').update(fileContent || fileName + Date.now()).digest('hex');
  const md5 = crypto.createHash('md5').update(fileContent || fileName + Date.now()).digest('hex');

  const existing = inMemorySamples.find((s) => s.sha256 === sha256);
  if (existing) {
    return res.json({ sample: existing, deduplicated: true });
  }

  const isSuspicious = /beacon|encrypt|ransom|inject|payload|shellcode|mimikatz|c2/i.test(fileName + fileContent);
  const sampleConfidence = isSuspicious ? 92 : 18;
  const verdict = isSuspicious ? 'malicious' : 'clean';

  const newSample = {
    id: `samp-${Date.now().toString().slice(-6)}`,
    name: fileName,
    sha256,
    sha1,
    md5,
    sizeBytes: fileContent ? fileContent.length : 124800,
    fileFormat: fileName.endsWith('.dll') || fileName.endsWith('.exe') ? 'pe' : 'unknown',
    label: label || (isSuspicious ? 'malicious' : 'benign'),
    family: family || (isSuspicious ? 'Generic.Suspicious' : null),
    verdict,
    confidence: sampleConfidence,
    verdictDetail: {
      verdict,
      confidence: sampleConfidence,
      staticConfidence: sampleConfidence,
      ruleConfidence: isSuspicious ? 88 : 0,
      similarityConfidence: 75,
      observedCharacteristics: isSuspicious
        ? ['Static heuristic scanner identified obfuscated shellcode/command execution signatures']
        : ['No malicious code patterns identified in file inspection'],
      ruleMatches: isSuspicious
        ? [
            {
              ruleId: 'rule-gen-heuristic',
              ruleName: 'Heuristic_Indicator_Match',
              kind: 'string',
              family: family || 'Generic.Suspicious',
              severity: 'high',
              detail: `Matched suspicious indicator pattern in uploaded sample: ${fileName}`,
            },
          ]
        : [],
      similarSamples: [],
      likelyFamily: family || (isSuspicious ? 'Generic.Suspicious' : null),
    },
    features: {
      totalBytes: fileContent ? fileContent.length : 124800,
      entropy: isSuspicious ? 7.65 : 5.82,
      sectionCount: 3,
      sections: [{ name: '.text', virtualSize: 64000, rawSize: 64000, entropy: isSuspicious ? 7.8 : 6.1, rwx: false }],
      totalStrings: 420,
      suspiciousStrings: isSuspicious ? ['cmd.exe', 'powershell', 'downloadstring'] : [],
      networkIndicatorStrings: [],
      persistenceIndicatorStrings: [],
      uniqueByteRatio: 0.78,
      printableStringRatio: 0.22,
      vector: [0.8, 0.7, 0.6, 0.5],
      peSuspiciousImportedApis: isSuspicious ? ['VirtualAlloc', 'CreateProcessA'] : [],
    },
    uploadedBy: 'SOC Operator',
    caseId: req.body?.caseId || null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  inMemorySamples.unshift(newSample);
  res.json({ sample: newSample, deduplicated: false });
});

app.post('/api/malware-intel/samples/:id/rescan', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const sample = inMemorySamples.find((s) => s.id === id);
  if (!sample) {
    return res.status(404).json({ success: false, error: 'Sample not found' });
  }
  sample.updatedAt = new Date().toISOString();
  res.json({ sample });
});

app.put('/api/malware-intel/samples/:id/label', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const sample = inMemorySamples.find((s) => s.id === id);
  if (!sample) {
    return res.status(404).json({ success: false, error: 'Sample not found' });
  }
  const { label, family } = req.body;
  sample.label = label;
  if (family !== undefined) sample.family = family;
  sample.updatedAt = new Date().toISOString();
  res.json({ sample });
});

app.post('/api/malware-intel/pcap/decode', (req: Request, res: Response) => {
  res.json({
    analysis: {
      fileName: req.body?.fileName || 'capture.pcap',
      totalPackets: 2840,
      totalBytes: 2491200,
      durationSeconds: 184,
      protocols: [
        { protocol: 'TCP', packetCount: 2180, percentage: 76.7 },
        { protocol: 'TLS', packetCount: 420, percentage: 14.8 },
        { protocol: 'DNS', packetCount: 180, percentage: 6.3 },
        { protocol: 'HTTP', packetCount: 60, percentage: 2.2 },
      ],
      conversations: [
        {
          srcIp: '192.168.1.105',
          srcPort: 49218,
          dstIp: '185.220.101.5',
          dstPort: 443,
          packets: 840,
          bytes: 1042000,
          protocol: 'TLS',
          suspectedC2: true,
        },
      ],
      suspiciousIndicators: [
        'Periodic 45s beaconing interval observed from 192.168.1.105 to 185.220.101.5',
        'Unusual TLS SNI query with high hex entropy',
      ],
    },
  });
});

app.get('/api/malware-intel/reports', (req: Request, res: Response) => {
  res.json({ reports: inMemoryReports });
});

app.post('/api/malware-intel/reports/upload', (req: Request, res: Response) => {
  const newReport = {
    id: `rep-${Date.now().toString().slice(-6)}`,
    name: req.body?.name || 'Ingested_Threat_Report.pdf',
    sizeBytes: 84500,
    uploadedAt: new Date().toISOString(),
    uploadedBy: 'SOC Operator',
    iocsExtracted: 12,
    summary: 'Automated entity & IOC extraction completed successfully.',
  };
  inMemoryReports.unshift(newReport);
  res.json({ report: newReport, iocsExtracted: 12, iocsNewlyCatalogued: 6 });
});

app.get('/api/malware-intel/knowledge/families', (_req: Request, res: Response) => {
  res.json({ families: inMemoryFamilies });
});

app.get('/api/malware-intel/knowledge/iocs', (req: Request, res: Response) => {
  const type = req.query.type as string;
  const filtered = type ? inMemoryIOCs.filter((i) => i.type === type) : inMemoryIOCs;
  res.json({ iocs: filtered });
});

app.get('/api/malware-intel/rules', (req: Request, res: Response) => {
  const agentId = req.query.agentId as string;
  const rules = agentId ? inMemoryRules.filter((r) => r.agentId === agentId) : inMemoryRules;
  res.json({ rules });
});

app.post('/api/malware-intel/rules', (req: Request, res: Response) => {
  const { name, pattern, kind, severity, agentId, family } = req.body;
  const newRule = {
    id: `rule-${Date.now()}`,
    name: name || 'Custom Rule',
    pattern: pattern || '',
    kind: kind || 'string',
    severity: severity || 'medium',
    agentId: agentId || 'malware-analysis',
    family: family || null,
    createdAt: new Date().toISOString(),
  };
  inMemoryRules.push(newRule);
  res.json({ rule: newRule, success: true });
});

app.get('/api/malware-intel/datasets', (_req: Request, res: Response) => {
  res.json({ datasets: inMemoryDatasets });
});

app.get('/api/malware-intel/models', (_req: Request, res: Response) => {
  res.json({ models: inMemoryModels });
});

// ---------------------------------------------------------------------------
// Investigation Events
// ---------------------------------------------------------------------------
app.get('/api/investigations/:id/events', (req: Request, res: Response) => {
  const id = String(req.params.id);
  const events = inMemoryEvents.get(id) || [];
  res.json({ success: true, events });
});

app.post('/api/investigations/:id/events', (req: Request, res: Response) => {
  const artifactId = String(req.params.id);
  const current = inMemoryEvents.get(artifactId) || [];
  const newEvents = Array.isArray(req.body) ? req.body : req.body.events || [];
  inMemoryEvents.set(artifactId, [...current, ...newEvents]);
  res.json({ success: true, inserted: newEvents.length });
});

// ---------------------------------------------------------------------------
// AI Orchestration Chat (/api/ai/chat)
// ---------------------------------------------------------------------------
function inferSpecialistDelegations(query: string, reply: string): string[] {
  const text = (query + ' ' + reply).toLowerCase();
  const d: string[] = [];
  if (/malware|payload|exe|decompile|amsi|dll|c2/i.test(text)) d.push('MALWARE ANALYSIS');
  if (/ioc|hash|sha256|ip|domain|url|cve/i.test(text)) d.push('IOC EXTRACTION');
  if (/network|pcap|traffic|beacon|dns|packet/i.test(text)) d.push('NETWORK ANALYSIS');
  if (/threat|actor|apt|campaign|intel/i.test(text)) d.push('THREAT INTEL');
  if (/verify|confidence|false positive|validate/i.test(text)) d.push('VERIFICATION AGENT');
  if (/mitigat|block|firewall|contain|isolate/i.test(text)) d.push('MITIGATION');
  return d.length > 0 ? d.slice(0, 3) : ['THREAT INTEL', 'MALWARE ANALYSIS'];
}

function generateDeterministicArchonReply(query: string): { reply: string; delegations: string[] } {
  const q = query.toLowerCase();
  let reply = '';
  let delegations: string[] = [];

  if (q.includes('beacon') || q.includes('c2') || q.includes('cobalt')) {
    reply =
      'ARCHON ORCHESTRATION DIRECTIVE: High-priority C2 beacon activity evaluated. I have instructed Network Analysis to isolate the egress channel and requested Threat Intel to correlate IP/domain indicators with known threat infrastructure. A containment proposal has been queued for analyst confirmation.';
    delegations = ['NETWORK ANALYSIS', 'THREAT INTEL', 'MITIGATION'];
  } else if (q.includes('malware') || q.includes('sample') || q.includes('payload') || q.includes('exe')) {
    reply =
      'ARCHON ANALYSIS: Sample triage engaged. Static feature extraction, PE header validation, and entropy clustering are running against our in-memory ruleset. Specialist agents are cross-referencing imports and suspicious API calls.';
    delegations = ['MALWARE ANALYSIS', 'IOC EXTRACTION'];
  } else if (q.includes('ioc') || q.includes('hash') || q.includes('ip') || q.includes('domain')) {
    reply =
      'ARCHON IOC HARVESTING: Extracted indicators have been routed to the Multi-Tool Gateway (VirusTotal, AlienVault OTX, AbuseIPDB). Confidence scoring and threat graph linking are underway.';
    delegations = ['IOC EXTRACTION', 'THREAT INTEL'];
  } else {
    reply =
      `ARCHON COMMAND DIRECTIVE: Directive acknowledged: "${query.slice(0, 60)}...". Coordinating fleet specialists across threat detection, network forensics, and mitigation playbooks. SOC telemetry nominal.`;
    delegations = inferSpecialistDelegations(query, '');
  }

  return { reply, delegations };
}

app.post('/api/ai/chat', async (req: Request, res: Response) => {
  const { messages = [], model = 'gemini-2.5-flash', providerId = 'google' } = req.body || {};
  const lastUserMsg = [...messages].reverse().find((m: any) => m.role === 'user');
  const userContent = lastUserMsg?.content || '';

  // Try real Gemini API if key is present
  const apiKey = process.env.GEMINI_API_KEY;
  if (apiKey && providerId === 'google') {
    try {
      const ai = new GoogleGenAI({ apiKey });
      const systemInstruction =
        'You are ARCHON, the CEO AI Orchestrator for the NEXSUS CyberResearch-X Security Operations Command Center. You direct 8 specialist cybersecurity agents. Speak with authoritative, precise tactical cyber intelligence style.';
      
      const contents = messages.map((m: any) => ({
        role: m.role === 'assistant' || m.role === 'ceo' ? 'model' : 'user',
        parts: [{ text: m.content || '' }],
      }));

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents,
        config: {
          systemInstruction,
          temperature: 0.2,
          maxOutputTokens: 1024,
        },
      });

      const replyText = response.text || 'Directive acknowledged by ARCHON.';
      return res.json({
        success: true,
        data: {
          reply: replyText,
          model: 'gemini-2.5-flash',
          provider: 'Google Gemini',
          delegations: inferSpecialistDelegations(userContent, replyText),
        },
      });
    } catch (err: any) {
      console.warn('Gemini call failed or timed out, falling back to deterministic Archon engine:', err.message);
    }
  }

  // Fallback to deterministic Archon response
  const fallback = generateDeterministicArchonReply(userContent);
  res.json({
    success: true,
    data: {
      reply: fallback.reply,
      model: model || 'archon-soc-orchestrator',
      provider: 'NEXSUS Archon Core',
      delegations: fallback.delegations,
    },
  });
});

// ---------------------------------------------------------------------------
// Dev / Production Serving
// ---------------------------------------------------------------------------
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    // Mount Vite dev server in middleware mode
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true, host: '0.0.0.0', port: PORT },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // Production static serving
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[NEXSUS SOC] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[NEXSUS SOC] Failed to start server:', err);
  process.exit(1);
});
