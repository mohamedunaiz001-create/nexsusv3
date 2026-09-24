import { SpecialistAgent, EvidenceArtifact, AgentFinding, EvidenceFinding, MalwareVerdict } from '../types';
import { extractIOCs, summarizeIOCsByType } from './iocExtraction';
import { analyzeCode } from './codeAnalysis';
import { applyCustomRules } from './customRules';
import { secureFetchWithRecovery } from './apiClient';
import { buildArtifactEvidenceProfile, evidenceContext } from './artifactEvidence';

/**
 * Fixed investigative sequence every uploaded artifact travels through.
 * Detection specialists run first, context/QA/synthesis specialists run
 * last — mirrors a real SOC triage → correlation → reporting workflow.
 */
export const ANALYSIS_PIPELINE_ORDER = [
  'malware-analysis',
  'ioc-extraction',
  'network-analysis',
  'threat-intel',
  'code-review',
  'memory-agent',
  'verification-agent',
  'report-generator',
];

/** Agents whose findings carry a numeric threat score that feeds the aggregate. */
const SCORING_AGENTS = new Set([
  'malware-analysis',
  'ioc-extraction',
  'network-analysis',
  'threat-intel',
  'code-review',
]);

/**
 * Builds the full ordered roster that will work a given artifact: the
 * assigned/auto-matched agent first (if any), then the rest of the fixed
 * pipeline order, then any remaining roster members not already covered.
 */
export function buildPipelineOrder(
  agents: SpecialistAgent[],
  primaryAgentName?: string,
): SpecialistAgent[] {
  const byId = new Map(agents.map((a) => [a.id, a]));
  const ordered: SpecialistAgent[] = [];

  const primary = primaryAgentName
    ? agents.find((a) => a.name.toLowerCase() === primaryAgentName.toLowerCase())
    : undefined;
  if (primary) ordered.push(primary);

  ANALYSIS_PIPELINE_ORDER.forEach((id) => {
    const a = byId.get(id);
    if (a && !ordered.some((o) => o.id === a.id)) ordered.push(a);
  });

  // Future-proofing: include anyone in the live roster not covered above.
  agents.forEach((a) => {
    if (!ordered.some((o) => o.id === a.id)) ordered.push(a);
  });

  return ordered;
}

export function initializeAgentFindings(pipeline: SpecialistAgent[]): AgentFinding[] {
  return pipeline.map((a, idx) => ({
    agentId: a.id,
    agentName: a.name,
    status: idx === 0 ? 'analyzing' : 'pending',
    stepProgress: idx === 0 ? 5 : 0,
  }));
}

interface FindingContent {
  verdict: AgentFinding['verdict'];
  maliciousScore?: number;
  summary: string;
  findings?: EvidenceFinding[];
  evidenceGaps?: string[];
  evidenceCoverage?: number;
  evidenceQuality?: AgentFinding['evidenceQuality'];
}

function investigationRelationships(artifact: EvidenceArtifact, iocs = extractIOCs({
  fileName: artifact.name,
  previewContent: artifact.analysisContent || artifact.previewContent,
})): string[] {
  const profile = buildArtifactEvidenceProfile(artifact);
  const relationships: string[] = [];
  const hasUrlOrDomain = iocs.some((ioc) => ioc.type === 'url' || ioc.type === 'domain');
  const hasPayload = iocs.some((ioc) => ioc.type === 'file_path' || /\.exe\b|\.dll\b|payload|dropper/i.test(ioc.value));
  if (hasUrlOrDomain && profile.hasDownloadPrimitive) {
    relationships.push('Download-capable command/API is associated with an extracted URL or domain.');
  }
  if (hasUrlOrDomain && hasPayload) {
    relationships.push('Network destination is associated with an extracted payload filename or file path.');
  }
  if (profile.hasExecutionPrimitive && profile.hasDownloadPrimitive) {
    relationships.push('Execution primitive and download primitive form a static download-to-execution chain.');
  }
  if (profile.hasPersistencePrimitive) {
    relationships.push('Persistence-related artifact is present, but no confirmed persistence event is available.');
  }
  return relationships;
}

const MALWARE_INTEL_VERDICT_MAP: Record<MalwareVerdict, AgentFinding['verdict']> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  clean: 'Safe',
  unknown: 'Insufficient Evidence',
};

// ---------------------------------------------------------------------------
// malware-analysis — real result from the Malware Intelligence Engine
// (static feature extraction -> rules -> similarity -> trained classifier ->
// fused verdict; see server/malware_intel and malwareIntelClient.ts) when
// the artifact was actually run through it. No engine result -> no
// invented sandbox/detonation narrative; the step honestly reports that
// nothing ran.
// ---------------------------------------------------------------------------
function findingFromMalwareIntel(artifact: EvidenceArtifact): FindingContent {
  const sample = artifact.malwareIntelSample;
  if (!sample || !sample.verdict) {
    const profile = buildArtifactEvidenceProfile(artifact);
    const text = artifact.analysisContent || artifact.previewContent;
    if (text) {
      const iocs = extractIOCs({ fileName: artifact.name, previewContent: text });
      const behavioralIndicators = [
        profile.hasExecutionPrimitive && 'execution primitive',
        profile.hasDownloadPrimitive && 'download primitive',
        profile.hasPersistencePrimitive && 'persistence primitive',
        profile.hasNetworkPrimitive && 'network primitive',
      ].filter((value): value is string => !!value);
      const findings: EvidenceFinding[] = [
        {
          claim: 'Textual artifact content was statically analyzed',
          evidence: `${profile.lineCount} line(s), ${iocs.length} extracted IOC(s), and ${behavioralIndicators.length} behavioral indicator category(ies).`,
          source: 'static.textual_analysis',
          confidence: 0.75,
          evidenceType: 'MEDIUM',
          limitation: 'The document is evidence about described or embedded behavior, not proof that the artifact executed.',
        },
      ];
      behavioralIndicators.forEach((indicator) => findings.push({
        claim: `Text contains a ${indicator}`,
        evidence: evidenceContext(profile),
        source: `static.textual_analysis.${indicator.replace(/ /g, '_')}`,
        confidence: profile.networkChain || profile.executionChain ? 0.7 : 0.45,
        evidenceType: 'MEDIUM',
        limitation: 'Static text and keyword context do not establish a runtime event.',
      }));
      if (profile.attackTechniques.length) findings.push({
        claim: 'ATT&CK techniques indicated by static content',
        evidence: profile.attackTechniques.join(', '),
        source: 'static.attack_mapping',
        confidence: 0.65,
        evidenceType: 'INFERRED',
        limitation: 'Technique mapping is based on static primitives and does not confirm execution.',
      });
      return {
        verdict: behavioralIndicators.length || iocs.length ? 'Suspicious' : 'Insufficient Evidence',
        maliciousScore: behavioralIndicators.length ? Math.min(70, behavioralIndicators.length * 12 + (profile.networkChain ? 20 : 0)) : undefined,
        summary: `Textual malware analysis completed for ${artifact.type} content: ${behavioralIndicators.length} behavioral indicator categor(ies) and ${iocs.length} IOC(s) identified. Binary analysis is not applicable to this artifact.`,
        findings,
        evidenceGaps: ['Dynamic execution, memory artifacts, and confirmed file/network/persistence events are unavailable.'],
      };
    }
    return {
      verdict: 'Insufficient Evidence',
      summary: `"${artifact.name}" was not run through the Malware Intelligence Engine (static feature extraction, detection rules, similarity search, and the trained classifier), so no static-analysis verdict is available for this artifact.`,
      evidenceGaps: [
        'This artifact type (image/link/pcap) is not currently routed through the static-analysis engine, or the engine was unreachable at upload time.',
      ],
    };
  }

  const detail = sample.verdictDetail;
  const findings: EvidenceFinding[] = [];

  if (detail?.observedCharacteristics?.length) {
    detail.observedCharacteristics.forEach((c) => {
      findings.push({ claim: c, evidence: c, source: 'static.observed_characteristics', confidence: 0.8, evidenceType: 'MEDIUM', limitation: 'Static feature evidence does not establish runtime behavior.' });
    });
  }
  if (detail?.ruleMatches?.length) {
    detail.ruleMatches.forEach((m) => {
      findings.push({
        claim: `Detection rule matched: ${m.ruleName}`,
        evidence: m.detail,
        source: `rules.${m.kind}`,
        confidence: m.severity === 'critical' ? 0.98 : m.severity === 'high' ? 0.9 : m.severity === 'medium' ? 0.7 : 0.5,
        evidenceType: m.severity === 'critical' || m.severity === 'high' ? 'HIGH' : 'MEDIUM',
      });
    });
  }
  if (detail?.similarSamples?.length) {
    const top = detail.similarSamples[0];
    if (top.score >= 60) {
      findings.push({
        claim: `Structurally similar to a previously catalogued sample`,
        evidence: `"${top.name}"${top.family ? ` (family: ${top.family})` : ''} — ${top.score}% vector similarity`,
        source: 'similarity.cosine',
        confidence: Math.min(0.95, top.score / 100),
        evidenceType: 'INFERRED',
        limitation: 'Similarity supports triage but does not prove shared origin or maliciousness.',
      });
    }
  }
  if (detail?.modelVersion && detail.modelConfidence != null) {
    findings.push({
      claim: `Trained classifier scored this sample`,
      evidence: `Model ${detail.modelVersion}: ${detail.modelConfidence}% malicious probability`,
      source: 'classifier.logistic_regression',
      confidence: detail.modelConfidence / 100,
      evidenceType: 'INFERRED',
      limitation: 'Classifier output is probabilistic and should not be treated as direct behavioral evidence.',
    });
  }
  findings.push({
    claim: 'Evidence-fusion components recorded separately',
    evidence: `Static: ${detail?.staticConfidence ?? 'n/a'}%; rules: ${detail?.ruleConfidence ?? 'n/a'}%; similarity: ${detail?.similarityConfidence ?? 'n/a'}%.`,
    source: 'verdict.evidence_fusion',
    confidence: Math.min(0.95, (sample.confidence ?? 0) / 100),
    evidenceType: 'INFERRED',
    limitation: 'The fused score is a triage confidence, not a measurement of execution or authorship.',
  });
  if (sample.features?.peSuspiciousImportedApis?.length) {
    findings.push({
      claim: 'Confirmed suspicious API import(s) via real PE Import Address Table',
      evidence: sample.features.peSuspiciousImportedApis.slice(0, 6).join(', '),
      source: 'static.pe.import_table',
      confidence: 0.9,
      evidenceType: 'HIGH',
      limitation: 'An imported API indicates capability, not that the API was executed.',
    });
  }

  const summary = findings.length
    ? `[Malware Intelligence Engine] ${detail?.observedCharacteristics?.[0] || 'Static analysis complete.'} ${sample.family ? `Structurally consistent with the "${sample.family}" family.` : ''}`.trim()
    : `[Malware Intelligence Engine] Static analysis complete on ${sample.fileFormat.toUpperCase()} sample (SHA-256 ${sample.sha256.slice(0, 12)}…) — no high-signal indicators observed.`;

  return {
    verdict: MALWARE_INTEL_VERDICT_MAP[sample.verdict],
    maliciousScore: sample.verdict === 'unknown' ? undefined : Math.round(sample.confidence ?? 0),
    summary,
    findings,
    evidenceGaps: [
      'This verdict is static-analysis only — no dynamic/behavioral sandbox telemetry is available (NEXSUS does not currently execute uploaded samples).',
    ],
  };
}

// ---------------------------------------------------------------------------
// ioc-extraction — runs the real regex-detector engine (iocExtraction.ts)
// against the artifact's actual filename, preview content, and (when
// available) the printable strings the static-analysis engine already
// found. A zero-indicator result is reported as exactly that, not padded
// with a plausible-looking random count.
// ---------------------------------------------------------------------------
function findingFromIOCExtraction(artifact: EvidenceArtifact): FindingContent {
  const profile = buildArtifactEvidenceProfile(artifact);
  const sample = artifact.malwareIntelSample;
  const analysisText = artifact.analysisContent || artifact.previewContent;
  const iocs = extractIOCs({
    fileName: artifact.name,
    previewContent: analysisText,
    staticStrings: sample?.features
      ? {
          suspicious: sample.features.suspiciousStrings,
          network: sample.features.networkIndicatorStrings,
          persistence: sample.features.persistenceIndicatorStrings,
        }
      : undefined,
  });

  if (iocs.length === 0) {
    const customMatches = applyCustomRules('ioc-extraction', [artifact.name, analysisText].filter(Boolean).join('\n'));
    return {
      verdict: customMatches.matchedCount ? 'Suspicious' : 'Safe',
      maliciousScore: Math.round(customMatches.confidence * 30),
      summary: `Scanned filename${artifact.analysisContent || artifact.previewContent ? ', full artifact content,' : ''}${sample ? ' and static-analysis string output' : ''} — no hashes, IPs, domains, URLs, CVEs, or ATT&CK technique IDs found.${customMatches.matchedCount ? ` ${customMatches.matchedCount} custom rule(s) matched.` : ''}`,
      findings: customMatches.findings,
    };
  }

  const counts = summarizeIOCsByType(iocs);
  const typeSummary = Object.entries(counts).map(([t, n]) => `${n} ${t}`).join(', ');
  const networkTypeIOCs = iocs.filter((i) => ['url', 'domain', 'ipv4', 'ipv6', 'email'].includes(i.type));
  const highSignalIOCs = iocs.filter((i) => ['sha256', 'sha1', 'md5', 'cve', 'attack_technique', 'registry_path'].includes(i.type));

  const findings: EvidenceFinding[] = iocs.map((ioc) => ({
    claim: `${ioc.type.toUpperCase()} indicator extracted`,
    evidence: `${ioc.value}${ioc.normalizedValue && ioc.normalizedValue !== ioc.value ? ` (normalized: ${ioc.normalizedValue})` : ''} (found in ${ioc.source})`,
    source: `ioc_extraction.${ioc.type}`,
    confidence: ioc.confidence,
    evidenceType: ioc.type === 'url' || ioc.type === 'domain' || ioc.type === 'ipv4' ? 'HIGH' : 'MEDIUM',
    context: ioc.context || (profile.text ? evidenceContext(profile) : 'indicator found in artifact metadata'),
    limitation: 'Extraction identifies an indicator shape; it does not establish malicious reputation or observed activity.',
  }));
  const relationships = investigationRelationships(artifact, iocs);
  if (relationships.length) {
    findings.push({
      claim: 'Related indicators form an investigation chain',
      evidence: relationships.join(' '),
      source: 'correlation.static_relationships',
      confidence: 0.75,
      evidenceType: 'MEDIUM',
      limitation: 'Relationships are derived from co-occurrence and static context; they do not prove execution or communication.',
    });
  }

  // Custom analyst-added rules — checked against the same filename/preview
  // text this agent already scans, plus every extracted indicator value
  // (catches watchlisted domains/hashes even if the built-in detectors
  // classified them under a different type than the rule author expected).
  const customBlob = [artifact.name, artifact.analysisContent || artifact.previewContent, ...iocs.map((i) => i.value)].filter(Boolean).join('\n');
  const customMatches = applyCustomRules('ioc-extraction', customBlob);
  findings.push(...customMatches.findings);

  const relationshipBonus = profile.networkChain || profile.executionChain ? 18 : 0;
  const score = Math.min(100, networkTypeIOCs.length * 8 + highSignalIOCs.length * 6 + relationshipBonus + customMatches.confidence * 30);
  const verdict: AgentFinding['verdict'] = score >= 40 ? 'Suspicious' : 'Safe';

  return {
    verdict,
    maliciousScore: score,
    summary: `Extracted ${iocs.length} indicator(s): ${typeSummary}.${customMatches.matchedCount ? ` ${customMatches.matchedCount} custom rule(s) matched.` : ''} ${networkTypeIOCs.length ? 'Network-reachable indicators present — recommend cross-referencing against threat-intel feeds.' : 'No network-reachable indicators found.'}${profile.networkChain ? ' Correlated network and execution/download behavior increases signal.' : ''}`,
    findings,
    evidenceCoverage: Math.round(Math.min(1, iocs.length / Math.max(1, counts ? Object.keys(counts).length : 1)) * 100),
    evidenceQuality: relationships.length ? 'MEDIUM' : 'LOW',
    evidenceGaps: networkTypeIOCs.length
      ? ['Extracted indicators have not been checked against reputation/threat-intel feeds — see the Threat Intelligence step for connector status.']
      : undefined,
  };
}

// ---------------------------------------------------------------------------
// network-analysis — honest about what NEXSUS can actually see: there is
// no PCAP-decoding engine wired up yet, so a .pcap artifact is reported as
// not decoded rather than fabricating beaconing/JA3 findings. For file/code
// artifacts that went through static analysis, real embedded
// network-indicator strings (if any) are surfaced as static evidence only.
// ---------------------------------------------------------------------------
function findingFromNetworkAnalysis(artifact: EvidenceArtifact): FindingContent {
  if (artifact.type === 'pcap') {
    const capture = artifact.pcapAnalysis;
    if (capture) {
      const protocolSummary = Object.entries(capture.protocols).map(([protocol, count]) => `${count} ${protocol}`).join(', ') || 'no decoded network-layer protocols';
      const endpointSummary = Object.entries(capture.endpoints).slice(0, 6).map(([endpoint, count]) => `${endpoint} (${count})`).join(', ');
      const applicationSummary = [
        ...Object.keys(capture.dnsQueries).map((name) => `DNS ${name}`),
        ...Object.keys(capture.httpHosts).map((host) => `HTTP ${host}`),
        ...Object.keys(capture.tlsSni).map((name) => `TLS SNI ${name}`),
      ].slice(0, 8);
      const findings: EvidenceFinding[] = [
        {
          claim: 'PCAP packet metadata decoded',
          evidence: `${capture.packetCount} packet(s); protocols: ${protocolSummary}.`,
          source: 'pcap.decoder.metadata',
          confidence: 0.95,
          evidenceType: 'DIRECT',
          limitation: 'Metadata decoding does not reconstruct application payloads or prove malicious intent.',
        },
      ];
      if (endpointSummary) findings.push({ claim: 'Network endpoints observed in capture', evidence: endpointSummary, source: 'pcap.decoder.endpoints', confidence: 0.9, evidenceType: 'DIRECT' });
      if (applicationSummary.length) findings.push({ claim: 'Application-layer metadata observed in capture', evidence: applicationSummary.join(', '), source: 'pcap.decoder.application_metadata', confidence: 0.85, evidenceType: 'DIRECT', limitation: 'Metadata is parsed without decrypting TLS or executing payloads.' });
      return {
        verdict: 'Informational',
        summary: `Decoded ${capture.packetCount} packet(s) from "${artifact.name}" with ${protocolSummary}.${capture.truncatedCount ? ` ${capture.truncatedCount} packet record(s) were truncated.` : ''}`,
        findings,
        evidenceGaps: ['Payload-level DNS/HTTP/TLS parsing, JA3, and behavioral detection are not enabled in the metadata decoder.'],
      };
    }
    return {
      verdict: 'Insufficient Evidence',
      summary: `"${artifact.name}" is a packet capture, but no PCAP-decoding engine is connected — DNS/HTTP/TLS layers were not parsed and no traffic-level findings could be produced.`,
      evidenceGaps: ['Connect a PCAP/traffic-analysis engine to decode this capture and enable real beaconing/JA3/DNS-tunneling detection.'],
    };
  }

  const sample = artifact.malwareIntelSample;
  const profile = buildArtifactEvidenceProfile(artifact);
  const netStrings = sample?.features?.networkIndicatorStrings || [];
  const extractedIOCs = extractIOCs({
    fileName: artifact.name,
    previewContent: artifact.analysisContent || artifact.previewContent,
    staticStrings: sample?.features
      ? { suspicious: sample.features.suspiciousStrings, network: netStrings, persistence: sample.features.persistenceIndicatorStrings }
      : undefined,
  });
  const networkIOCs = extractedIOCs.filter((ioc) => ['url', 'domain', 'ipv4', 'ipv6'].includes(ioc.type));
  const customBlob = [artifact.previewContent, ...netStrings, ...networkIOCs.map((ioc) => ioc.value)].filter(Boolean).join('\n');
  const customMatches = applyCustomRules('network-analysis', customBlob);

  if (netStrings.length > 0 || networkIOCs.length > 0 || profile.hasNetworkPrimitive) {
    const findings: EvidenceFinding[] = [
      ...networkIOCs.map((ioc) => ({
        claim: `${ioc.type.toUpperCase()} network artifact identified`,
        evidence: `${ioc.value}${ioc.normalizedValue ? ` (normalized: ${ioc.normalizedValue})` : ''} (found in ${ioc.source})`,
        source: `ioc_extraction.${ioc.type}`,
        confidence: ioc.confidence,
        evidenceType: 'HIGH' as const,
        context: ioc.context || evidenceContext(profile),
        limitation: 'Static extraction identifies a network artifact; it does not establish that a connection occurred.',
      })),
      ...netStrings.slice(0, 8).map((s) => ({
      claim: 'Network-related string reference found in static scan',
      evidence: s,
      source: 'static.network_indicator_strings',
      confidence: profile.networkChain ? 0.7 : 0.25,
      evidenceType: profile.networkChain ? ('MEDIUM' as const) : ('LOW' as const),
      context: evidenceContext(profile),
      limitation: 'Static text or import evidence does not prove that a connection occurred.',
      })),
    ];
    findings.push(...customMatches.findings);
    const relationships = investigationRelationships(artifact, extractedIOCs);
    if (relationships.length) findings.push({ claim: 'Static network relationship identified', evidence: relationships.join(' '), source: 'correlation.network_relationships', confidence: 0.75, evidenceType: 'MEDIUM', limitation: 'Static correlation does not establish observed traffic.' });
    const baseScore = profile.networkChain ? 25 + Math.min(35, (netStrings.length + networkIOCs.length) * 5) : networkIOCs.length ? Math.min(25, networkIOCs.length * 8) : 0;
    const score = Math.min(100, baseScore + customMatches.confidence * 30);
    return {
      verdict: score >= 30 ? 'Suspicious' : 'Informational',
      maliciousScore: score > 0 ? score : undefined,
      summary: `Identified ${networkIOCs.length} URL/domain/IP artifact(s), ${netStrings.length} network-related static string reference(s), and ${profile.hasNetworkPrimitive ? 'a network-capable command or API' : 'no explicit network-capable command or API'}. ${profile.networkChain ? 'The artifacts form a download/execution-oriented static chain.' : 'The evidence is static and is not treated as an observed connection.'}${customMatches.matchedCount ? ` ${customMatches.matchedCount} custom rule(s) matched.` : ''} No live traffic was captured or analyzed.`,
      findings,
      evidenceCoverage: Math.round((networkIOCs.length > 0 ? 0.6 : 0.3) * 100),
      evidenceQuality: profile.networkChain ? 'MEDIUM' : 'LOW',
      evidenceGaps: ['No dynamic/sandbox network telemetry available — these are embedded strings only, not observed connections.'],
    };
  }

  if (customMatches.matchedCount > 0) {
    return {
      verdict: 'Suspicious',
      maliciousScore: Math.round(customMatches.confidence * 30),
      summary: `No network-related strings from the built-in scan, but ${customMatches.matchedCount} custom rule(s) matched against available content.`,
      findings: customMatches.findings,
      evidenceGaps: ['No dynamic/sandbox network telemetry available — these are custom pattern matches only, not observed connections.'],
    };
  }

  if (artifact.type === 'file' || artifact.type === 'code') {
    return {
      verdict: 'Informational',
      summary: sample
        ? 'Static scan found no network-related strings (URLs, socket APIs, DNS calls) embedded in this sample.'
        : 'No network capture or static-analysis result available for this artifact — nothing to inspect at the traffic layer.',
    };
  }

  return {
    verdict: 'Not Applicable',
    summary: `No embedded network capture or network-related content applies to this ${artifact.type} artifact.`,
  };
}

// ---------------------------------------------------------------------------
// threat-intel — NEXSUS has a real tool gateway (server/tools) with
// VirusTotal / OTX / AbuseIPDB / Shodan adapters, but it requires an admin
// to connect credentials under Tools → Connectors, and querying it is an
// async per-indicator lookup outside this synchronous pipeline tick. Rather
// than pretend a cross-reference happened, this step reports plainly that
// no live lookup ran, and separately (and distinctly) surfaces the
// internal rule-engine family attribution, which is NOT external threat
// intel and is labeled as such.
// ---------------------------------------------------------------------------
function findingFromThreatIntelFallback(artifact: EvidenceArtifact): FindingContent {
  const sample = artifact.malwareIntelSample;
  const findings: EvidenceFinding[] = [];

  if (sample?.family) {
    findings.push({
      claim: `Internal rule engine attributes this sample to a known family`,
      evidence: `"${sample.family}" — from NEXSUS's own rule/similarity matching, not an external feed`,
      source: 'internal.rules_and_similarity',
      confidence: 0.5,
    });
  }

  // Analyst-maintained watchlist terms (threat-actor names, campaign
  // aliases, known-bad domains not yet in an external feed) — a real
  // local signal distinct from, and clearly labeled apart from, an
  // external connector lookup.
  const customBlob = [artifact.name, artifact.analysisContent || artifact.previewContent, sample?.family].filter(Boolean).join('\n');
  const customMatches = applyCustomRules('threat-intel', customBlob);
  findings.push(...customMatches.findings);

  return {
    verdict: customMatches.matchedCount ? 'Suspicious' : 'Insufficient Evidence',
    maliciousScore: customMatches.matchedCount ? Math.round(customMatches.confidence * 100) : undefined,
    summary: `No live threat-intelligence connector (VirusTotal, OTX, AbuseIPDB, Shodan) executed a lookup for this artifact's indicators — no external cross-reference has been performed.${customMatches.matchedCount ? ` ${customMatches.matchedCount} analyst watchlist rule(s) matched locally.` : ''}`,
    findings: findings.length ? findings : undefined,
    evidenceGaps: ['Connect and enable a threat-intel provider under Tools → Connectors, then re-run this step to query real external feeds for the IOCs extracted above.'],
  };
}

const TOOL_ACTION_BY_IOC_TYPE: Partial<Record<string, string>> = {
  sha256: 'hash.lookup',
  sha1: 'hash.lookup',
  md5: 'hash.lookup',
  ipv4: 'ip.lookup',
  ipv6: 'ip.lookup',
  domain: 'domain.lookup',
  url: 'url.lookup',
};

export function getThreatIntelCandidates(artifact: EvidenceArtifact) {
  const sample = artifact.malwareIntelSample;
  const analysisText = artifact.analysisContent || artifact.previewContent;
  return extractIOCs({
    fileName: artifact.name,
    previewContent: analysisText,
    staticStrings: sample?.features
      ? { suspicious: sample.features.suspiciousStrings, network: sample.features.networkIndicatorStrings, persistence: sample.features.persistenceIndicatorStrings }
      : undefined,
  });
}

/** Query enabled connectors for already-extracted IOCs, keeping failures local. */
export async function fetchThreatIntelFinding(artifact: EvidenceArtifact): Promise<FindingContent> {
  const fallback = findingFromThreatIntelFallback(artifact);
  const iocs = getThreatIntelCandidates(artifact);

  if (iocs.length === 0) return fallback;

  const results = await Promise.all(iocs.map(async (ioc) => {
    const action = TOOL_ACTION_BY_IOC_TYPE[ioc.type];
    if (!action) return { ioc, status: 'unsupported' as const };
    try {
      const response = await secureFetchWithRecovery('/api/tools/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, indicatorValue: ioc.value, requestedByAgent: 'threat-intel' }),
      });
      const body = await response.json().catch(() => null);
      if (!response.ok || !body?.result) return { ioc, status: 'failed' as const };
      return { ioc, status: 'success' as const, result: body.result };
    } catch {
      return { ioc, status: 'failed' as const };
    }
  }));

  const successful = results.filter((entry): entry is { ioc: typeof iocs[number]; status: 'success'; result: any } => entry.status === 'success');
  const unsupported = results.filter((entry) => entry.status === 'unsupported');
  const failed = results.filter((entry) => entry.status === 'failed');

  const findings: EvidenceFinding[] = [...(fallback.findings || [])];
  successful.forEach(({ ioc, result }) => {
    const tool = String(result.tool || 'external connector');
    const verdict = String(result.verdict || 'unknown');
    findings.push({
      claim: `${tool} reputation result for ${ioc.type.toUpperCase()}`,
      evidence: `${ioc.value}: ${verdict} (${Number(result.confidence || 0)}% confidence)${result.findings?.[0]?.detail ? ` — ${result.findings[0].detail}` : ''}`,
      source: `external.${tool}.${String(result.action || TOOL_ACTION_BY_IOC_TYPE[ioc.type])}`,
      confidence: Math.min(1, Math.max(0, Number(result.confidence || 0) / 100)),
      evidenceType: 'DIRECT',
      limitation: 'External reputation describes the indicator, not necessarily this artifact or an observed connection.',
    });
  });
  unsupported.forEach(({ ioc }) => {
    findings.push({
      claim: `Threat-intel enrichment not applicable for ${ioc.type.toUpperCase()}`,
      evidence: `${ioc.value}: no registered connector action supports this indicator type.`,
      source: `external.unavailable.${ioc.type}`,
      confidence: ioc.confidence,
      evidenceType: 'DIRECT',
      limitation: 'The indicator was discovered and validated, but no enabled provider can query this type.',
    });
  });
  failed.forEach(({ ioc }) => {
    findings.push({
      claim: `Threat-intel lookup failed for ${ioc.type.toUpperCase()}`,
      evidence: `${ioc.value}: a compatible lookup was attempted but did not return a result.`,
      source: `external.failed.${ioc.type}`,
      confidence: 1,
      evidenceType: 'DIRECT',
      limitation: 'Provider or network failure prevents an external reputation conclusion.',
    });
  });

  const malicious = successful.filter(({ result }) => String(result.verdict).toLowerCase() === 'malicious');
  const suspicious = successful.filter(({ result }) => String(result.verdict).toLowerCase() === 'suspicious');
  const scores = successful.map(({ result }) => Number(result.confidence || 0)).filter((score) => Number.isFinite(score));
  const score = scores.length ? Math.round(scores.reduce((sum, value) => sum + value, 0) / scores.length) : 0;
  const verdict: FindingContent['verdict'] = malicious.length > 0 ? 'Malicious' : suspicious.length > 0 ? 'Suspicious' : successful.length === 0 ? 'Insufficient Evidence' : score >= 30 ? 'Suspicious' : 'Informational';
  const uncovered = unsupported.length + failed.length;

  return {
    verdict,
    maliciousScore: score,
    summary: `External threat intelligence evaluated all ${iocs.length} extracted indicator(s): ${successful.length} lookup(s) completed, ${unsupported.length} unsupported/not applicable, and ${failed.length} lookup(s) failed. Completed lookups: ${malicious.length} malicious, ${suspicious.length} suspicious, ${successful.length - malicious.length - suspicious.length} with no malicious verdict. Internal family attribution remains separate from these external results.`,
    findings,
    evidenceGaps: uncovered ? [`${unsupported.length} indicator(s) were not applicable to an available connector and ${failed.length} compatible lookup(s) failed; their external reputation remains unknown.`] : undefined,
  };
}

// ---------------------------------------------------------------------------
// code-review — real static heuristics (codeAnalysis.ts) over actual
// source/script text when present.
// ---------------------------------------------------------------------------
function findingFromCodeReview(artifact: EvidenceArtifact): FindingContent {
  const sourceText = artifact.analysisContent || artifact.previewContent;
  const profile = buildArtifactEvidenceProfile(artifact);
  const hasCodeLikeContent = !!sourceText && (artifact.type === 'code' || profile.hasExecutableContext || profile.hasDownloadPrimitive || profile.hasEncodedContent);
  const hasSource = !!sourceText && hasCodeLikeContent;
  if (!hasSource) {
    return {
      verdict: 'Not Applicable',
      summary: sourceText ? 'Artifact content was scanned and classified as plain text without detectable code-like commands or execution primitives; static code review is not applicable.' : 'No embedded script or source text is present in this artifact for static code review.',
    };
  }
  const result = analyzeCode(sourceText as string);
  const customMatches = applyCustomRules('code-review', sourceText as string);
  const findings = [...result.findings, ...customMatches.findings];
  const score = Math.min(100, result.maliciousScore + customMatches.confidence * 30);
  const verdict: FindingContent['verdict'] = score >= 55 ? 'Malicious' : score >= 20 ? 'Suspicious' : findings.length ? result.verdict : 'Safe';

  return {
    verdict,
    maliciousScore: score,
    summary: `${artifact.type === 'code' ? 'Executable/source artifact' : 'Plain-text artifact containing code-like content'}: static review performed. ${result.summary}${customMatches.matchedCount ? ` ${customMatches.matchedCount} custom rule(s) matched.` : ''}`,
    findings,
    evidenceCoverage: 100,
    evidenceQuality: 'HIGH',
    evidenceGaps: ['Static review identifies commands and capabilities but does not establish that the command executed.'],
  };
}

// ---------------------------------------------------------------------------
// memory-agent — real similarity-search results from the Malware
// Intelligence Engine's corpus when available, rather than a random
// "found N similar cases" line.
// ---------------------------------------------------------------------------
function findingFromMemoryAgent(artifact: EvidenceArtifact): FindingContent {
  const sample = artifact.malwareIntelSample;
  if (!sample) {
    return {
      verdict: 'Insufficient Evidence',
      summary: 'No similarity search was run for this artifact — it was not processed by the Malware Intelligence Engine\'s similarity index.',
    };
  }
  const matches = sample.verdictDetail?.similarSamples || [];
  if (matches.length === 0) {
    return {
      verdict: 'Informational',
      summary: 'No structurally similar historical sample found in the knowledge base — this appears to be a novel artifact by feature-vector similarity.',
    };
  }
  const findings: EvidenceFinding[] = matches.slice(0, 5).map((m) => ({
    claim: 'Structurally similar prior sample found',
    evidence: `"${m.name}"${m.family ? ` (${m.family})` : ''}${m.label ? `, previously labeled ${m.label}` : ''} — ${m.score}% overall similarity${m.structureSimilarity != null ? `; content ${m.contentSimilarity}%, IOC ${m.iocSimilarity}%, network ${m.networkSimilarity}%, behavior ${m.behaviorSimilarity}%, structure ${m.structureSimilarity}%` : ''}`,
    source: 'similarity.cosine',
    confidence: Math.min(0.95, m.score / 100),
    evidenceType: 'INFERRED',
    limitation: 'Vector similarity does not establish shared authorship, identical content, or maliciousness.',
  }));
  const top = matches[0];
  findings.push({
    claim: 'Similarity dimensions require corroboration',
    evidence: `Available comparison is a static feature-vector score (${top.score}%). IOC, network, behavior, and textual-content overlap are not independently measured by this result.`,
    source: 'similarity.vector_scope',
    confidence: 0.95,
    evidenceType: 'DIRECT',
    limitation: 'The current similarity engine does not expose component-level content or IOC overlap.',
  });
  return {
    verdict: 'Informational',
    summary: `Found ${matches.length} structurally similar historical sample(s) in the knowledge base — top match ${matches[0].score}% similar to "${matches[0].name}".`,
    findings,
    evidenceCoverage: 100,
    evidenceQuality: 'LOW',
    evidenceGaps: ['Component-level content, IOC, network, behavior, and structure similarity are not separately available from the current vector index.'],
  };
}

// ---------------------------------------------------------------------------
// verification-agent — actually cross-validates the other specialists'
// completed findings on this artifact (available via artifact.agentFindings,
// which is progressively filled in as earlier pipeline steps complete)
// instead of issuing a canned "no contradictions" line regardless of what
// happened.
// ---------------------------------------------------------------------------
function findingFromVerification(artifact: EvidenceArtifact): FindingContent {
  const priorFindings = (artifact.agentFindings || []).filter(
    (f) => f.status === 'complete' && f.agentId !== 'verification-agent' && f.agentId !== 'report-generator',
  );
  if (priorFindings.length === 0) {
    return { verdict: 'Insufficient Evidence', summary: 'No specialist findings are available yet to cross-validate.' };
  }

  const scored = priorFindings.filter((f) => typeof f.maliciousScore === 'number');
  const insufficient = priorFindings.filter((f) => f.verdict === 'Insufficient Evidence' || f.verdict === 'Not Applicable');
  const verdictSet = new Set(scored.map((f) => f.verdict).filter((v) => v && v !== 'Informational'));

  const findings: EvidenceFinding[] = [];
  const evidenceGaps: string[] = [];
  const directEvidence = priorFindings.flatMap((f) => f.findings || []).filter((f) => f.evidenceType === 'DIRECT' || f.evidenceType === 'HIGH');

  const hasMalicious = verdictSet.has('Malicious');
  const hasSafe = verdictSet.has('Safe');
  if (hasMalicious && hasSafe) {
    findings.push({
      claim: 'Contradictory specialist verdicts detected',
      evidence: `${scored.filter((f) => f.verdict === 'Malicious').map((f) => f.agentName).join(', ')} reported Malicious while ${scored.filter((f) => f.verdict === 'Safe').map((f) => f.agentName).join(', ')} reported Safe.`,
      source: 'verification.cross_check',
      confidence: 0.9,
    });
  } else if (scored.length > 0) {
    findings.push({
      claim: 'Specialist verdicts are consistent',
      evidence: `${scored.length} scoring specialist(s) agree on direction (no Malicious/Safe contradiction).`,
      source: 'verification.cross_check',
      confidence: 0.7,
    });
  }

  const scores = scored.map((f) => f.maliciousScore as number);
  const spread = scores.length > 1 ? Math.max(...scores) - Math.min(...scores) : 0;
  if (spread >= 40) {
    findings.push({
      claim: 'Wide confidence spread across specialists',
      evidence: `Scores range from ${Math.min(...scores)} to ${Math.max(...scores)} across ${scored.length} specialist(s).`,
      source: 'verification.score_spread',
      confidence: 0.7,
    });
    evidenceGaps.push('Specialists disagree materially on confidence; review the strongest supporting and contradicting evidence before acting.');
  }

  if (insufficient.length > 0) {
    evidenceGaps.push(
      `${insufficient.length} of ${priorFindings.length} specialist(s) reported insufficient evidence or that the check didn't apply: ${insufficient.map((f) => f.agentName).join(', ')}.`,
    );
    findings.push({
      claim: 'Evidence coverage is incomplete',
      evidence: `${insufficient.length} specialist(s) could not produce a real finding for this artifact (see individual step summaries).`,
      source: 'verification.coverage',
      confidence: 0.8,
    });
  }

  if (directEvidence.length === 0) {
    evidenceGaps.push('No direct or high-quality evidence was established; current conclusions rely on static, inferred, or unverified signals.');
    findings.push({
      claim: 'No direct/high-quality evidence established',
      evidence: `${priorFindings.length} specialist result(s) were reviewed, but none carried DIRECT or HIGH evidence quality.`,
      source: 'verification.evidence_quality',
      confidence: 0.9,
      evidenceType: 'LOW',
      limitation: 'A numeric coverage percentage is not a confidence score.',
    });
  }

  const coverageRatio = (priorFindings.length - insufficient.length) / priorFindings.length;
  const confidenceLabel = coverageRatio >= 0.8 && !(hasMalicious && hasSafe) ? 'HIGH' : coverageRatio >= 0.4 ? 'MEDIUM' : 'LOW';

  return {
    verdict: 'Informational',
    summary: `Cross-validated ${priorFindings.length} specialist finding(s). Evidence coverage: ${Math.round(coverageRatio * 100)}% (${confidenceLabel} confidence). ${hasMalicious && hasSafe ? 'Contradictions found — see below.' : 'No contradictory conclusions found.'}`,
    findings,
    evidenceGaps: evidenceGaps.length ? evidenceGaps : undefined,
  };
}

// ---------------------------------------------------------------------------
// report-generator — synthesizes the real per-specialist outcomes recorded
// on the artifact rather than a fixed "compiled findings" sentence.
// ---------------------------------------------------------------------------
function findingFromReportGenerator(artifact: EvidenceArtifact): FindingContent {
  const priorFindings = (artifact.agentFindings || []).filter(
    (f) => f.status === 'complete' && f.agentId !== 'report-generator',
  );
  const byVerdict: Record<string, number> = {};
  priorFindings.forEach((f) => {
    const v = f.verdict || 'Informational';
    byVerdict[v] = (byVerdict[v] || 0) + 1;
  });
  const breakdown = Object.entries(byVerdict).map(([v, n]) => `${n} ${v}`).join(', ');
  const evidenceLeads = priorFindings
    .map((finding) => {
      const strongest = [...(finding.findings || [])].sort((a, b) => b.confidence - a.confidence)[0];
      return strongest ? `${finding.agentName}: ${strongest.claim} (${strongest.evidence})` : null;
    })
    .filter((lead): lead is string => !!lead)
    .slice(0, 5);
  const reportFindings = priorFindings
    .flatMap((finding) => (finding.findings || []).map((evidence) => ({ ...evidence, source: `${finding.agentName} / ${evidence.source}` })))
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 10);
  const evidenceGaps = [...new Set(priorFindings.flatMap((finding) => finding.evidenceGaps || []))].slice(0, 8);
  const verifiedCount = reportFindings.filter((finding) => finding.evidenceType === 'DIRECT' || finding.evidenceType === 'HIGH').length;
  const inferredCount = reportFindings.filter((finding) => finding.evidenceType === 'INFERRED' || finding.evidenceType === 'LOW' || finding.evidenceType === 'UNVERIFIED').length;
  if (verifiedCount > 0) {
    reportFindings.push({
      claim: 'Verified or high-quality evidence is present',
      evidence: `${verifiedCount} selected finding(s) are marked DIRECT or HIGH by their owning specialist.`,
      source: 'report.evidence_quality.verified',
      confidence: 0.9,
      evidenceType: 'DIRECT',
      limitation: 'Verified static evidence supports the claim recorded; it does not automatically prove runtime execution.',
    });
  }
  if (inferredCount > 0) {
    reportFindings.push({
      claim: 'Some conclusions remain inferred or weakly supported',
      evidence: `${inferredCount} selected finding(s) are marked INFERRED, LOW, or UNVERIFIED.`,
      source: 'report.evidence_quality.inferred',
      confidence: 0.9,
      evidenceType: 'INFERRED',
      limitation: 'Inference should not be treated as direct observation or external confirmation.',
    });
  }

  return {
    verdict: 'Informational',
    summary: priorFindings.length
      ? `Final report compiled from ${priorFindings.length} specialist step(s): ${breakdown}.${evidenceLeads.length ? ` Highest-confidence evidence: ${evidenceLeads.join(' | ')}` : ' No evidence-backed sub-findings were available.'}`
      : 'No specialist findings were available to compile into a final report.',
    findings: reportFindings.length ? reportFindings : undefined,
    evidenceGaps: evidenceGaps.length ? evidenceGaps : undefined,
  };
}

function contentFor(agentId: string, artifact: EvidenceArtifact): FindingContent {
  switch (agentId) {
    case 'malware-analysis':
      return findingFromMalwareIntel(artifact);
    case 'ioc-extraction':
      return findingFromIOCExtraction(artifact);
    case 'network-analysis':
      return findingFromNetworkAnalysis(artifact);
    case 'threat-intel':
      return findingFromThreatIntelFallback(artifact);
    case 'code-review':
      return findingFromCodeReview(artifact);
    case 'memory-agent':
      return findingFromMemoryAgent(artifact);
    case 'verification-agent':
      return findingFromVerification(artifact);
    case 'report-generator':
      return findingFromReportGenerator(artifact);
    default:
      return { verdict: 'Informational', summary: 'Analysis complete.' };
  }
}

export function generateFinding(agentId: string, artifact: EvidenceArtifact): FindingContent {
  return contentFor(agentId, artifact);
}

export function computeAggregateVerdict(
  findings: AgentFinding[],
): { maliciousScore: number; verdict: 'Malicious' | 'Suspicious' | 'Safe' | 'Unknown' } {
  const scored = findings.filter((f) => typeof f.maliciousScore === 'number');
  if (scored.length === 0) {
    // No specialist produced a real, evidence-backed score — reporting
    // "Safe" here would be indistinguishable from an artifact that was
    // actually checked and found clean. Say plainly that it's unassessed.
    return { maliciousScore: 0, verdict: 'Unknown' };
  }
  const score = Math.round(scored.reduce((sum, f) => sum + (f.maliciousScore || 0), 0) / scored.length);
  const verdict = score >= 65 ? 'Malicious' : score >= 30 ? 'Suspicious' : 'Safe';
  return { maliciousScore: score, verdict };
}

export function computeInvestigationMetrics(findings: AgentFinding[]): {
  evidenceCoverage: number;
  evidenceQuality: 'LOW' | 'MEDIUM' | 'HIGH';
  investigationConfidence: number;
} {
  const completed = findings.filter((finding) => finding.status === 'complete');
  if (completed.length === 0) return { evidenceCoverage: 0, evidenceQuality: 'LOW', investigationConfidence: 0 };

  const coverageValues = completed.map((finding) => finding.evidenceCoverage).filter((value): value is number => typeof value === 'number');
  const evidenceCoverage = coverageValues.length
    ? Math.round(coverageValues.reduce((sum, value) => sum + value, 0) / coverageValues.length)
    : Math.round((completed.filter((finding) => (finding.findings || []).length > 0).length / completed.length) * 100);
  const qualityRank = { LOW: 1, MEDIUM: 2, HIGH: 3 } as const;
  const qualityValues = completed.map((finding) => finding.evidenceQuality).filter((value): value is keyof typeof qualityRank => !!value);
  const averageQuality = qualityValues.length
    ? qualityValues.reduce((sum, value) => sum + qualityRank[value], 0) / qualityValues.length
    : 1;
  const evidenceQuality = averageQuality >= 2.5 ? 'HIGH' : averageQuality >= 1.75 ? 'MEDIUM' : 'LOW';
  const scoredCount = completed.filter((finding) => typeof finding.maliciousScore === 'number').length;
  const investigationConfidence = Math.round(evidenceCoverage * (0.5 + 0.5 * (scoredCount / completed.length)));
  return { evidenceCoverage, evidenceQuality, investigationConfidence };
}
