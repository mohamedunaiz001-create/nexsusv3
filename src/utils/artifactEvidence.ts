import { EvidenceArtifact } from '../types';

export interface ArtifactEvidenceProfile {
  text: string;
  lineCount: number;
  hasExecutableContext: boolean;
  hasNetworkPrimitive: boolean;
  hasExecutionPrimitive: boolean;
  hasDownloadPrimitive: boolean;
  hasEncodedContent: boolean;
  hasPersistencePrimitive: boolean;
  networkChain: boolean;
  executionChain: boolean;
  attackTechniques: string[];
}

const NETWORK_PRIMITIVE_RE = /(?:socket\s*\(|\.connect\s*\(|\b(?:InternetConnect|HttpSendRequest|URLDownloadToFile|WSA(?:Startup|Send|Recv)|DnsQuery|getaddrinfo)\b|https?:\/\/|\b(?:TCPClient|WebClient)\b)/i;
const EXECUTION_PRIMITIVE_RE = /(?:\b(?:powershell|pwsh|cmd(?:\.exe)?|bash|sh)\b|\b(?:exec|eval|os\.system|subprocess\.(?:run|Popen|call))\s*\(|\b(?:WinExec|ShellExecute|CreateProcess)\b)/i;
const DOWNLOAD_PRIMITIVE_RE = /(?:\b(?:curl|wget|Invoke-(?:WebRequest|RestMethod)|URLDownloadToFile|WebClient)\b|https?:\/\/)/i;
const ENCODED_CONTENT_RE = /(?:-enc(?:odedcommand)?\b|(?:FromBase64String|base64\.(?:b64decode|decode)|atob)\s*\(|(?:[A-Za-z0-9+/]{40,}={0,2}))/i;
const PERSISTENCE_PRIMITIVE_RE = /(?:CurrentVersion\\Run|schtasks|StartupApproved|CreateService|reg\s+add|New-ItemProperty|Winlogon\\Shell)/i;
const CODE_LIKE_RE = /(?:[{};]|=>|\b(?:function|class|import|def|const|let|var|select|where)\b|[#$]\w+)/i;

export function buildArtifactEvidenceProfile(artifact: EvidenceArtifact): ArtifactEvidenceProfile {
  const text = [artifact.analysisContent || artifact.previewContent, artifact.description, artifact.name].filter(Boolean).join('\n');
  const hasNetworkPrimitive = NETWORK_PRIMITIVE_RE.test(text);
  const hasExecutionPrimitive = EXECUTION_PRIMITIVE_RE.test(text);
  const hasDownloadPrimitive = DOWNLOAD_PRIMITIVE_RE.test(text);
  const hasEncodedContent = ENCODED_CONTENT_RE.test(text);
  const hasPersistencePrimitive = PERSISTENCE_PRIMITIVE_RE.test(text);
  const hasExecutableContext = artifact.type === 'code' || artifact.type === 'file' || CODE_LIKE_RE.test(text);
  const attackTechniques: string[] = [];
  if (/\b(?:powershell|pwsh)\b/i.test(text)) attackTechniques.push('T1059.001 PowerShell');
  if (/\b(?:cmd(?:\.exe)?|bash|sh)\b|\b(?:exec|os\.system|subprocess\.(?:run|Popen|call))\s*\(/i.test(text)) attackTechniques.push('T1059 Command and Scripting Interpreter');
  if (hasDownloadPrimitive) attackTechniques.push('T1105 Ingress Tool Transfer');
  if (hasPersistencePrimitive) attackTechniques.push('T1547.001 Registry Run Keys / Startup Folder');
  if (hasEncodedContent) attackTechniques.push('T1027 Obfuscated/Compressed Files and Information');

  return {
    text,
    lineCount: text ? text.split(/\r?\n/).length : 0,
    hasExecutableContext,
    hasNetworkPrimitive,
    hasExecutionPrimitive,
    hasDownloadPrimitive,
    hasEncodedContent,
    hasPersistencePrimitive,
    networkChain: hasNetworkPrimitive && (hasDownloadPrimitive || hasExecutionPrimitive),
    executionChain: hasExecutionPrimitive && (hasEncodedContent || hasDownloadPrimitive || hasPersistencePrimitive),
    attackTechniques: [...new Set(attackTechniques)],
  };
}

export function evidenceContext(profile: ArtifactEvidenceProfile): string {
  const relationships: string[] = [];
  if (profile.networkChain) relationships.push('network primitive is associated with download or execution behavior');
  if (profile.executionChain) relationships.push('execution primitive is associated with encoding, download, or persistence behavior');
  if (relationships.length) return relationships.join('; ');
  if (profile.hasNetworkPrimitive) return profile.hasExecutableContext ? 'network primitive present without a corroborating behavior chain' : 'network-related text without executable context';
  return 'no correlated network or execution behavior identified';
}