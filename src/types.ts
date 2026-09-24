import type { LucideIcon } from "lucide-react";

export type NavItem = {
  id: string;
  label: string;
  href: string;
  icon: LucideIcon;
  badge?: string;
};

export type NavSection = {
  label: string;
  items: NavItem[];
};

export type CeoAgent = {
  name: string;
  title: string;
  tagline: string;
  mandate: string;
  model: string;
  contextWindow: string;
  temperature: string;
  memory: string;
  status: "ACTIVE" | "STANDBY" | "OFFLINE";
};

export type SpecialistAgent = {
  name: string;
  role: string;
  model: string;
  task: string;
  progress: number;
  status: "ACTIVE" | "IDLE" | "ERROR";
  iconName?: string;
  description?: string;
};

export type Case = {
  id: string;
  title: string;
  severity?: "critical" | "high" | "medium" | "low" | string;
  priority?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  status: string;
  summary: string;
  createdAt: string;
  leadAgent?: string;
  indicatorsCount: number;
  artifactsCount?: number;
  assignedAgent?: string;
  mitreTechniques?: string[];
};

export type CaseItem = Case;

export type TopIoc = {
  value: string;
  type: "IP" | "Domain" | "File Hash" | "URL" | "CVE";
  verdict: "Malicious" | "Suspicious" | "Clean" | "Unknown";
  source: string;
  threatActor?: string;
  lastSeen?: string;
};

export type LiveActivityItem = {
  time: string;
  agent: string;
  detail: string;
  done: boolean;
};

export type CurrentMissionData = {
  title: string;
  caseId: string;
  priority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
  progress: number;
  startedAt: string;
  estimatedCompletion: string;
  delegatedBy: string;
  steps: { label: string; status: "Completed" | "In Progress" | "Pending" }[];
};

export type ProviderStatusItem = {
  name: string;
  uptime: number;
  online: boolean;
  status?: string;
  latencyMs: number;
  activeModels: number;
};

export type AgentPerformanceItem = {
  agent: string;
  tasks: number;
  success: number;
  avgTime: string;
};

export type SystemOverviewData = {
  cpu: number;
  memoryUsed: number;
  memoryTotal: number;
  disk: number;
  activeAgents: string;
  networkInMbps: number;
  networkOutMbps: number;
};

export type LiveEventStreamItem = {
  time: string;
  text: string;
  level?: "info" | "warn" | "danger" | "success";
};

// Malware Intelligence Engine types
export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

export type RuleMatch = {
  ruleId: string;
  ruleName: string;
  severity: "low" | "medium" | "high" | "critical";
  family?: string;
  description: string;
};

export type SimilarSample = {
  id: string;
  name: string;
  score: number;
  family?: string;
  verdict: Verdict;
};

export type PeSection = {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number;
};

export type StaticFeatures = {
  entropyOverall: number;
  uniqueByteRatio: number;
  printableStringRatio: number;
  suspiciousStrings: string[];
  persistenceIndicatorStrings: string[];
  networkIndicatorStrings: string[];
  peSections?: PeSection[];
  peNumSections?: number;
  peImportedDlls?: Record<string, string[]>;
  peSuspiciousImportedApis?: string[];
  elfType?: string;
  vector: number[];
};

export type SampleVerdictResult = {
  verdict: Verdict;
  confidence: number;
  staticConfidence: number;
  ruleConfidence: number;
  similarityConfidence: number;
  modelConfidence?: number | null;
  modelVersion?: string | null;
  observedCharacteristics: string[];
  ruleMatches: RuleMatch[];
  similarSamples: SimilarSample[];
  likelyFamily?: string | null;
};

export type MalwareSample = {
  id: string;
  name: string;
  sizeBytes: number;
  sha256: string;
  md5: string;
  mimeType: string;
  uploadedAt: string;
  verdictResult: SampleVerdictResult;
  features: StaticFeatures;
};

export type EvidenceArtifact = {
  id: string;
  caseId: string;
  filename: string;
  fileType: string;
  sizeBytes: number;
  sha256: string;
  uploadedAt: string;
  status: "analyzed" | "processing" | "flagged";
  malwareIntelSample?: MalwareSample;
  summary?: string;
  tags: string[];
};

export type OrchestrationEvent = {
  type: string;
  timestamp: string;
  [key: string]: any;
};
