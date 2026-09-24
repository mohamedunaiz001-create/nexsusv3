/**
 * Phase 1 placeholder data.
 *
 * These fixtures exist only so the dashboard UI has something to render
 * and can be visually validated. In Phase 2 every section here is wired
 * to the real /api/v1 endpoints (agents, cases, providers, audit-logs)
 * via TanStack Query — nothing here is live.
 */

export const ceoAgent = {
  name: "ARCHON",
  title: "CEO AGENT (COMMANDER)",
  tagline: "The Strategist. The Orchestrator. The Decision Maker.",
  mandate:
    "Analyze the objective, break it down, assign it to the right experts, validate findings, and deliver truth with precision.",
  model: "Claude 3.5 Sonnet",
  contextWindow: "200K",
  temperature: "0.2",
  memory: "Long-Term",
  status: "ACTIVE" as const,
};

export type SpecialistAgent = {
  name: string;
  role: string;
  model: string;
  task: string;
  progress: number;
  status: "ACTIVE" | "IDLE" | "ERROR";
};

export const specialistAgents: SpecialistAgent[] = [
  { name: "MALWARE ANALYSIS", role: "Specialist", model: "GPT-4o", task: "Analyzing malware.exe", progress: 75, status: "ACTIVE" },
  { name: "IOC EXTRACTION", role: "Specialist", model: "Gemini 1.5 Pro", task: "Extracting IOCs", progress: 65, status: "ACTIVE" },
  { name: "THREAT INTEL", role: "Specialist", model: "Claude 3.5 Sonnet", task: "Enriching indicators", progress: 80, status: "ACTIVE" },
  { name: "NETWORK ANALYSIS", role: "Specialist", model: "GPT-4o Mini", task: "Analyzing pcap file", progress: 60, status: "ACTIVE" },
  { name: "CODE REVIEW", role: "Specialist", model: "Claude 3.5 Sonnet", task: "Reviewing script.py", progress: 50, status: "ACTIVE" },
  { name: "REPORT GENERATOR", role: "Specialist", model: "GPT-4o", task: "Drafting report", progress: 65, status: "ACTIVE" },
  { name: "MEMORY AGENT", role: "Specialist", model: "MiniLM + Qdrant", task: "Updating memory", progress: 90, status: "ACTIVE" },
  { name: "VERIFICATION AGENT", role: "Specialist", model: "GPT-4o", task: "Validating findings", progress: 55, status: "ACTIVE" },
];

export const liveActivity = [
  { time: "10:24:48", agent: "ARCHON", detail: "Delegated task to Malware Analysis Agent", done: false },
  { time: "10:24:44", agent: "IOC Extraction Agent", detail: "Extracted 38 IOCs", done: true },
  { time: "10:24:40", agent: "Threat Intel Agent", detail: "Querying VirusTotal, OTX...", done: false },
  { time: "10:24:36", agent: "Network Analysis Agent", detail: "Parsing PCAP file", done: false },
  { time: "10:24:31", agent: "Report Generator Agent", detail: "Compiling insights", done: false },
];

export const topIocs = [
  { value: "185.199.108.153", type: "IP", verdict: "Malicious" as const },
  { value: "bad-domain.com", type: "Domain", verdict: "Malicious" as const },
  { value: "c2.server.net", type: "Domain", verdict: "Suspicious" as const },
  { value: "45.77.32.11", type: "IP", verdict: "Malicious" as const },
  { value: "evil.exe", type: "File Hash", verdict: "Malicious" as const },
];

export const currentMission = {
  title: "Malware Analysis & Threat Investigation",
  caseId: "CASE-2024-017",
  priority: "HIGH" as const,
  description:
    "Analyze the provided malware sample, extract IOCs, enrich threat intelligence, analyze network behavior, and generate a comprehensive report.",
  progress: 68,
  startedAt: "May 20, 2024 · 10:21:31",
  estimatedCompletion: "May 20, 2024 · 10:45:00",
  delegatedBy: "CEO Agent ARCHON",
  steps: [
    { label: "Malware Analysis", status: "Completed" as const },
    { label: "IOC Extraction", status: "Completed" as const },
    { label: "Threat Intelligence", status: "In Progress" as const },
    { label: "Network Analysis", status: "In Progress" as const },
    { label: "Code Review", status: "Pending" as const },
    { label: "Report Generation", status: "Pending" as const },
    { label: "Verification", status: "Pending" as const },
  ],
};

export const recentCases = [
  { id: "CASE-2024-017", title: "Suspicious Email Investigation", status: "In Progress" as const },
  { id: "CASE-2024-016", title: "Malware Sample Analysis", status: "Completed" as const },
  { id: "CASE-2024-015", title: "Network Traffic Anomaly", status: "High" as const },
  { id: "CASE-2024-014", title: "Phishing Website Analysis", status: "Completed" as const },
  { id: "CASE-2024-013", title: "Code Security Review", status: "Low" as const },
];

export const agentPerformance = [
  { agent: "Malware Analysis", tasks: 12, success: 98, avgTime: "2m 14s" },
  { agent: "IOC Extraction", tasks: 15, success: 99, avgTime: "1m 02s" },
  { agent: "Threat Intel", tasks: 18, success: 95, avgTime: "2m 45s" },
  { agent: "Network Analysis", tasks: 9, success: 96, avgTime: "3m 10s" },
  { agent: "Code Review", tasks: 10, success: 92, avgTime: "4m 20s" },
  { agent: "Report Generator", tasks: 8, success: 100, avgTime: "2m 05s" },
  { agent: "Memory Agent", tasks: 22, success: 99, avgTime: "1m 15s" },
  { agent: "Verification Agent", tasks: 14, success: 97, avgTime: "1m 40s" },
];

export const providerStatus = [
  { name: "OpenAI (GPT-4o)", uptime: 98, online: true },
  { name: "Anthropic (Claude 3.5)", uptime: 97, online: true },
  { name: "Google (Gemini 1.5)", uptime: 96, online: true },
  { name: "Groq (Mixtral)", uptime: 95, online: true },
  { name: "Ollama (Local)", uptime: 100, online: true },
  { name: "OpenRouter", uptime: 94, online: true },
];

export const systemOverview = { cpu: 23, memoryUsed: 7.3, memoryTotal: 16, disk: 62, activeAgents: "7 / 8" };

export const liveEventStream = [
  { time: "10:24:48", text: "Case CASE-2024-017 updated" },
  { time: "10:24:44", text: "IOC Extraction completed" },
  { time: "10:24:40", text: "Threat Intel enriching IOCs" },
  { time: "10:24:36", text: "Network Analysis in progress" },
  { time: "10:24:31", text: "Malware Analysis completed" },
];
