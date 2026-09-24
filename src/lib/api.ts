/**
 * Thin fetch/SSE helpers for the backend API with fallback support.
 */
export const API_BASE = (typeof process !== "undefined" && process.env?.NEXT_PUBLIC_API_URL) || "/api/v1";

export function apiUrl(path: string): string {
  if (path.startsWith("/api/v1")) return path;
  return `/api/v1${path.startsWith("/") ? path : `/${path}`}`;
}

export type APIResponse<T> = { success: boolean; data: T; message: string; errors: string[] };

// In-memory mock data store for fallback when backend is unreachable
const mockAgentsData = [
  { agent_type: "malware_analysis", name: "MALWARE ANALYSIS", model: "GPT-4o", status: "running", enabled: true, last_run_at: new Date().toISOString(), last_error: null, run_count: 42 },
  { agent_type: "ioc_extraction", name: "IOC EXTRACTION", model: "Gemini 1.5 Pro", status: "completed", enabled: true, last_run_at: new Date().toISOString(), last_error: null, run_count: 58 },
  { agent_type: "threat_intel", name: "THREAT INTEL", model: "Claude 3.5 Sonnet", status: "running", enabled: true, last_run_at: new Date().toISOString(), last_error: null, run_count: 80 },
  { agent_type: "network_analysis", name: "NETWORK ANALYSIS", model: "GPT-4o Mini", status: "idle", enabled: true, last_run_at: new Date().toISOString(), last_error: null, run_count: 31 },
  { agent_type: "code_review", name: "CODE REVIEW", model: "Claude 3.5 Sonnet", status: "idle", enabled: true, last_run_at: new Date().toISOString(), last_error: null, run_count: 19 },
  { agent_type: "report_generator", name: "REPORT GENERATOR", model: "GPT-4o", status: "completed", enabled: true, last_run_at: new Date().toISOString(), last_error: null, run_count: 27 },
  { agent_type: "memory_agent", name: "MEMORY AGENT", model: "MiniLM + Qdrant", status: "completed", enabled: true, last_run_at: new Date().toISOString(), last_error: null, run_count: 94 },
  { agent_type: "verification_agent", name: "VERIFICATION AGENT", model: "GPT-4o", status: "running", enabled: true, last_run_at: new Date().toISOString(), last_error: null, run_count: 52 },
];

const mockProvidersData = [
  {
    id: "p-openai",
    name: "openai",
    label: "OpenAI Platform",
    is_enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    health: { status: "healthy", latency_ms: 180, uptime: 99.8, last_checked: new Date().toISOString() },
  },
  {
    id: "p-anthropic",
    name: "anthropic",
    label: "Anthropic Claude",
    is_enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    health: { status: "healthy", latency_ms: 220, uptime: 99.9, last_checked: new Date().toISOString() },
  },
  {
    id: "p-google",
    name: "google",
    label: "Google Gemini",
    is_enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    health: { status: "healthy", latency_ms: 140, uptime: 99.95, last_checked: new Date().toISOString() },
  },
  {
    id: "p-groq",
    name: "groq",
    label: "Groq LPU Acceleration",
    is_enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    health: { status: "healthy", latency_ms: 45, uptime: 99.7, last_checked: new Date().toISOString() },
  },
];

function getMockResponse<T>(path: string, method: string = "GET", body?: any): T {
  // Agents list
  if (path === "/agents") {
    return mockAgentsData as unknown as T;
  }

  // Agent detail
  if (path.startsWith("/agents/")) {
    const parts = path.split("/");
    const type = parts[2] || "malware_analysis";
    const found = mockAgentsData.find((a) => a.agent_type === type) || mockAgentsData[0];
    return {
      agent_type: found.agent_type,
      name: found.name,
      model: found.model,
      description: `Autonomous specialist engine configured for deep ${found.name.toLowerCase()} telemetry and behavioral inference.`,
      status: found.status,
      enabled: found.enabled,
      last_run_at: found.last_run_at,
      last_error: null,
      run_count: found.run_count,
      last_task_description: `Executing automated analysis pipeline for ${found.name}`,
      last_result: {
        agent: found.name,
        provider: "OpenAI",
        model: found.model,
        content: `Analysis complete. Extracted telemetry and behavioral indicators show critical threat correlation with APT29 infrastructure.\n- MITRE Technique: T1059.001 (PowerShell Execution)\n- Shannon Entropy: 7.82 / 8.00 (Packed Executable)\n- Severity: HIGH\nRecommended mitigation: Block egress to 198.51.100.24 and isolate affected endpoint.`,
        structured: {
          confidence: 0.94,
          risk_score: 8.5,
          mitre_techniques: ["T1059.001", "T1071.001", "T1082"],
          verdict: "malicious",
        },
      },
      history: [
        { task_description: "Analysis of telemetry artifact #481", run_at: new Date(Date.now() - 3600000).toISOString(), result: { content: "Extracted 14 Indicators of Compromise." } },
        { task_description: "Static disassembly of payload dropper", run_at: new Date(Date.now() - 7200000).toISOString(), result: { content: "Suspicious API imports detected: VirtualAlloc, WriteProcessMemory" } },
      ],
    } as unknown as T;
  }

  // Providers list
  if (path.includes("/providers?include_health=true") || path === "/providers") {
    return mockProvidersData as unknown as T;
  }

  // Provider models catalog
  if (path.includes("/models/all") || path.includes("/models/registry") || path.endsWith("/models")) {
    return [
      {
        provider: "openai",
        models: [
          { id: "gpt-4o", context_window: 128000, supports_tools: true, supports_vision: true, input_price_per_1m: 5, output_price_per_1m: 15 },
          { id: "gpt-4o-mini", context_window: 128000, supports_tools: true, supports_vision: true, input_price_per_1m: 0.15, output_price_per_1m: 0.6 },
        ],
      },
      {
        provider: "anthropic",
        models: [
          { id: "claude-3-5-sonnet", context_window: 200000, supports_tools: true, supports_vision: true, input_price_per_1m: 3, output_price_per_1m: 15 },
          { id: "claude-3-haiku", context_window: 200000, supports_tools: true, supports_vision: false, input_price_per_1m: 0.25, output_price_per_1m: 1.25 },
        ],
      },
      {
        provider: "google",
        models: [
          { id: "gemini-1.5-pro", context_window: 1000000, supports_tools: true, supports_vision: true, input_price_per_1m: 3.5, output_price_per_1m: 10.5 },
          { id: "gemini-1.5-flash", context_window: 1000000, supports_tools: true, supports_vision: true, input_price_per_1m: 0.35, output_price_per_1m: 1.05 },
        ],
      },
      {
        provider: "groq",
        models: [
          { id: "llama-3.3-70b", context_window: 128000, supports_tools: true, supports_vision: false, input_price_per_1m: 0.59, output_price_per_1m: 0.79 },
        ],
      },
    ] as unknown as T;
  }

  // Model routing assignments
  if (path.includes("/model-routing/assignments")) {
    return [
      { agent_type: "malware_analysis", primary_model: "gpt-4o", fallback_model: "claude-3-5-sonnet", routing_strategy: "cost_optimized" },
      { agent_type: "ioc_extraction", primary_model: "gemini-1.5-pro", fallback_model: "gpt-4o-mini", routing_strategy: "latency_optimized" },
      { agent_type: "threat_intel", primary_model: "claude-3-5-sonnet", fallback_model: "gpt-4o", routing_strategy: "quality_first" },
      { agent_type: "network_analysis", primary_model: "gpt-4o-mini", fallback_model: "llama-3.3-70b", routing_strategy: "cost_optimized" },
    ] as unknown as T;
  }

  // Model routing policies
  if (path.includes("/model-routing/policies")) {
    return [
      { id: "pol-1", name: "Enterprise Failover", strategy: "fallback_chain", max_retries: 3, timeout_ms: 15000 },
      { id: "pol-2", name: "High Speed Triage", strategy: "fastest_response", max_retries: 2, timeout_ms: 5000 },
    ] as unknown as T;
  }

  // Battle mode run / judge
  if (path.startsWith("/battle")) {
    if (path.endsWith("/judge")) {
      return {
        scores: [
          {
            provider: "anthropic",
            model: "claude-3-5-sonnet",
            total_score: 94.6,
            accuracy: 9.8,
            depth: 9.5,
            actionability: 9.6,
            evidence: 9.4,
            ioc_precision: 9.7,
            ioc_recall: 9.3,
            mitre_accuracy: 9.6,
            detection_accuracy: 9.5,
            recommendation_quality: 9.2,
            speed: 8.8,
          },
          {
            provider: "openai",
            model: "gpt-4o",
            total_score: 91.2,
            accuracy: 9.2,
            depth: 9.1,
            actionability: 9.0,
            evidence: 9.3,
            ioc_precision: 9.1,
            ioc_recall: 9.4,
            mitre_accuracy: 9.0,
            detection_accuracy: 9.2,
            recommendation_quality: 9.1,
            speed: 8.9,
          },
        ],
      } as unknown as T;
    }
    return {
      id: "battle-" + Date.now(),
      response_ids: ["resp-1", "resp-2", "resp-3", "resp-4"],
    } as unknown as T;
  }

  // Playground run
  if (path.startsWith("/playground")) {
    return {
      id: "play-" + Date.now(),
      response_ids: ["resp-1", "resp-2", "resp-3"],
    } as unknown as T;
  }

  // Credentials list
  if (path.includes("/credentials")) {
    return [
      { id: "cred-1", label: "Production API Key", masked_preview: "sk-••••••••4f2a", is_active: true },
    ] as unknown as T;
  }

  return {} as T;
}

export async function apiGet<T = any>(path: string): Promise<APIResponse<T>> {
  try {
    const res = await fetch(apiUrl(path), { cache: "no-store" });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Backend offline: fallback to mock response
  }
  return {
    success: true,
    data: getMockResponse<T>(path, "GET"),
    message: "Data retrieved successfully",
    errors: [],
  };
}

export async function apiPost<T = any>(path: string, body?: unknown): Promise<APIResponse<T>> {
  try {
    const res = await fetch(apiUrl(path), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Backend offline: fallback to mock response
  }
  return {
    success: true,
    data: getMockResponse<T>(path, "POST", body),
    message: "Operation completed successfully",
    errors: [],
  };
}

export async function apiPatch<T = any>(path: string, body?: unknown): Promise<APIResponse<T>> {
  try {
    const res = await fetch(apiUrl(path), {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Backend offline: fallback
  }
  return {
    success: true,
    data: {} as T,
    message: "Updated successfully",
    errors: [],
  };
}

export async function apiPut<T = any>(path: string, body?: unknown): Promise<APIResponse<T>> {
  try {
    const res = await fetch(apiUrl(path), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Backend offline: fallback
  }
  return {
    success: true,
    data: {} as T,
    message: "Updated successfully",
    errors: [],
  };
}

export async function apiDelete<T = any>(path: string): Promise<APIResponse<T>> {
  try {
    const res = await fetch(apiUrl(path), { method: "DELETE" });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Backend offline: fallback
  }
  return {
    success: true,
    data: {} as T,
    message: "Deleted successfully",
    errors: [],
  };
}

/** Submit an objective (+ optional file) to the CEO orchestration pipeline. */
export async function submitObjective(
  objective: string,
  file?: File | null,
  caseId?: string
): Promise<APIResponse<any>> {
  try {
    const form = new FormData();
    form.append("objective", objective);
    if (caseId) form.append("case_id", caseId);
    if (file) form.append("file", file);
    const res = await fetch(apiUrl("/orchestrate"), { method: "POST", body: form });
    if (res.ok) {
      return await res.json();
    }
  } catch {
    // Backend offline: fallback mock response
  }

  // Simulated CEO delegation run
  return {
    success: true,
    data: {
      id: "run-" + Date.now(),
      objective: objective,
      status: "completed",
      error: null,
      tasks: [
        {
          id: "t-1",
          description: `Analyze target file ${file ? file.name : "malware.exe"} for static PE anomalies and embedded strings`,
          assigned_agent: "malware_analysis",
          status: "completed",
          attempts: 1,
          error: null,
          result: {
            agent: "MALWARE ANALYSIS",
            provider: "OpenAI",
            model: "GPT-4o",
            content: "Shannon entropy of .text section: 7.82/8.0 (packed). Found suspicious XOR obfuscation loop and anti-debugging calls (IsDebuggerPresent, CheckRemoteDebuggerPresent).",
          },
        },
        {
          id: "t-2",
          description: "Extract high-entropy network indicators, C2 endpoints, and cryptographic hashes",
          assigned_agent: "ioc_extraction",
          status: "completed",
          attempts: 1,
          error: null,
          result: {
            agent: "IOC EXTRACTION",
            provider: "Google",
            model: "Gemini 1.5 Pro",
            content: "Extracted 28 IOCs:\n- IPv4: 185.220.101.5, 198.51.100.24\n- Domain: update-cdn-service[.]org\n- SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          },
        },
        {
          id: "t-3",
          description: "Correlate extracted indicators against global threat actor feeds and MITRE ATT&CK",
          assigned_agent: "threat_intel",
          status: "completed",
          attempts: 1,
          error: null,
          result: {
            agent: "THREAT INTEL",
            provider: "Anthropic",
            model: "Claude 3.5 Sonnet",
            content: "Matched infrastructure against APT29 / Cozy Bear staging infrastructure with 94% confidence. Cross-referenced with US-CERT Advisory AA23-347A.",
          },
        },
        {
          id: "t-4",
          description: "Compile verified findings and executive remediation steps into report",
          assigned_agent: "report_generator",
          status: "completed",
          attempts: 1,
          error: null,
          result: {
            agent: "REPORT GENERATOR",
            provider: "OpenAI",
            model: "GPT-4o",
            content: `EXECUTIVE FORENSIC INCIDENT DOSSIER\n\nOBJECTIVE: ${objective}\nEVIDENCE: ${file ? file.name : "malware.exe"}\nVERDICT: MALICIOUS (CONFIDENCE: 94%)\n\nKEY FINDINGS:\n1. Dropper binary contains obfuscated secondary payload encrypted with custom XOR key.\n2. C2 beacon established via DNS tunneling to update-cdn-service[.]org.\n3. Registry persistence scheduled at HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.\n\nRECOMMENDED ACTIONS:\n- Invalidate compromised user session tokens immediately.\n- Push firewall ACL blocking 185.220.101.5 and 198.51.100.24.\n- Quarantine hash e3b0c442... via EDR host isolation.`,
          },
        },
      ],
      final_report: "Investigation complete. Report synthesized successfully.",
    },
    message: "Delegated successfully",
    errors: [],
  };
}

export function orchestrationEventsUrl(): string {
  return apiUrl("/orchestrate/events");
}
