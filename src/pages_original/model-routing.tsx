"use client";

import { useState, useEffect } from "react";
import {
  Crown,
  Brain,
  Bug,
  Search,
  Shield,
  Zap,
  FileText,
  Database,
  RotateCcw,
  Loader2,
  Play,
  CheckCircle,
  AlertCircle,
  Wifi,
  WifiOff,
  ChevronDown,
  ChevronUp,
  Save,
  X,
  Edit,
  Trash2,
  Plus,
  ArrowRight,
  ArrowLeft,
  Sparkles,
} from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { apiGet, apiPost, apiPatch, apiDelete, apiPut } from "@/lib/api";
import { cn } from "@/lib/utils";

type AgentAssignment = {
  id: string;
  agent_type: string;
  provider: string;
  model: string;
  fallback_chain: string[];
  priority: number;
  created_at: string;
  updated_at: string;
};

type RoutingPolicy = {
  id: string;
  name: string;
  description: string | null;
  rules: Record<string, any>;
  is_active: boolean;
  created_at: string;
  updated_at: string;
};

type ModelInfo = {
  id: string;
  provider: string;
  context_window: number | null;
  supports_tools: boolean;
  supports_vision: boolean;
  supports_streaming: boolean;
  role: string;
  known: boolean;
  input_price_per_1m: number | null;
  output_price_per_1m: number | null;
};

type TestResult = {
  success: boolean;
  agent_type: string;
  provider: string;
  model: string;
  latency_ms: number;
  tokens: { prompt: number | null; completion: number | null };
  cost: number | null;
  content: string;
  error: string | null;
};

const AGENTS = [
  { type: "ceo", name: "CEO Orchestrator", description: "Plans, delegates, and synthesizes results", icon: Crown },
  { type: "malware_analysis", name: "Malware Analysis", description: "Static and dynamic malware analysis", icon: Bug },
  { type: "ioc_extraction", name: "IOC Extraction", description: "Extract indicators of compromise", icon: Search },
  { type: "threat_intel", name: "Threat Intelligence", description: "Threat intel lookup and enrichment", icon: Shield },
  { type: "network_analysis", name: "Network Analysis", description: "PCAP and network traffic analysis", icon: Zap },
  { type: "code_review", name: "Secure Code Review", description: "Security-focused code review", icon: FileText },
  { type: "memory", name: "Memory & Knowledge", description: "Long-term memory and retrieval", icon: Database },
  { type: "verification", name: "Verification", description: "Output validation and quality check", icon: RotateCcw },
] as const;

const ROUTING_STRATEGIES = [
  { value: "manual", label: "Manual", description: "Use explicitly assigned model" },
  { value: "cheapest", label: "Cheapest", description: "Lowest cost tier compatible model" },
  { value: "fastest", label: "Fastest", description: "Lowest latency / smallest model" },
  { value: "highest_quality", label: "Highest Quality", description: "Best capabilities (context, tools, vision)" },
  { value: "best_for_security", label: "Best for Security", description: "Large context, tools, reasoning" },
  { value: "best_for_code", label: "Best for Code", description: "Code capabilities, tools, context" },
  { value: "best_for_vision", label: "Best for Vision", description: "Requires vision capability" },
  { value: "auto", label: "Auto", description: "Intelligent selection by task type" },
] as const;

function statusColor(status: string) {
  switch (status) {
    case "ok": return "text-signal-green";
    case "error": return "text-ember-400";
    case "unknown": return "text-violet-400/50";
    default: return "text-violet-400/50";
  }
}

function statusDot(status: string) {
  return (
    <span className={cn("h-1.5 w-1.5 rounded-full", statusColor(status))} />
  );
}

function AgentIcon({ type }: { type: string }) {
  const agent = AGENTS.find(a => a.type === type);
  return agent ? <agent.icon className="h-5 w-5 text-violet-400" /> : <Brain className="h-5 w-5 text-violet-400" />;
}

export default function ModelRoutingSettingsPage() {
  const [assignments, setAssignments] = useState<Record<string, AgentAssignment>>({});
  const [policies, setPolicies] = useState<RoutingPolicy[]>([]);
  const [models, setModels] = useState<Record<string, ModelInfo[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, TestResult>>({});
  const [editingAgent, setEditingAgent] = useState<string | null>(null);
  const [formData, setFormData] = useState<Record<string, Partial<{ provider: string; model: string; fallback_chain: string[]; strategy: string }>>>({});
  const [showFallbacks, setShowFallbacks] = useState<Record<string, boolean>>({});

  async function loadData() {
    try {
      const [assignRes, policyRes, modelRes] = await Promise.all([
        apiGet<AgentAssignment[]>("/model-routing/assignments"),
        apiGet<RoutingPolicy[]>("/model-routing/policies"),
        apiGet<ModelInfo[]>("/models/registry"),
      ]);
      
      const assignmentMap: Record<string, AgentAssignment> = {};
      assignRes.data.forEach(a => { assignmentMap[a.agent_type] = a; });
      setAssignments(assignmentMap);
      
      setPolicies(policyRes.data);
      
      const modelMap: Record<string, ModelInfo[]> = {};
      modelRes.data.forEach(m => {
        const bucket = modelMap[m.provider] ?? (modelMap[m.provider] = []);
        bucket.push(m);
      });
      setModels(modelMap);
      
      // Initialize form data
      AGENTS.forEach(agent => {
        const existing = assignmentMap[agent.type];
        setFormData(prev => ({
          ...prev,
          [agent.type]: {
            provider: existing?.provider || "ollama",
            model: existing?.model || "llama3",
            fallback_chain: existing?.fallback_chain || [],
            strategy: "manual",
          }
        }));
      });
      
      setError(null);
    } catch (e: any) {
      setError(`Failed to load data: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function handleSaveAssignment(agentType: string) {
    const data = formData[agentType];
    if (!data?.provider || !data?.model) {
      setError("Provider and model are required");
      return;
    }
    
    try {
      await apiPut(`/model-routing/assignments/${agentType}`, data);
      setEditingAgent(null);
      loadData();
    } catch (e: any) {
      setError(`Failed to save: ${e.message}`);
    }
  }

  async function handleTestAgent(agentType: string) {
    setTesting(agentType);
    try {
      const res = await apiPost<TestResult>(`/agents/${agentType}/test`);
      setTestResults(prev => ({ ...prev, [agentType]: res.data }));
    } catch (e: any) {
      setTestResults(prev => ({ ...prev, [agentType]: { 
        success: false, 
        agent_type: agentType, 
        provider: "", 
        model: "", 
        latency_ms: 0, 
        tokens: { prompt: null, completion: null }, 
        cost: null, 
        content: "", 
        error: e.message 
      }}));
    } finally {
      setTesting(null);
    }
  }

  function getAvailableModels(provider: string): ModelInfo[] {
    return models[provider] || [];
  }

  function getAllProviders(): string[] {
    return Array.from(new Set(Object.values(assignments).map((a: any) => a.provider))).sort();
  }

  function getFallbackOptions(currentProvider: string, currentModel: string): string[] {
    const options: string[] = [];
    Object.entries(models).forEach(([provider, providerModels]: [string, any]) => {
      if (Array.isArray(providerModels)) {
        providerModels.forEach((m: any) => {
          if (provider !== currentProvider || m.id !== currentModel) {
            options.push(`${provider}:${m.id}`);
          }
        });
      }
    });
    return options;
  }

  useEffect(() => {
    loadData();
  }, []);

  return (
    <DashboardShell>
      <div className="space-y-6">
        <section className="panel relative overflow-hidden p-6">
          <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-violet-950/40 via-transparent to-transparent" />
          <div className="relative flex flex-col items-center gap-2">
            <div className="flex h-14 w-14 items-center justify-center rounded-full border border-violet-500/30 bg-violet-600/10 shadow-glow-sm">
              <ArrowRight className="h-7 w-7 text-violet-300" />
            </div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.25em] text-violet-400/60">Model Routing</p>
            <h1 className="font-display text-2xl text-violet-50">Agent Model Assignment</h1>
            <p className="max-w-2xl text-xs text-violet-300/60 text-center">
              Assign specific models to each agent. Choose routing strategies for automatic selection.
            </p>
          </div>
        </section>

        {error && (
          <div className="panel border-ember-400/30 bg-ember-400/5 p-4 rounded-lg flex items-center justify-between">
            <p className="text-sm text-ember-300">{error}</p>
            <button onClick={() => setError(null)} className="text-ember-400 hover:text-ember-200">✕</button>
          </div>
        )}

        {/* CEO Configuration Section */}
        <section className="panel p-6">
          <h2 className="font-display text-lg text-violet-100 mb-4 flex items-center gap-2">
            <Crown className="h-5 w-5 text-violet-400" />
            CEO Orchestrator Configuration
          </h2>
          <p className="text-xs text-violet-400/50 mb-4">
            The CEO is the primary agent you interact with. It plans, delegates, and synthesizes results from all specialists.
          </p>
          
          {editingAgent === "ceo" ? (
            <div className="space-y-4 max-w-2xl">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-[10px] uppercase tracking-wider text-violet-400/50 mb-1">Provider</label>
                  <select
                    value={formData.ceo?.provider || "ollama"}
                    onChange={e => setFormData(prev => ({ ...prev, ceo: { ...prev.ceo, provider: e.target.value } }))}
                    className="w-full rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 focus:border-violet-500/50 focus:outline-none"
                  >
                    <option value="openai">OpenAI</option>
                    <option value="anthropic">Anthropic</option>
                    <option value="gemini">Google Gemini</option>
                    <option value="groq">Groq</option>
                    <option value="openrouter">OpenRouter</option>
                    <option value="ollama">Ollama (Local)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-wider text-violet-400/50 mb-1">Model</label>
                  <select
                    value={formData.ceo?.model || "llama3"}
                    onChange={e => setFormData(prev => ({ ...prev, ceo: { ...prev.ceo, model: e.target.value } }))}
                    className="w-full rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 focus:border-violet-500/50 focus:outline-none"
                  >
                    {getAvailableModels(formData.ceo?.provider || "ollama").map(m => (
                      <option key={m.id} value={m.id}>{m.id}</option>
                    ))}
                  </select>
                </div>
              </div>
              
              <div>
                <label className="block text-[10px] uppercase tracking-wider text-violet-400/50 mb-1">Routing Strategy</label>
                <select
                  value={formData.ceo?.strategy || "manual"}
                  onChange={e => setFormData(prev => ({ ...prev, ceo: { ...prev.ceo, strategy: e.target.value } }))}
                  className="w-full rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 focus:border-violet-500/50 focus:outline-none"
                >
                  {ROUTING_STRATEGIES.map(s => (
                    <option key={s.value} value={s.value}>{s.label} - {s.description}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-[10px] uppercase tracking-wider text-violet-400/50 mb-1">Fallback Chain (ordered)</label>
                <div className="space-y-2">
                  {formData.ceo?.fallback_chain?.map((fb, idx) => (
                    <div key={idx} className="flex gap-2">
                      <select
                        value={fb}
                        onChange={e => {
                          const newChain = [...(formData.ceo?.fallback_chain || [])];
                          newChain[idx] = e.target.value;
                          setFormData(prev => ({ ...prev, ceo: { ...prev.ceo, fallback_chain: newChain } }));
                        }}
                        className="flex-1 rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 focus:border-violet-500/50 focus:outline-none"
                      >
                        <option value="">Select fallback...</option>
                        {getFallbackOptions(formData.ceo?.provider || "", formData.ceo?.model || "").map(fb => (
                          <option key={fb} value={fb}>{fb}</option>
                        ))}
                      </select>
                      <button onClick={() => {
                        const newChain = [...(formData.ceo?.fallback_chain || [])];
                        newChain.splice(idx, 1);
                        setFormData(prev => ({ ...prev, ceo: { ...prev.ceo, fallback_chain: newChain } }));
                      }} className="px-3 py-2 text-ember-400 hover:text-ember-300">
                        <X className="h-4 w-4" />
                      </button>
                    </div>
                  ))}
                  <button onClick={() => {
                    setFormData(prev => ({ ...prev, ceo: { ...prev.ceo, fallback_chain: [...(prev.ceo?.fallback_chain || []), ""] } }));
                  }} className="text-sm text-violet-400 hover:text-violet-200 flex items-center gap-1">
                    <Plus className="h-3 w-3" /> Add Fallback
                  </button>
                </div>
              </div>

              <div className="flex gap-2 pt-2">
                <button onClick={() => handleSaveAssignment("ceo")} className="flex-1 px-3 py-2 text-xs font-medium text-violet-100 bg-violet-600/20 border border-violet-500/30 rounded-lg hover:bg-violet-600/30">
                  <Save className="h-3.5 w-3.5 inline mr-1" /> Save CEO Config
                </button>
                <button onClick={() => setEditingAgent(null)} className="px-3 py-2 text-xs font-medium text-violet-300/60 hover:text-violet-100">Cancel</button>
              </div>
            </div>
          ) : (
            <div className="max-w-2xl">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
                <div>
                  <span className="text-[10px] uppercase tracking-wider text-violet-400/50">Provider</span>
                  <p className="font-medium text-violet-100 mt-1">{assignments.ceo?.provider || "Not configured"}</p>
                </div>
                <div>
                  <span className="text-[10px] uppercase tracking-wider text-violet-400/50">Model</span>
                  <p className="font-medium text-violet-100 mt-1">{assignments.ceo?.model || "Not configured"}</p>
                </div>
                <div>
                  <span className="text-[10px] uppercase tracking-wider text-violet-400/50">Strategy</span>
                  <p className="font-medium text-violet-100 mt-1">{formData.ceo?.strategy || "manual"}</p>
                </div>
              </div>
              {assignments.ceo?.fallback_chain?.length && (
                <div className="mb-4">
                  <span className="text-[10px] uppercase tracking-wider text-violet-400/50">Fallback Chain</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {assignments.ceo.fallback_chain.map((fb, idx) => (
                      <span key={idx} className="px-2 py-1 text-[10px] bg-violet-500/10 border border-violet-500/20 rounded text-violet-300">
                        {fb}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              <button onClick={() => setEditingAgent("ceo")} className="px-3 py-2 text-xs font-medium text-violet-300 hover:text-violet-100 flex items-center gap-1">
                <Edit className="h-3 w-3" /> Configure CEO
              </button>
            </div>
          )}
        </section>

        {/* Specialist Agents Section */}
        <section className="panel p-6">
          <h2 className="font-display text-lg text-violet-100 mb-4 flex items-center gap-2">
            <Bug className="h-5 w-5 text-violet-400" />
            Specialist Agent Model Assignments
          </h2>
          <p className="text-xs text-violet-400/50 mb-4">
            Each specialist can have its own provider/model. Changes take effect immediately without code changes.
          </p>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {AGENTS.filter(a => a.type !== "ceo").map(agent => {
              const assignment = assignments[agent.type];
              const isEditing = editingAgent === agent.type;
              const testResult = testResults[agent.type];
              
              return (
                <div key={agent.type} className="panel relative p-4 space-y-3">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-violet-500/20 bg-violet-600/10">
                        <AgentIcon type={agent.type} />
                      </div>
                      <div>
                        <h3 className="font-medium text-violet-100">{agent.name}</h3>
                        <p className="text-[10px] text-violet-400/50">{agent.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      {assignment ? (
                        <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium", statusColor("ok"))}>
                          {statusDot("ok")} Configured
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium text-violet-400/50 bg-violet-500/10">
                          <WifiOff className="h-3 w-3" /> Not Set
                        </span>
                      )}
                    </div>
                  </div>

                  {isEditing ? (
                    <div className="space-y-3">
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="block text-[10px] uppercase tracking-wider text-violet-400/50 mb-1">Provider</label>
                          <select
                            value={formData[agent.type]?.provider || "ollama"}
                            onChange={e => setFormData(prev => ({ ...prev, [agent.type]: { ...prev[agent.type], provider: e.target.value, model: getAvailableModels(e.target.value)[0]?.id || "" } }))}
                            className="w-full rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 focus:border-violet-500/50 focus:outline-none"
                          >
                            <option value="openai">OpenAI</option>
                            <option value="anthropic">Anthropic</option>
                            <option value="gemini">Google Gemini</option>
                            <option value="groq">Groq</option>
                            <option value="openrouter">OpenRouter</option>
                            <option value="ollama">Ollama (Local)</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-[10px] uppercase tracking-wider text-violet-400/50 mb-1">Model</label>
                          <select
                            value={formData[agent.type]?.model || ""}
                            onChange={e => setFormData(prev => ({ ...prev, [agent.type]: { ...prev[agent.type], model: e.target.value } }))}
                            className="w-full rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 focus:border-violet-500/50 focus:outline-none"
                          >
                            {getAvailableModels(formData[agent.type]?.provider || "ollama").map(m => (
                              <option key={m.id} value={m.id}>{m.id}</option>
                            ))}
                          </select>
                        </div>
                      </div>
                      
                      <div>
                        <label className="block text-[10px] uppercase tracking-wider text-violet-400/50 mb-1">Routing Strategy</label>
                        <select
                          value={formData[agent.type]?.strategy || "manual"}
                          onChange={e => setFormData(prev => ({ ...prev, [agent.type]: { ...prev[agent.type], strategy: e.target.value } }))}
                          className="w-full rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 focus:border-violet-500/50 focus:outline-none"
                        >
                          {ROUTING_STRATEGIES.map(s => (
                            <option key={s.value} value={s.value}>{s.label}</option>
                          ))}
                        </select>
                      </div>

                      <div>
                        <label className="block text-[10px] uppercase tracking-wider text-violet-400/50 mb-1">Fallback Chain (max 3)</label>
                        <div className="space-y-2">
                          {formData[agent.type]?.fallback_chain?.map((fb, idx) => (
                            <div key={idx} className="flex gap-2">
                              <select
                                value={fb}
                                onChange={e => {
                                  const newChain = [...(formData[agent.type]?.fallback_chain || [])];
                                  newChain[idx] = e.target.value;
                                  setFormData(prev => ({ ...prev, [agent.type]: { ...prev[agent.type], fallback_chain: newChain } }));
                                }}
                                className="flex-1 rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 focus:border-violet-500/50 focus:outline-none"
                              >
                                <option value="">Select fallback...</option>
                                {getFallbackOptions(formData[agent.type]?.provider || "", formData[agent.type]?.model || "").map(fb => (
                                  <option key={fb} value={fb}>{fb}</option>
                                ))}
                              </select>
                              <button onClick={() => {
                                const newChain = [...(formData[agent.type]?.fallback_chain || [])];
                                newChain.splice(idx, 1);
                                setFormData(prev => ({ ...prev, [agent.type]: { ...prev[agent.type], fallback_chain: newChain } }));
                              }} className="px-3 py-2 text-ember-400 hover:text-ember-300">
                                <X className="h-3 w-3" />
                              </button>
                            </div>
                          ))}
                          <button onClick={() => {
                            setFormData(prev => ({ ...prev, [agent.type]: { ...prev[agent.type], fallback_chain: [...(prev[agent.type]?.fallback_chain || []), ""] } }));
                          }} className="text-sm text-violet-400 hover:text-violet-200 flex items-center gap-1">
                            <Plus className="h-3 w-3" /> Add Fallback
                          </button>
                        </div>
                      </div>

                      <div className="flex gap-2 pt-2">
                        <button onClick={() => handleSaveAssignment(agent.type)} className="flex-1 px-3 py-2 text-xs font-medium text-violet-100 bg-violet-600/20 border border-violet-500/30 rounded-lg hover:bg-violet-600/30">
                          <Save className="h-3.5 w-3.5 inline mr-1" /> Save
                        </button>
                        <button onClick={() => setEditingAgent(null)} className="px-3 py-2 text-xs font-medium text-violet-300/60 hover:text-violet-100">Cancel</button>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {assignment && (
                        <>
                          <div className="flex items-center gap-2 text-sm">
                            <span className="text-violet-400/50">Provider:</span>
                            <span className="font-medium text-violet-100">{assignment.provider}</span>
                          </div>
                          <div className="flex items-center gap-2 text-sm">
                            <span className="text-violet-400/50">Model:</span>
                            <span className="font-medium text-violet-100">{assignment.model}</span>
                          </div>
                          <div className="flex items-center gap-2 text-sm">
                            <span className="text-violet-400/50">Strategy:</span>
                            <span className="font-medium text-violet-100">{formData[agent.type]?.strategy || "manual"}</span>
                          </div>
                          {assignment.fallback_chain?.length && (
                            <div className="flex flex-wrap gap-1 mt-1">
                              <span className="text-[10px] text-violet-400/50">Fallbacks:</span>
                              {assignment.fallback_chain.map((fb, idx) => (
                                <span key={idx} className="px-1.5 py-0.5 text-[9px] bg-violet-500/10 border border-violet-500/20 rounded text-violet-300">
                                  {fb}
                                </span>
                              ))}
                            </div>
                          )}
                        </>
                      )}
                      
                      <div className="flex flex-wrap gap-2 pt-2">
                        <button onClick={() => setEditingAgent(agent.type)} className="flex-1 px-3 py-1.5 text-[10px] font-medium rounded-lg border bg-violet-500/10 border-violet-500/20 text-violet-300 hover:bg-violet-500/20 transition-colors">
                          <Edit className="h-3 w-3 inline mr-1" /> Configure
                        </button>
                        <button
                          onClick={() => handleTestAgent(agent.type)}
                          disabled={testing === agent.type || !assignment}
                          className={cn(
                            "flex-1 flex items-center justify-center gap-1 px-2 py-1.5 text-[10px] font-medium rounded-lg border transition-colors",
                            testing === agent.type
                              ? "bg-violet-500/10 border-violet-500/30 text-violet-400"
                              : !assignment
                              ? "border-violet-500/10 text-violet-400/40 cursor-not-allowed"
                              : "bg-violet-500/10 border-violet-500/20 text-violet-300 hover:bg-violet-500/20"
                          )}
                        >
                          {testing === agent.type ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                          {testing === agent.type ? "Testing..." : "Test"}
                        </button>
                      </div>

                      {testResult && (
                        <div className={cn("p-3 rounded text-[10px]", testResult.success ? "bg-signal-green/10 border border-signal-green/30" : "bg-ember-400/10 border border-ember-400/30")}>
                          <div className="flex items-center gap-1 mb-1">
                            {testResult.success ? (
                              <CheckCircle className="h-3 w-3 text-signal-green" />
                            ) : (
                              <AlertCircle className="h-3 w-3 text-ember-400" />
                            )}
                            <span className="font-medium">{testResult.success ? "Success" : "Failed"}</span>
                            <span className="text-violet-400/50 ml-auto">{testResult.latency_ms}ms</span>
                          </div>
                          {testResult.tokens.prompt && (
                            <div className="text-violet-300/60">
                              Tokens: {testResult.tokens.prompt} in / {testResult.tokens.completion} out
                              {testResult.cost !== null && ` • Cost: $${testResult.cost.toFixed(6)}`}
                            </div>
                          )}
                          {testResult.error && (
                            <div className="text-ember-400 mt-1 truncate">{testResult.error}</div>
                          )}
                          {testResult.content && (
                            <div className="text-violet-300/60 mt-1 line-clamp-2">{testResult.content}</div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>

        {/* Routing Policies Section */}
        <section className="panel p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display text-lg text-violet-100 flex items-center gap-2">
              <RotateCcw className="h-5 w-5 text-violet-400" />
              Routing Policies
            </h2>
            <button className="px-3 py-1.5 text-xs font-medium text-violet-100 bg-violet-600/20 border border-violet-500/30 rounded-lg hover:bg-violet-600/30">
              <Plus className="h-3.5 w-3.5 inline mr-1" /> Create Policy
            </button>
          </div>

          {policies.length === 0 ? (
            <div className="text-center py-8">
              <RotateCcw className="h-12 w-12 mx-auto text-violet-400/30 mb-4" />
              <p className="text-violet-400/50">No routing policies configured</p>
              <p className="text-xs text-violet-400/30 mt-1">Create policies to define automatic routing rules</p>
            </div>
          ) : (
            <div className="space-y-3">
              {policies.map(policy => (
                <div key={policy.id} className="panel p-4 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-violet-500/20 bg-violet-600/10">
                      <RotateCcw className="h-5 w-5 text-violet-400" />
                    </div>
                    <div>
                      <h3 className="font-medium text-violet-100">{policy.name}</h3>
                      <p className="text-xs text-violet-400/50">{policy.description || "No description"}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium", policy.is_active ? "bg-signal-green/20 text-signal-green" : "bg-violet-500/10 text-violet-400/50")}>
                      {policy.is_active ? "Active" : "Inactive"}
                    </span>
                    <span className="text-[10px] text-violet-400/50">Strategy: {policy.rules?.strategy || "manual"}</span>
                    <button className="px-2 py-1 text-[10px] text-violet-400 hover:text-violet-200">Edit</button>
                    <button className="px-2 py-1 text-[10px] text-ember-400 hover:text-ember-300">Delete</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Visual Orchestration */}
        <section className="panel p-6">
          <h2 className="font-display text-lg text-violet-100 mb-4 flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-violet-400" />
            Orchestration Flow Visualization
          </h2>
          <p className="text-xs text-violet-400/50 mb-4">
            Real-time view of the agent hierarchy with assigned models.
          </p>
          
          <div className="space-y-4">
            {/* CEO at top */}
            <div className="flex flex-col items-center">
              <div className="panel p-4 w-full max-w-md text-center border-violet-500/40 bg-violet-500/5">
                <div className="flex items-center justify-center gap-2 mb-2">
                  <Crown className="h-5 w-5 text-violet-300" />
                  <span className="font-display text-lg text-violet-50">CEO Orchestrator</span>
                </div>
                <div className="text-sm">
                  <span className="text-violet-400/50">{assignments.ceo?.provider || "Not set"}:</span>
                  <span className="font-medium text-violet-100 ml-1">{assignments.ceo?.model || "Not set"}</span>
                </div>
              </div>
              <div className="h-4 w-px bg-violet-500/30" />
            </div>
            
            {/* Specialists row */}
            <div className="flex flex-wrap justify-center gap-4">
              {AGENTS.filter(a => a.type !== "ceo").map(agent => {
                const assignment = assignments[agent.type];
                const testResult = testResults[agent.type];
                
                return (
                  <div key={agent.type} className={cn(
                    "panel p-3 w-40 text-center transition-all",
                    testResult?.success ? "border-signal-green/40 bg-signal-green/5 animate-pulse" : 
                    testResult?.success === false ? "border-ember-400/40 bg-ember-400/5" : ""
                  )}>
                    <div className="flex items-center justify-center gap-1 mb-1">
                      <AgentIcon type={agent.type} />
                      <span className="font-medium text-xs text-violet-100">{agent.name}</span>
                    </div>
                    {assignment ? (
                      <>
                        <div className="text-[10px] text-violet-300">{assignment.provider}</div>
                        <div className="font-medium text-[11px] text-violet-100 truncate">{assignment.model}</div>
                        <div className={cn("text-[9px] mt-1", formData[agent.type]?.strategy === "manual" ? "text-violet-400/50" : "text-violet-300")}>
                          Strategy: {formData[agent.type]?.strategy || "manual"}
                        </div>
                      </>
                    ) : (
                      <div className="text-[10px] text-violet-400/50">Not configured</div>
                    )}
                    {testResult && (
                      <div className={cn("mt-1 h-1.5 w-1.5 rounded-full mx-auto", testResult.success ? "bg-signal-green" : "bg-ember-400")} />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </section>
      </div>
    </DashboardShell>
  );
}