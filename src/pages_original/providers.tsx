"use client";

import React, { useState, useEffect } from "react";
import {
  Plus,
  Edit,
  Trash2,
  Check,
  X,
  Play,
  RefreshCw,
  Eye,
  EyeOff,
  Key,
  RotateCcw,
  Loader2,
  AlertCircle,
  CheckCircle,
  Wifi,
  WifiOff,
  Server,
  Database,
  Shield,
  Brain,
  Zap,
  DollarSign,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  TestTube,
  Sparkles,
} from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { apiGet, apiPost, apiPatch, apiDelete } from "@/lib/api";
import { cn } from "@/lib/utils";

type Provider = {
  id: string;
  name: string;
  provider_type: "cloud" | "local";
  base_url: string | null;
  is_enabled: boolean;
  created_at: string;
  updated_at: string;
  health_status: string;
  health_latency_ms: number | null;
  health_last_checked: string | null;
  health_last_error: string | null;
  configured: boolean;
};

type Credential = {
  id: string;
  provider: string;
  label: string;
  secret_ref: string;
  masked_preview: string | null;
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

type ProviderModels = {
  provider: string;
  models: ModelInfo[];
  unavailable_reason: string | null;
};

type TestResult = {
  provider: string;
  ok: boolean;
  detail: string | null;
  latency_ms: number;
};

const statusColors = {
  ok: "text-signal-green",
  error: "text-ember-400",
  unknown: "text-violet-400/50",
  degraded: "text-signal-amber",
};

const providerIcons: Record<string, React.ReactNode> = {
  openai: <Brain className="h-5 w-5 text-green-400" />,
  anthropic: <Sparkles className="h-5 w-5 text-amber-400" />,
  gemini: <Zap className="h-5 w-5 text-blue-400" />,
  groq: <Zap className="h-5 w-5 text-orange-400" />,
  openrouter: <ExternalLink className="h-5 w-5 text-purple-400" />,
  ollama: <Database className="h-5 w-5 text-violet-400" />,
  custom: <Server className="h-5 w-5 text-cyan-400" />,
};

function StatusBadge({ status, configured }: { status: string; configured: boolean }) {
  if (!configured) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium text-violet-400/50 bg-violet-500/10">
        <WifiOff className="h-3 w-3" /> Not Configured
      </span>
    );
  }
  
  const Icon = status === "ok" ? CheckCircle : status === "error" ? AlertCircle : Wifi;
  return (
    <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium", statusColors[status as keyof typeof statusColors] || "text-violet-400/50")}>
      <Icon className="h-3 w-3" />
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function HealthIndicator({ latency, status, lastChecked }: { latency: number | null; status: string; lastChecked: string | null }) {
  if (status === "unknown") return <span className="text-[10px] text-violet-400/40">Never checked</span>;
  if (status === "error") return <span className="text-[10px] text-ember-400">Failed</span>;
  
  return (
    <span className="text-[10px] text-violet-300/60">
      {latency !== null ? `${latency.toFixed(0)}ms` : "OK"}
      {lastChecked && ` • ${new Date(lastChecked).toLocaleString()}`}
    </span>
  );
}

export default function ProvidersSettingsPage() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const [discovering, setDiscovering] = useState<string | null>(null);
  const [models, setModels] = useState<Record<string, ModelInfo[]>>({});
  const [showModels, setShowModels] = useState<Record<string, boolean>>({});
  const [addingProvider, setAddingProvider] = useState(false);
  const [editingProvider, setEditingProvider] = useState<Provider | null>(null);
  const [formData, setFormData] = useState({
    name: "",
    provider_type: "cloud" as "cloud" | "local",
    base_url: "",
    is_enabled: true,
  });
  const [showCredentials, setShowCredentials] = useState<Record<string, boolean>>({});
  const [credentials, setCredentials] = useState<Record<string, Credential[]>>({});
  const [addingCredential, setAddingCredential] = useState<string | null>(null);
  const [credForm, setCredForm] = useState({ label: "", secret_ref: "" });

  async function loadProviders() {
    try {
      const res = await apiGet<Provider[]>("/providers?include_health=true");
      setProviders(res.data);
      setError(null);
    } catch {
      setError("Could not reach the orchestration API. Is apps/api running?");
    } finally {
      setLoading(false);
    }
  }

  async function testProvider(name: string) {
    setTesting(name);
    try {
      const res = await apiPost<TestResult>(`/providers/${name}/test`);
      setProviders(prev => prev.map(p => p.name === name ? { ...p, health_status: res.data.ok ? "ok" : "error", health_latency_ms: res.data.latency_ms, health_last_error: res.data.detail, health_last_checked: new Date().toISOString() } : p));
    } catch (e: any) {
      setError(`Test failed: ${e.message}`);
    } finally {
      setTesting(null);
    }
  }

  async function discoverProviderModels(name: string) {
    setDiscovering(name);
    try {
      const res = await apiGet<ProviderModels>(`/providers/${name}/models`);
      if (res.data.models.length > 0) {
        setModels(prev => ({ ...prev, [name]: res.data.models }));
        setShowModels(prev => ({ ...prev, [name]: true }));
      }
    } catch (e: any) {
      setError(`Model discovery failed: ${e.message}`);
    } finally {
      setDiscovering(null);
    }
  }

  async function loadCredentials(providerName: string) {
    try {
      const res = await apiGet<Credential[]>(`/providers/${providerName}/credentials`);
      setCredentials(prev => ({ ...prev, [providerName]: res.data }));
    } catch (e: any) {
      setError(`Failed to load credentials: ${e.message}`);
    }
  }

  async function handleAddCredential(providerName: string) {
    try {
      await apiPost(`/providers/${providerName}/credentials`, credForm);
      setAddingCredential(null);
      setCredForm({ label: "", secret_ref: "" });
      loadCredentials(providerName);
    } catch (e: any) {
      setError(`Failed to add credential: ${e.message}`);
    }
  }

  async function handleDeleteCredential(providerName: string, credId: string) {
    if (!confirm("Delete this credential?")) return;
    try {
      await apiDelete(`/providers/${providerName}/credentials/${credId}`);
      loadCredentials(providerName);
    } catch (e: any) {
      setError(`Failed to delete credential: ${e.message}`);
    }
  }

  async function handleAddProvider() {
    try {
      await apiPost("/providers", formData);
      setAddingProvider(false);
      setFormData({ name: "", provider_type: "cloud", base_url: "", is_enabled: true });
      loadProviders();
    } catch (e: any) {
      setError(`Failed to add provider: ${e.message}`);
    }
  }

  async function handleEditProvider(provider: Provider) {
    try {
      await apiPatch(`/providers/${provider.id}`, formData);
      setEditingProvider(null);
      loadProviders();
    } catch (e: any) {
      setError(`Failed to update provider: ${e.message}`);
    }
  }

  async function handleDeleteProvider(provider: Provider) {
    if (!confirm(`Delete provider ${provider.name} and all its credentials?`)) return;
    try {
      await apiDelete(`/providers/${provider.id}`);
      loadProviders();
    } catch (e: any) {
      setError(`Failed to delete provider: ${e.message}`);
    }
  }

  async function handleToggleProvider(provider: Provider) {
    try {
      await apiPost(`/providers/${provider.id}/${provider.is_enabled ? "disable" : "enable"}`);
      loadProviders();
    } catch (e: any) {
      setError(`Failed to toggle provider: ${e.message}`);
    }
  }

  function startAddProvider() {
    setFormData({ name: "", provider_type: "cloud", base_url: "", is_enabled: true });
    setAddingProvider(true);
  }

  function startEditProvider(provider: Provider) {
    setFormData({
      name: provider.name,
      provider_type: provider.provider_type,
      base_url: provider.base_url || "",
      is_enabled: provider.is_enabled,
    });
    setEditingProvider(provider);
  }

  function cancelForm() {
    setAddingProvider(false);
    setEditingProvider(null);
  }

  useEffect(() => {
    loadProviders();
    const interval = setInterval(loadProviders, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <DashboardShell>
      <div className="space-y-6">
        <section className="panel relative overflow-hidden p-6">
          <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-violet-950/40 via-transparent to-transparent" />
          <div className="relative flex flex-col items-center gap-2">
            <div className="flex h-14 w-14 items-center justify-center rounded-full border border-violet-500/30 bg-violet-600/10 shadow-glow-sm">
              <Server className="h-7 w-7 text-violet-300" />
            </div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.25em] text-violet-400/60">Provider Hub</p>
            <h1 className="font-display text-2xl text-violet-50">AI Provider Management</h1>
            <p className="max-w-2xl text-xs text-violet-300/60 text-center">
              Configure, test, and monitor AI providers. Add credentials, discover models, and manage routing.
            </p>
          </div>
        </section>

        {error && (
          <div className="panel border-ember-400/30 bg-ember-400/5 p-4 rounded-lg flex items-center justify-between">
            <p className="text-sm text-ember-300">{error}</p>
            <button onClick={() => setError(null)} className="text-ember-400 hover:text-ember-200">✕</button>
          </div>
        )}

        <section className="panel p-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-display text-lg text-violet-100">Registered Providers</h2>
            {!addingProvider && !editingProvider && (
              <button onClick={startAddProvider} className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-violet-100 bg-violet-600/20 border border-violet-500/30 rounded-lg hover:bg-violet-600/30">
                <Plus className="h-3.5 w-3.5" /> Add Provider
              </button>
            )}
          </div>

          {(addingProvider || editingProvider) && (
            <div className="panel bg-violet-500/5 border-violet-500/30 mb-4 p-4 space-y-3">
              <h3 className="font-medium text-violet-100">{editingProvider ? "Edit Provider" : "Add New Provider"}</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-[10px] uppercase tracking-wider text-violet-400/50 mb-1">Name</label>
                  <input
                    value={formData.name}
                    onChange={e => setFormData({ ...formData, name: e.target.value })}
                    placeholder="e.g., openai, my-custom-llm"
                    className="w-full rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 placeholder-violet-400/30 focus:border-violet-500/50 focus:outline-none"
                    required
                  />
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-wider text-violet-400/50 mb-1">Type</label>
                  <select
                    value={formData.provider_type}
                    onChange={e => setFormData({ ...formData, provider_type: e.target.value as "cloud" | "local" })}
                    className="w-full rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 focus:border-violet-500/50 focus:outline-none"
                  >
                    <option value="cloud">Cloud (API-based)</option>
                    <option value="local">Local (Ollama, vLLM, etc.)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-wider text-violet-400/50 mb-1">Base URL (optional)</label>
                  <input
                    value={formData.base_url}
                    onChange={e => setFormData({ ...formData, base_url: e.target.value })}
                    placeholder="https://api.example.com/v1"
                    className="w-full rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 placeholder-violet-400/30 focus:border-violet-500/50 focus:outline-none"
                  />
                </div>
                <div className="flex items-end">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.is_enabled}
                      onChange={e => setFormData({ ...formData, is_enabled: e.target.checked })}
                      className="h-4 w-4 rounded border-violet-500/30 text-violet-600 focus:ring-violet-500 bg-void-900/40"
                    />
                    <span className="text-sm text-violet-200">Enabled</span>
                  </label>
                </div>
              </div>
              <div className="flex gap-2 pt-2">
                <button onClick={() => editingProvider ? handleEditProvider(editingProvider) : handleAddProvider()} disabled={!formData.name} className="flex-1 px-3 py-2 text-xs font-medium text-violet-100 bg-violet-600/20 border border-violet-500/30 rounded-lg hover:bg-violet-600/30 disabled:opacity-50">
                  {editingProvider ? "Save Changes" : "Add Provider"}
                </button>
                <button onClick={cancelForm} className="px-3 py-2 text-xs font-medium text-violet-300/60 hover:text-violet-100">
                  Cancel
                </button>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {providers.map(p => (
              <div key={p.id} className="panel relative p-4 space-y-3">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-violet-500/20 bg-violet-600/10">
                      {providerIcons[p.name] || <Server className="h-5 w-5 text-violet-400" />}
                    </div>
                    <div>
                      <h3 className="font-medium text-violet-100">{p.name}</h3>
                      <p className="text-[10px] uppercase tracking-wider text-violet-400/50">{p.provider_type}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <StatusBadge status={p.health_status} configured={p.configured} />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[10px]">
                  <div>
                    <span className="text-violet-400/40">Status:</span>
                    <HealthIndicator latency={p.health_latency_ms} status={p.health_status} lastChecked={p.health_last_checked} />
                  </div>
                  <div>
                    <span className="text-violet-400/40">Enabled:</span>
                    <span className={cn("font-medium", p.is_enabled ? "text-signal-green" : "text-ember-400")}>
                      {p.is_enabled ? "Yes" : "No"}
                    </span>
                  </div>
                  {p.base_url && (
                    <div className="col-span-2 truncate">
                      <span className="text-violet-400/40">Base URL:</span>
                      <span className="text-violet-300/60 ml-1">{p.base_url}</span>
                    </div>
                  )}
                  {p.health_last_error && (
                    <div className="col-span-2 truncate text-ember-400/80">
                      Error: {p.health_last_error}
                    </div>
                  )}
                </div>

                <div className="flex flex-wrap gap-2 pt-2 border-t border-violet-500/10">
                  <button
                    onClick={() => testProvider(p.name)}
                    disabled={testing === p.name || !p.configured}
                    className={cn(
                      "flex-1 flex items-center justify-center gap-1 px-2 py-1.5 text-[10px] font-medium rounded-lg border transition-colors",
                      testing === p.name
                        ? "bg-violet-500/10 border-violet-500/30 text-violet-400"
                        : !p.configured
                        ? "border-violet-500/10 text-violet-400/40 cursor-not-allowed"
                        : "bg-violet-500/10 border-violet-500/20 text-violet-300 hover:bg-violet-500/20"
                    )}
                  >
                    {testing === p.name ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                    {testing === p.name ? "Testing..." : "Test"}
                  </button>
                  <button
                    onClick={() => {
                      setShowModels(prev => ({ ...prev, [p.name]: !showModels[p.name] }));
                      if (!showModels[p.name] && !models[p.name]) {
                        discoverProviderModels(p.name);
                      }
                    }}
                    disabled={discovering === p.name || !p.configured}
                    className={cn(
                      "flex-1 flex items-center justify-center gap-1 px-2 py-1.5 text-[10px] font-medium rounded-lg border transition-colors",
                      discovering === p.name
                        ? "bg-violet-500/10 border-violet-500/30 text-violet-400"
                        : !p.configured
                        ? "border-violet-500/10 text-violet-400/40 cursor-not-allowed"
                        : "bg-violet-500/10 border-violet-500/20 text-violet-300 hover:bg-violet-500/20"
                    )}
                  >
                    {discovering === p.name ? <Loader2 className="h-3 w-3 animate-spin" /> : <Sparkles className="h-3 w-3" />}
                    {discovering === p.name ? "Discovering..." : "Models"}
                  </button>
                  <button
                    onClick={() => {
                      setShowCredentials(prev => ({ ...prev, [p.name]: !showCredentials[p.name] }));
                      if (!showCredentials[p.name]) loadCredentials(p.name);
                    }}
                    className="flex-1 flex items-center justify-center gap-1 px-2 py-1.5 text-[10px] font-medium rounded-lg border bg-violet-500/10 border-violet-500/20 text-violet-300 hover:bg-violet-500/20 transition-colors"
                  >
                    <Key className="h-3 w-3" /> Creds
                  </button>
                  {!editingProvider && !addingProvider && (
                    <button
                      onClick={() => handleToggleProvider(p)}
                      className={cn(
                        "flex-1 flex items-center justify-center gap-1 px-2 py-1.5 text-[10px] font-medium rounded-lg border transition-colors",
                        p.is_enabled
                          ? "bg-ember-400/10 border-ember-400/30 text-ember-400 hover:bg-ember-400/20"
                          : "bg-signal-green/10 border-signal-green/30 text-signal-green hover:bg-signal-green/20"
                      )}
                    >
                      {p.is_enabled ? "Disable" : "Enable"}
                    </button>
                  )}
                  {!editingProvider && !addingProvider && (
                    <button
                      onClick={() => startEditProvider(p)}
                      className="flex-1 flex items-center justify-center gap-1 px-2 py-1.5 text-[10px] font-medium rounded-lg border bg-violet-500/10 border-violet-500/20 text-violet-300 hover:bg-violet-500/20 transition-colors"
                    >
                      <Edit className="h-3 w-3" />
                    </button>
                  )}
                  {!editingProvider && !addingProvider && (
                    <button
                      onClick={() => handleDeleteProvider(p)}
                      className="flex-1 flex items-center justify-center gap-1 px-2 py-1.5 text-[10px] font-medium rounded-lg border bg-ember-400/10 border-ember-400/30 text-ember-400 hover:bg-ember-400/20 transition-colors"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  )}
                </div>

                {showModels[p.name] && (
                  <div className="mt-3 pt-3 border-t border-violet-500/10 space-y-2">
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-violet-400/50 uppercase tracking-wider">Discovered Models ({models[p.name]?.length || 0})</span>
                      <button onClick={() => setShowModels(prev => ({ ...prev, [p.name]: false }))} className="text-violet-400/50 hover:text-violet-200">Hide</button>
                    </div>
                    <div className="max-h-48 overflow-y-auto space-y-1">
                      {models[p.name]?.map(m => (
                        <div key={m.id} className="text-[10px] p-2 rounded bg-void-900/40 border border-violet-500/10 flex flex-wrap gap-2 items-center">
                          <span className="font-medium text-violet-100">{m.id}</span>
                          {m.context_window && <span className="text-violet-400/40">Ctx: {m.context_window.toLocaleString()}</span>}
                          <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-medium", m.supports_tools ? "bg-green-500/20 text-green-400" : "bg-violet-500/10 text-violet-400/50")}>
                            {m.supports_tools ? "Tools" : "No Tools"}
                          </span>
                          <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-medium", m.supports_vision ? "bg-blue-500/20 text-blue-400" : "bg-violet-500/10 text-violet-400/50")}>
                            {m.supports_vision ? "Vision" : "No Vision"}
                          </span>
                          {m.input_price_per_1m && m.output_price_per_1m && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-medium bg-amber-500/20 text-amber-400">
                              ${m.input_price_per_1m}/${m.output_price_per_1m} per 1M
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {showCredentials[p.name] && (
                  <div className="mt-3 pt-3 border-t border-violet-500/10 space-y-2">
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-violet-400/50 uppercase tracking-wider">Credentials</span>
                      {addingCredential === p.name ? (
                        <button onClick={() => setAddingCredential(null)} className="text-violet-400/50 hover:text-violet-200">Cancel</button>
                      ) : (
                        <button onClick={() => setAddingCredential(p.name)} className="text-violet-400 hover:text-violet-200">+ Add</button>
                      )}
                    </div>
                    
                    {addingCredential === p.name && (
                      <div className="panel bg-violet-500/5 border-violet-500/20 p-3 space-y-2">
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          <input
                            value={credForm.label}
                            onChange={e => setCredForm({ ...credForm, label: e.target.value })}
                            placeholder="Label (e.g., Production Key)"
                            className="rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 placeholder-violet-400/30 focus:border-violet-500/50 focus:outline-none"
                          />
                          <input
                            value={credForm.secret_ref}
                            onChange={e => setCredForm({ ...credForm, secret_ref: e.target.value })}
                            placeholder="env:OPENAI_API_KEY or vault:providers/openai"
                            className="rounded-lg border border-violet-500/20 bg-void-900/40 px-3 py-2 text-sm text-violet-100 placeholder-violet-400/30 focus:border-violet-500/50 focus:outline-none"
                          />
                        </div>
                        <div className="flex gap-2">
                          <button onClick={() => handleAddCredential(p.name)} className="flex-1 px-3 py-2 text-xs font-medium text-violet-100 bg-violet-600/20 border border-violet-500/30 rounded-lg hover:bg-violet-600/30">
                            Add Credential
                          </button>
                          <button onClick={() => setAddingCredential(null)} className="px-3 py-2 text-xs font-medium text-violet-300/60 hover:text-violet-100">Cancel</button>
                        </div>
                      </div>
                    )}
                    
                    {credentials[p.name]?.length === 0 && !addingCredential && (
                      <p className="text-center text-[10px] text-violet-400/40 py-2">No credentials configured</p>
                    )}
                    
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                      {credentials[p.name]?.map(c => (
                        <div key={c.id} className="text-[10px] p-2 rounded bg-void-900/40 border border-violet-500/10 flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 flex-1 min-w-0">
                            <span className={cn("font-medium truncate", c.is_active ? "text-signal-green" : "text-violet-400/50")}>
                              {c.label}
                            </span>
                            <span className="text-violet-400/40 font-mono">{c.masked_preview || "••••"}</span>
                            <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-medium", c.is_active ? "bg-signal-green/20 text-signal-green" : "bg-violet-500/10 text-violet-400/50")}>
                              {c.is_active ? "Active" : "Inactive"}
                            </span>
                          </div>
                          <div className="flex gap-1">
                            <button
                              onClick={() => handleDeleteCredential(p.name, c.id)}
                              className="p-1 text-ember-400/60 hover:text-ember-300 hover:bg-ember-400/10 rounded"
                              title="Delete"
                            >
                              <Trash2 className="h-3 w-3" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>

          {!loading && providers.length === 0 && !addingProvider && !editingProvider && (
            <div className="text-center py-12">
              <Server className="h-12 w-12 mx-auto text-violet-400/30 mb-4" />
              <p className="text-violet-400/50">No providers configured yet</p>
              <p className="text-xs text-violet-400/30 mt-1">Click &quot;Add Provider&quot; to get started</p>
            </div>
          )}
        </section>
      </div>
    </DashboardShell>
  );
}