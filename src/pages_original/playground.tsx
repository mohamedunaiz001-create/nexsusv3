"use client";

import { useEffect, useState } from "react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { apiGet, apiPost, apiUrl } from "@/lib/api";

type Model = { provider: string; model: string };
type Response = Model & { id: string; content: string; status: string; error?: string; latency_ms?: number; tokens_prompt?: number; tokens_completion?: number; estimated_cost_usd?: number };
const presets: Model[] = [{ provider: "openai", model: "gpt-4o-mini" }, { provider: "anthropic", model: "claude-3-5-haiku-latest" }, { provider: "gemini", model: "gemini-1.5-flash" }];

export default function PlaygroundPage() {
  const [prompt, setPrompt] = useState("Analyze this cybersecurity evidence. Identify IOCs, likely behavior, MITRE ATT&CK mappings, confidence, and prioritized mitigations.");
  const [models, setModels] = useState<Model[]>([presets[0]!]); const [provider, setProvider] = useState("openai"); const [model, setModel] = useState("gpt-4o-mini");
  const [temperature, setTemperature] = useState(0.2); const [maxTokens, setMaxTokens] = useState(2000); const [running, setRunning] = useState(false); const [sessionId, setSessionId] = useState<string>(); const [responses, setResponses] = useState<Response[]>([]); const [error, setError] = useState(""); const [history, setHistory] = useState<any[]>([]); const [fileIds, setFileIds] = useState<string[]>([]); const [catalog, setCatalog] = useState<Model[]>(presets);
  const canRun = prompt.trim() && models.length > 0 && !running;
  const loadHistory = () => apiGet<any[]>("/playground").then(r => setHistory(r.data)).catch(() => {});
  useEffect(() => { loadHistory(); apiGet<any[]>("/providers/models/all").then(r => { const discovered = r.data.flatMap((p: any) => (p.models || []).map((m: any) => ({ provider: p.provider, model: m.id }))); if (discovered.length) { setCatalog(discovered); setProvider(discovered[0].provider); setModel(discovered[0].model); } }).catch(() => {}); }, []);
  useEffect(() => { if (!sessionId || !running) return; const es = new EventSource(apiUrl(`/playground/${sessionId}/stream`)); es.onmessage = e => { const x = JSON.parse(e.data); if (x.type === "model_token") setResponses(old => old.map(r => r.id === x.response_id ? { ...r, content: x.content, status: "streaming" } : r)); if (x.type === "model_completed" || x.type === "model_error") setResponses(old => old.map(r => r.id === x.response_id ? { ...r, ...x, status: x.type === "model_error" ? "error" : "completed" } : r)); if (x.type === "model_stopped") setResponses(old => old.map(r => r.id === x.response_id ? { ...r, content: x.content, status: "stopped" } : r)); if (x.type === "run_completed") { setRunning(false); es.close(); loadHistory(); } }; return () => es.close(); }, [sessionId, running]);
  async function inspectFile(file?: File) { if (!file) return; try { const form = new FormData(); form.append("file", file); const res = await fetch(apiUrl("/files/analyze"), { method: "POST", body: form }); if (!res.ok) throw new Error(await res.text()); const result = await res.json(); const e = result.data; setFileIds(ids => [...ids, e.id]); setPrompt(p => `${p}\n\nSAFE EVIDENCE METADATA\nFile: ${e.filename}\nSHA-256: ${e.sha256}\nSize: ${e.size_bytes} bytes\n${e.text_preview ? `Text preview (untrusted):\n${e.text_preview}` : "Binary sample: metadata only; it was not executed or extracted."}`); } catch (e: any) { setError(e.message); } }
  async function run() { setError(""); try { const created = await apiPost<any>("/playground", { name: `Investigation ${new Date().toLocaleString()}`, prompt, model_configs: models, temperature, max_tokens: maxTokens, file_ids: fileIds }); const id = created.data.id; const run = await apiPost<any>(`/playground/${id}/run`); setSessionId(id); setResponses(models.map((m, i) => ({ ...m, id: String(run.data.response_ids[i]), content: "", status: "streaming" }))); setRunning(true); } catch (e: any) { setError(e.message); } }
  async function stop() { if (sessionId) { await apiPost(`/playground/${sessionId}/stop`); setRunning(false); setResponses(old => old.map(r => r.status === "streaming" ? { ...r, status: "stopped" } : r)); } }
  function addModel() { if (models.length < 8 && !models.some(m => m.provider === provider && m.model === model)) setModels([...models, { provider, model }]); }
  return (
    <DashboardShell>
      <main className="mx-auto max-w-7xl space-y-5 p-2">
        <header>
          <p className="text-xs tracking-[.25em] text-violet-400">MULTI-MODEL INVESTIGATION</p>
          <h1 className="text-3xl font-semibold">AI Playground</h1>
          <p className="text-sm text-violet-200/60">Run the same evidence against 1–8 selected models. Each response completes independently.</p>
        </header>
        {error && <div className="rounded border border-red-500/50 bg-red-500/10 p-3 text-sm text-red-200">{error}</div>}
        <section className="grid gap-5 lg:grid-cols-[1.1fr_.9fr]">
          <div className="panel p-4 space-y-4">
            <label className="panel-title">Investigation prompt</label>
            <textarea className="min-h-48 w-full rounded-lg border border-violet-500/20 bg-black/20 p-3 text-sm outline-none focus:border-violet-400" value={prompt} onChange={e => setPrompt(e.target.value)} />
            <div className="grid grid-cols-2 gap-3">
              <label className="text-xs text-violet-200/70">Temperature <input className="mt-1 w-full" type="range" min="0" max="2" step=".1" value={temperature} onChange={e => setTemperature(+e.target.value)} /><span>{temperature}</span></label>
              <label className="text-xs text-violet-200/70">Max tokens <input className="mt-1 w-full rounded bg-black/30 p-2" type="number" min="1" max="8192" value={maxTokens} onChange={e => setMaxTokens(+e.target.value)} /></label>
            </div>
            <div className="flex gap-2">
              <button disabled={!canRun} onClick={run} className="rounded bg-violet-600 px-4 py-2 text-sm disabled:opacity-40">Run {models.length} model{models.length !== 1 ? "s" : ""}</button>
              {running && <button onClick={stop} className="rounded border border-red-400/60 px-4 py-2 text-sm text-red-200">Stop</button>}
              {sessionId && <a className="rounded border border-violet-400/40 px-4 py-2 text-sm" href={apiUrl(`/playground/${sessionId}/export?format=markdown`)}>Export MD</a>}
            </div>
          </div>
          <aside className="panel p-4 space-y-3">
            <p className="panel-title">Selected models ({models.length}/8)</p>
            <div className="flex gap-2">
              <input className="w-1/2 rounded bg-black/30 p-2 text-sm" value={provider} onChange={e => setProvider(e.target.value)} placeholder="provider"/>
              <input className="w-1/2 rounded bg-black/30 p-2 text-sm" value={model} onChange={e => setModel(e.target.value)} placeholder="model"/>
              <button onClick={addModel} className="rounded bg-violet-600 px-3">+</button>
            </div>
            {models.map(m => (
              <div key={`${m.provider}:${m.model}`} className="flex items-center justify-between rounded bg-white/5 p-2 text-sm">
                <span>{m.provider}:{m.model}</span>
                <button onClick={() => setModels(models.filter(x => x !== m))} className="text-red-300">Remove</button>
              </div>
            ))}
            <label className="block rounded border border-dashed border-violet-400/40 p-3 text-xs text-violet-100/70">Attach safe evidence
              <input className="mt-2 block w-full text-xs" type="file" onChange={e => inspectFile(e.target.files?.[0])}/>
            </label>
            <p className="pt-2 text-xs text-violet-200/45">Text is previewed with a size cap. Binary samples are SHA-256 hashed only—never executed or extracted.</p>
          </aside>
        </section>
        <section className="space-y-3">
          <h2 className="panel-title">Live responses</h2>
          <div className="grid gap-4 md:grid-cols-2">
            {responses.map(r => (
              <article key={r.id} className="panel overflow-hidden">
                <div className="panel-header">
                  <span>{r.provider}:{r.model}</span>
                  <span className={r.status === "completed" ? "text-emerald-300" : r.status === "error" ? "text-red-300" : "text-amber-300"}>{r.status}</span>
                </div>
                <div className="min-h-32 whitespace-pre-wrap p-4 text-sm text-violet-100/85">{r.error || r.content || "Waiting for provider…"}</div>
                <footer className="border-t border-violet-500/10 p-3 text-xs text-violet-200/50">{r.latency_ms ? `${Math.round(r.latency_ms)}ms · ` : ""}{r.tokens_prompt || 0} in / {r.tokens_completion || 0} out {r.estimated_cost_usd ? `· $${r.estimated_cost_usd.toFixed(5)}` : ""}</footer>
              </article>
            ))}
          </div>
        </section>
        <section className="panel p-4">
          <h2 className="panel-title mb-3">Session history</h2>
          {history.slice(0, 8).map(h => (
            <div className="flex justify-between border-t border-violet-500/10 py-2 text-sm" key={h.id}>
              <span>{h.name} · {h.model_count} models</span>
              <span>{h.status}</span>
            </div>
          ))}
        </section>
      </main>
    </DashboardShell>
  );
}
