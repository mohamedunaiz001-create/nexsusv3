"use client";

import { useEffect, useRef, useState } from "react";
import { Loader2, Paperclip, Send, X } from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { submitObjective, orchestrationEventsUrl } from "@/lib/api";
import { KNOWN_EVENT_TYPES, type OrchestrationEvent } from "@/components/orchestration/eventTypes";
import { cn } from "@/lib/utils";

type TaskRead = {
  id: string;
  description: string;
  assigned_agent: string | null;
  status: string;
  attempts: number;
  error: string | null;
  result: { agent?: string; provider?: string; model?: string; content?: string; structured?: any } | null;
};

type RunRead = {
  id: string;
  objective: string;
  status: string;
  final_report: string | null;
  error: string | null;
  tasks: TaskRead[];
};

const stateTone: Record<string, string> = {
  queued: "text-violet-400/50",
  running: "text-signal-amber",
  completed: "text-signal-green",
  verified: "text-signal-green",
  delivered: "text-signal-green",
  failed: "text-ember-400",
};

export default function CeoChatPage() {
  const [objective, setObjective] = useState("Analyze malware.exe");
  const [file, setFile] = useState<File | null>(null);
  const [running, setRunning] = useState(false);
  const [run, setRun] = useState<RunRead | null>(null);
  const [events, setEvents] = useState<OrchestrationEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const sourceRef = useRef<EventSource | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    let source: EventSource;
    try {
      source = new EventSource(orchestrationEventsUrl());
      sourceRef.current = source;
      const handler = (evt: MessageEvent) => {
        try {
          const payload = JSON.parse(evt.data);
          setEvents((prev) => [{ type: evt.type, ...payload }, ...prev].slice(0, 100));
        } catch {
          /* ignore malformed frames */
        }
      };
      for (const type of KNOWN_EVENT_TYPES) source.addEventListener(type, handler as any);
      source.onerror = () => {
        // Backend unreachable — the page still renders; live events simply
        // won't stream until apps/api is running.
      };
    } catch {
      /* EventSource unavailable in this environment */
    }
    return () => sourceRef.current?.close();
  }, []);

  async function handleSubmit() {
    if (!objective.trim()) return;
    setRunning(true);
    setError(null);
    setRun(null);
    try {
      const res = await submitObjective(objective, file);
      setRun(res.data as RunRead);
    } catch (err) {
      setError(`Delegation failed: ${(err as Error).message}. Is the API running (apps/api) with the specialists registered?`);
    } finally {
      setRunning(false);
    }
  }

  const reportTask = run?.tasks.find((t) => t.assigned_agent === "report_generator");

  return (
    <DashboardShell>
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[1fr_360px]">
        <div className="space-y-5">
          <section className="panel p-5">
            <p className="panel-title">CEO AI Chat — Delegate an Objective</p>
            <div className="mt-3 flex flex-col gap-2">
              <textarea
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
                rows={2}
                placeholder="e.g. Analyze malware.exe / Analyze capture.pcap / Review server.py for vulnerabilities"
                className="w-full resize-none rounded-lg border border-violet-500/20 bg-void-900/60 px-3 py-2 text-sm text-violet-100 placeholder:text-violet-400/40 focus:outline-none"
              />
              <div className="flex items-center gap-2">
                <input
                  ref={fileInputRef}
                  type="file"
                  className="hidden"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="flex items-center gap-2 rounded-lg border border-violet-500/20 px-3 py-2 text-xs text-violet-200/70 hover:bg-violet-500/10"
                >
                  <Paperclip className="h-3.5 w-3.5" />
                  {file ? file.name : "Attach a file (.exe, .pcap, .py, ...)"}
                </button>
                {file && (
                  <button onClick={() => setFile(null)} className="text-violet-400/50 hover:text-ember-400">
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
                <button
                  onClick={handleSubmit}
                  disabled={running}
                  className="ml-auto flex items-center gap-2 rounded-lg bg-violet-600/90 px-4 py-2 text-sm font-medium text-white shadow-glow-sm transition hover:bg-violet-600 disabled:opacity-50"
                >
                  {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                  Delegate to CEO
                </button>
              </div>
              <p className="text-[10px] text-violet-400/40">
                The CEO plans a task pipeline, delegates to specialist agents (in parallel where possible),
                verifies results, and compiles a report — matching the file/objective you give it.
              </p>
            </div>
          </section>

          {error && (
            <section className="panel border-ember-500/30 p-5">
              <p className="text-xs text-ember-400">{error}</p>
            </section>
          )}

          {run && (
            <section className="panel p-5">
              <div className="flex items-center justify-between">
                <p className="panel-title">Execution Graph</p>
                <span className={cn("text-xs font-medium", stateTone[run.status] ?? "text-violet-400/50")}>
                  &bull; {run.status}
                </span>
              </div>
              <ol className="mt-3 space-y-2">
                {run.tasks.map((t, i) => (
                  <li key={t.id} className="rounded-lg border border-violet-500/10 bg-void-900/40 px-3 py-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <span className="flex h-5 w-5 items-center justify-center rounded-full border border-violet-500/30 text-[10px] text-violet-300">
                          {i + 1}
                        </span>
                        <span className="text-violet-100">{(t.assigned_agent ?? "?").replace(/_/g, " ")}</span>
                      </span>
                      <span className={cn("font-medium", stateTone[t.status] ?? "text-violet-400/50")}>
                        &bull; {t.status}
                      </span>
                    </div>
                    {t.result?.content && (
                      <p className="mt-2 whitespace-pre-wrap text-violet-300/70">
                        {t.result.content.slice(0, 300)}
                        {t.result.content.length > 300 ? "…" : ""}
                      </p>
                    )}
                    {t.error && <p className="mt-1 text-ember-400/80">{t.error}</p>}
                  </li>
                ))}
              </ol>
            </section>
          )}

          {reportTask?.result?.content && (
            <section className="panel p-5">
              <p className="panel-title">Investigation Report</p>
              <pre className="mt-2 max-h-[50vh] overflow-y-auto whitespace-pre-wrap text-xs leading-relaxed text-violet-200/80">
                {reportTask.result.content}
              </pre>
            </section>
          )}
        </div>

        <section className="panel">
          <div className="panel-header">
            <p className="panel-title">Live Delegation Feed</p>
          </div>
          <ul className="max-h-[75vh] space-y-2 overflow-y-auto px-4 py-3">
            {events.length === 0 && (
              <p className="text-xs text-violet-400/40">Waiting for orchestration events...</p>
            )}
            {events.map((e, i) => (
              <li key={i} className="text-xs">
                <p className="text-[10px] text-violet-400/40">
                  {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : ""}
                </p>
                <p className="text-violet-200/80">
                  {e.type}
                  {e.agent_type ? ` — ${String(e.agent_type).replace(/_/g, " ")}` : ""}
                </p>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </DashboardShell>
  );
}
