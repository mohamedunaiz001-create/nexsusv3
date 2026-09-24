"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, Loader2 } from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/utils";

type HistoryEntry = { task_description: string; run_at: string; result: any };

type AgentDetail = {
  agent_type: string;
  name: string;
  model: string;
  description: string;
  status: string;
  enabled: boolean;
  last_run_at: string | null;
  last_error: string | null;
  run_count: number;
  last_task_description: string | null;
  last_result: { agent?: string; provider?: string; model?: string; content?: string; structured?: any } | null;
  history: HistoryEntry[];
};

const statusTone: Record<string, string> = {
  idle: "text-violet-400/50",
  running: "text-signal-amber",
  completed: "text-signal-green",
  failed: "text-ember-400",
};

function confidenceOf(structured: any): number | null {
  if (!structured) return null;
  if (typeof structured.confidence === "number") return structured.confidence;
  if (typeof structured.risk_score === "number") return structured.risk_score;
  return null;
}

export default function AgentDetailPage() {
  const params = useParams<{ agentType: string }>();
  const agentType = params.agentType;
  const [detail, setDetail] = useState<AgentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    try {
      const res = await apiGet<AgentDetail>(`/agents/${agentType}`);
      setDetail(res.data);
      setError(null);
    } catch {
      setError("Could not reach the orchestration API, or this agent isn't registered.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 4000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agentType]);

  const confidence = confidenceOf(detail?.last_result?.structured);

  return (
    <DashboardShell>
      <Link href="/agents" className="mb-4 flex items-center gap-1 text-xs text-violet-400/60 hover:text-violet-200">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to Agent Center
      </Link>

      {loading && !detail && <Loader2 className="h-5 w-5 animate-spin text-violet-400/50" />}
      {error && <p className="text-xs text-ember-400">{error}</p>}

      {detail && (
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-[1fr_320px]">
          <div className="space-y-5">
            <section className="panel p-5">
              <div className="flex items-start justify-between">
                <div>
                  <h1 className="font-display text-xl text-violet-50">{detail.name}</h1>
                  <p className="mt-1 text-xs text-violet-400/50">{detail.description}</p>
                </div>
                <span className={cn("flex items-center gap-1 text-xs font-medium", statusTone[detail.status] ?? "text-violet-400/50")}>
                  <span className="status-dot bg-current" /> {detail.status}
                </span>
              </div>

              <dl className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-4">
                {[
                  ["Assigned Model", detail.model],
                  ["Enabled", detail.enabled ? "Yes" : "No"],
                  ["Run Count", String(detail.run_count)],
                  ["Confidence", confidence !== null ? confidence.toFixed(2) : "—"],
                ].map(([label, value]) => (
                  <div key={label}>
                    <dt className="text-[10px] uppercase tracking-wider text-violet-400/50">{label}</dt>
                    <dd className="text-sm font-medium text-violet-100">{value}</dd>
                  </div>
                ))}
              </dl>
            </section>

            <section className="panel p-5">
              <p className="panel-title">Current / Last Task</p>
              <p className="mt-2 text-xs text-violet-200/70">
                {detail.last_task_description ?? "No task has been assigned yet."}
              </p>
              {detail.last_error && <p className="mt-2 text-xs text-ember-400">{detail.last_error}</p>}
            </section>

            <section className="panel p-5">
              <p className="panel-title">Output</p>
              <pre className="mt-2 max-h-64 overflow-y-auto whitespace-pre-wrap text-xs leading-relaxed text-violet-200/80">
                {detail.last_result?.content ?? "No output yet."}
              </pre>
            </section>

            <section className="panel p-5">
              <p className="panel-title">Tool Usage / Structured Findings</p>
              <pre className="mt-2 max-h-64 overflow-y-auto whitespace-pre-wrap text-[10px] leading-relaxed text-violet-300/60">
                {detail.last_result?.structured
                  ? JSON.stringify(detail.last_result.structured, null, 2)
                  : "No structured findings yet."}
              </pre>
            </section>
          </div>

          <section className="panel">
            <div className="panel-header">
              <p className="panel-title">History</p>
            </div>
            <ul className="max-h-[75vh] space-y-3 overflow-y-auto px-4 py-3">
              {detail.history.length === 0 && <p className="text-xs text-violet-400/40">No runs yet.</p>}
              {detail.history.map((h, i) => (
                <li key={i} className="rounded-lg border border-violet-500/10 bg-void-900/40 p-2 text-xs">
                  <p className="text-[10px] text-violet-400/40">{new Date(h.run_at).toLocaleString()}</p>
                  <p className="mt-1 text-violet-200/70">{h.task_description}</p>
                  {h.result?.content && (
                    <p className="mt-1 truncate text-violet-400/50">{h.result.content}</p>
                  )}
                </li>
              ))}
            </ul>
          </section>
        </div>
      )}
    </DashboardShell>
  );
}
