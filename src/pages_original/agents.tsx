"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Crown, Loader2 } from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { apiGet, apiPost } from "@/lib/api";
import { cn } from "@/lib/utils";

type AgentSnapshot = {
  agent_type: string;
  name: string;
  model: string;
  status: string;
  enabled: boolean;
  last_run_at: string | null;
  last_error: string | null;
  run_count: number;
};

const statusTone: Record<string, string> = {
  idle: "text-violet-400/50",
  running: "text-signal-amber",
  completed: "text-signal-green",
  failed: "text-ember-400",
};

export default function AgentCenterPage() {
  const [agents, setAgents] = useState<AgentSnapshot[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    try {
      const res = await apiGet<AgentSnapshot[]>("/agents");
      setAgents(res.data);
      setError(null);
    } catch {
      setError("Could not reach the orchestration API. Is apps/api running?");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 4000);
    return () => clearInterval(interval);
  }, []);

  async function toggle(agentType: string, enabled: boolean) {
    await apiPost(`/agents/${agentType}/${enabled ? "disable" : "enable"}`);
    load();
  }

  return (
    <DashboardShell>
      <div className="space-y-6">
        <section className="panel relative overflow-hidden p-6 text-center">
          <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-violet-950/40 via-transparent to-transparent" />
          <div className="relative flex flex-col items-center gap-2">
            <div className="flex h-14 w-14 items-center justify-center rounded-full border border-violet-500/30 bg-violet-600/10 shadow-glow-sm">
              <Crown className="h-6 w-6 text-violet-300" />
            </div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.25em] text-violet-400/60">CEO Agent</p>
            <h1 className="font-display text-2xl text-violet-50">ARCHON</h1>
            <p className="max-w-md text-xs text-violet-300/60">
              Plans, delegates, and verifies work across every specialist below. Delegate a new
              objective from CEO AI Chat.
            </p>
          </div>
          {/* connector line down to the grid */}
          <div className="relative mx-auto mt-4 h-6 w-px animate-pulse bg-gradient-to-b from-violet-500/60 to-transparent" />
        </section>

        <section>
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-[0.25em] text-violet-400/50">
              Specialist Agents
            </p>
            {loading && <Loader2 className="h-3.5 w-3.5 animate-spin text-violet-400/50" />}
          </div>
          {error && <p className="mb-3 text-xs text-ember-400">{error}</p>}

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {agents.map((a) => (
              <div key={a.agent_type} className="panel relative flex flex-col p-4">
                {/* connector line up to the CEO */}
                <div className="absolute -top-4 left-1/2 h-4 w-px -translate-x-1/2 bg-violet-500/30" />
                <Link href={`/agents/${a.agent_type}`} className="text-sm font-medium text-violet-100 hover:text-violet-300">
                  {a.name}
                </Link>
                <p className="mt-1 text-[10px] text-violet-400/40">{a.model}</p>
                <div className="mt-3 flex items-center justify-between text-xs">
                  <span className={cn("flex items-center gap-1 font-medium", statusTone[a.status] ?? "text-violet-400/50")}>
                    <span className="status-dot bg-current" /> {a.status}
                  </span>
                  <span className="text-violet-400/40">{a.run_count} run(s)</span>
                </div>
                {a.last_error && <p className="mt-2 truncate text-[10px] text-ember-400/80">{a.last_error}</p>}
                <div className="mt-3 flex items-center gap-2">
                  <Link
                    href={`/agents/${a.agent_type}`}
                    className="flex-1 rounded-lg border border-violet-500/20 px-2 py-1.5 text-center text-[10px] text-violet-200/70 hover:bg-violet-500/10"
                  >
                    View Detail
                  </Link>
                  <button
                    onClick={() => toggle(a.agent_type, a.enabled)}
                    className="rounded-lg border border-violet-500/20 px-2 py-1.5 text-[10px] text-violet-200/70 hover:bg-violet-500/10"
                  >
                    {a.enabled ? "Disable" : "Enable"}
                  </button>
                </div>
              </div>
            ))}
            {!loading && agents.length === 0 && !error && (
              <p className="col-span-full text-center text-xs text-violet-400/40">No agents registered.</p>
            )}
          </div>
        </section>
      </div>
    </DashboardShell>
  );
}
