import React from "react";
import { agentPerformance } from "@/lib/mock-data";
import { BarChart3 } from "lucide-react";

export function AgentPerformance() {
  return (
    <section className="relative rounded-xl border border-violet-500/25 bg-[#090514]/90 shadow-[0_4px_24px_-4px_rgba(147,51,234,0.2)] backdrop-blur-md">
      <div className="flex items-center justify-between border-b border-violet-500/15 px-4 py-3">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-3.5 w-3.5 text-violet-400" />
          <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-violet-300">
            Agent Performance
          </p>
        </div>
        <button
          onClick={() => {
            if (typeof window !== "undefined") {
              window.history.pushState({}, "", "/analytics");
              window.dispatchEvent(new PopStateEvent("popstate"));
            }
          }}
          className="text-[10px] font-medium text-violet-400 hover:text-violet-200 transition-colors cursor-pointer"
        >
          View Analytics
        </button>
      </div>

      <div className="overflow-x-auto max-h-[200px] overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-[#090514]">
            <tr className="text-left text-[9px] uppercase tracking-wider text-violet-400/50 border-b border-violet-500/10">
              <th className="px-4 py-2 font-medium">Agent</th>
              <th className="px-2 py-2 font-medium">Tasks</th>
              <th className="px-2 py-2 font-medium">Success</th>
              <th className="px-2 py-2 font-medium">Avg. Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-violet-500/10">
            {agentPerformance.map((row) => (
              <tr key={row.agent} className="text-violet-200/80 hover:bg-[#12082b]/40 transition-colors">
                <td className="px-4 py-1.5 font-medium text-violet-100 truncate max-w-[130px]">{row.agent}</td>
                <td className="px-2 py-1.5 font-mono text-violet-300">{row.tasks}</td>
                <td className="px-2 py-1.5 font-mono font-semibold text-emerald-400">{row.success}%</td>
                <td className="px-2 py-1.5 font-mono text-violet-400/70">{row.avgTime}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
