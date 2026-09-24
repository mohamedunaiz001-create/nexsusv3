import React from "react";
import { recentCases } from "@/lib/mock-data";
import { cn } from "@/lib/utils";
import { FolderGit2 } from "lucide-react";

const statusTone: Record<string, string> = {
  "In Progress": "text-amber-400",
  Completed: "text-emerald-400",
  High: "text-rose-400",
  Low: "text-violet-400/70",
};

export function RecentCases() {
  return (
    <section className="relative rounded-xl border border-violet-500/25 bg-[#090514]/90 shadow-[0_4px_24px_-4px_rgba(147,51,234,0.2)] backdrop-blur-md">
      <div className="flex items-center justify-between border-b border-violet-500/15 px-4 py-3">
        <div className="flex items-center gap-2">
          <FolderGit2 className="h-3.5 w-3.5 text-violet-400" />
          <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-violet-300">
            Recent Cases
          </p>
        </div>
        <button
          onClick={() => {
            if (typeof window !== "undefined") {
              window.history.pushState({}, "", "/cases");
              window.dispatchEvent(new PopStateEvent("popstate"));
            }
          }}
          className="text-[10px] font-medium text-violet-400 hover:text-violet-200 transition-colors cursor-pointer"
        >
          View All
        </button>
      </div>

      <ul className="divide-y divide-violet-500/10">
        {recentCases.map((c) => (
          <li
            key={c.id}
            onClick={() => {
              if (typeof window !== "undefined") {
                window.history.pushState({}, "", "/cases");
                window.dispatchEvent(new PopStateEvent("popstate"));
              }
            }}
            className="flex items-center justify-between px-4 py-2.5 text-xs transition hover:bg-[#12082b]/50 cursor-pointer"
          >
            <div>
              <p className="font-mono font-semibold text-violet-100">{c.id}</p>
              <p className="text-[11px] text-violet-300/70">{c.title}</p>
            </div>
            <span className={cn("font-medium text-[11px] flex items-center gap-1", statusTone[c.status])}>
              <span className={cn(
                "h-1.5 w-1.5 rounded-full",
                c.status === "Completed" ? "bg-emerald-400 shadow-[0_0_6px_#34d399]" :
                c.status === "In Progress" ? "bg-amber-400 shadow-[0_0_6px_#fbbf24]" :
                c.status === "High" ? "bg-rose-500 shadow-[0_0_6px_#f43f5e]" : "bg-violet-400"
              )} />
              {c.status}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
