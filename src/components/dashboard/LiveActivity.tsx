import React from "react";
import { CheckCircle2, Loader2, Bot, ArrowRight } from "lucide-react";
import { liveActivity } from "@/lib/mock-data";

export function LiveActivity() {
  return (
    <section className="relative rounded-xl border border-violet-500/25 bg-[#090514]/90 shadow-[0_4px_24px_-4px_rgba(147,51,234,0.2)] backdrop-blur-md">
      <div className="flex items-center justify-between border-b border-violet-500/15 px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="h-1.5 w-1.5 rounded-full bg-violet-400 animate-ping" />
          <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-violet-300">
            Live Activity
          </p>
        </div>
        <button
          onClick={() => {
            if (typeof window !== "undefined") {
              window.history.pushState({}, "", "/timeline");
              window.dispatchEvent(new PopStateEvent("popstate"));
            }
          }}
          className="text-[10px] font-medium text-violet-400 hover:text-violet-200 transition-colors cursor-pointer"
        >
          View All
        </button>
      </div>

      <ul className="space-y-2.5 px-4 py-3">
        {liveActivity.map((a, i) => (
          <li
            key={i}
            className="flex items-start gap-2.5 text-xs rounded-lg border border-transparent p-1.5 transition hover:border-violet-500/20 hover:bg-[#12082b]/50"
          >
            <span className="font-mono text-[10px] text-violet-400/50 mt-0.5 whitespace-nowrap">
              {a.time}
            </span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] font-semibold text-violet-100 truncate">{a.agent}</span>
              </div>
              <p className="text-[11px] text-violet-300/70 leading-snug line-clamp-2 mt-0.5">{a.detail}</p>
            </div>
            {a.done ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <Loader2 className="h-3.5 w-3.5 animate-spin text-violet-400 shrink-0 mt-0.5" />
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
