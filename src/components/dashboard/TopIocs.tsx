import React from "react";
import { topIocs } from "@/lib/mock-data";
import { cn } from "@/lib/utils";

export function TopIocs() {
  return (
    <section className="relative rounded-xl border border-violet-500/25 bg-[#090514]/90 shadow-[0_4px_24px_-4px_rgba(147,51,234,0.2)] backdrop-blur-md">
      <div className="flex items-center justify-between border-b border-violet-500/15 px-4 py-3">
        <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-violet-300">
          Top IOCs
        </p>
        <button
          onClick={() => {
            if (typeof window !== "undefined") {
              window.history.pushState({}, "", "/evidence");
              window.dispatchEvent(new PopStateEvent("popstate"));
            }
          }}
          className="text-[10px] font-medium text-violet-400 hover:text-violet-200 transition-colors cursor-pointer"
        >
          View All
        </button>
      </div>

      <div className="divide-y divide-violet-500/10 px-4 py-1">
        {topIocs.map((ioc) => (
          <div key={ioc.value} className="flex items-center justify-between py-2 text-xs">
            <span className="font-mono text-violet-100 truncate max-w-[130px] sm:max-w-[170px]" title={ioc.value}>
              {ioc.value}
            </span>
            <div className="flex items-center gap-2 shrink-0">
              <span className="rounded bg-violet-950/80 border border-violet-500/20 px-1.5 py-0.5 text-[9px] font-mono text-violet-300">
                {ioc.type}
              </span>
              <span
                className={cn(
                  "flex items-center gap-1 text-[10px] font-semibold",
                  ioc.verdict === "Malicious" ? "text-rose-400" : "text-amber-400"
                )}
              >
                <span
                  className={cn(
                    "h-1.5 w-1.5 rounded-full",
                    ioc.verdict === "Malicious" ? "bg-rose-500 shadow-[0_0_6px_#f43f5e]" : "bg-amber-400 shadow-[0_0_6px_#fbbf24]"
                  )}
                />
                {ioc.verdict}
              </span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
