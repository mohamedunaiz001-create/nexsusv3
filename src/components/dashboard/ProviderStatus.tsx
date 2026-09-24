import React from "react";
import { providerStatus } from "@/lib/mock-data";
import { Cpu } from "lucide-react";

export function ProviderStatus() {
  return (
    <section className="relative rounded-xl border border-violet-500/25 bg-[#090514]/90 shadow-[0_4px_24px_-4px_rgba(147,51,234,0.2)] backdrop-blur-md">
      <div className="flex items-center justify-between border-b border-violet-500/15 px-4 py-3">
        <div className="flex items-center gap-2">
          <Cpu className="h-3.5 w-3.5 text-violet-400" />
          <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-violet-300">
            AI Provider Status
          </p>
        </div>
        <button
          onClick={() => {
            if (typeof window !== "undefined") {
              window.history.pushState({}, "", "/settings/providers");
              window.dispatchEvent(new PopStateEvent("popstate"));
            }
          }}
          className="text-[10px] font-medium text-violet-400 hover:text-violet-200 transition-colors cursor-pointer"
        >
          Manage
        </button>
      </div>

      <ul className="divide-y divide-violet-500/10">
        {providerStatus.map((p) => (
          <li
            key={p.name}
            onClick={() => {
              if (typeof window !== "undefined") {
                window.history.pushState({}, "", "/settings/providers");
                window.dispatchEvent(new PopStateEvent("popstate"));
              }
            }}
            className="flex items-center justify-between px-4 py-2.5 text-xs transition hover:bg-[#12082b]/50 cursor-pointer"
          >
            <span className="flex items-center gap-2 font-medium text-violet-100">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_6px_#34d399]" />
              {p.name}
            </span>
            <div className="flex items-center gap-2 text-[11px] font-mono">
              <span className="text-emerald-400 font-semibold">Online</span>
              <span className="text-violet-500">•</span>
              <span className="text-violet-300/80">{p.uptime}%</span>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
