import React from "react";
import { ShieldAlert, AlertTriangle } from "lucide-react";

export function ThreatLevelGauge() {
  return (
    <section className="relative rounded-xl border border-violet-500/25 bg-[#090514]/90 shadow-[0_4px_24px_-4px_rgba(147,51,234,0.2)] backdrop-blur-md">
      <div className="flex items-center justify-between border-b border-violet-500/15 px-4 py-3">
        <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-violet-300">
          Threat Level
        </p>
        <button
          onClick={() => {
            if (typeof window !== "undefined") {
              window.history.pushState({}, "", "/threat-intel");
              window.dispatchEvent(new PopStateEvent("popstate"));
            }
          }}
          className="text-[10px] font-medium text-violet-400 hover:text-violet-200 transition-colors cursor-pointer"
        >
          View Details
        </button>
      </div>

      <div className="flex items-center gap-4 p-4">
        {/* Glowing Circular Gauge */}
        <div className="relative flex h-20 w-20 shrink-0 items-center justify-center rounded-full border-4 border-rose-500/80 bg-[#16061a] shadow-[0_0_20px_rgba(244,63,94,0.4)]">
          <div className="text-center">
            <p className="text-sm font-black tracking-wider text-rose-400 drop-shadow-[0_0_8px_rgba(244,63,94,0.7)]">
              HIGH
            </p>
            <p className="text-[10px] font-mono font-semibold text-violet-300/80">7.8 / 10</p>
          </div>
        </div>

        {/* Telemetry Sparkline & Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse shadow-[0_0_8px_#f43f5e]" />
            <p className="text-xs font-semibold text-rose-300 truncate">Elevated Risk Detected</p>
          </div>
          <p className="text-[10px] text-violet-400/60 mt-0.5 font-mono">
            Active CVEs: 4 &bull; C2 Beacons: 2
          </p>

          <svg viewBox="0 0 100 30" className="mt-2 h-7 w-full text-rose-400 drop-shadow-[0_0_6px_rgba(244,63,94,0.5)]">
            <polyline
              points="0,20 15,15 30,22 45,10 60,18 75,8 90,14 100,6"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.75"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
      </div>
    </section>
  );
}
