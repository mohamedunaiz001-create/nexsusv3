import React from "react";
import { Globe, Radio } from "lucide-react";

export function ThreatMap() {
  return (
    <section className="relative rounded-xl border border-violet-500/25 bg-[#090514]/90 shadow-[0_4px_24px_-4px_rgba(147,51,234,0.2)] backdrop-blur-md overflow-hidden">
      <div className="flex items-center justify-between border-b border-violet-500/15 px-4 py-3">
        <div className="flex items-center gap-2">
          <Radio className="h-3.5 w-3.5 text-rose-400 animate-pulse" />
          <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-violet-300">
            Threat Map (Live)
          </p>
        </div>
        <button
          onClick={() => {
            if (typeof window !== "undefined") {
              window.history.pushState({}, "", "/threat-intel");
              window.dispatchEvent(new PopStateEvent("popstate"));
            }
          }}
          className="text-[10px] font-medium text-violet-400 hover:text-violet-200 transition-colors cursor-pointer"
        >
          View Map
        </button>
      </div>

      <div className="relative flex h-48 items-center justify-center p-2 overflow-hidden bg-[#070311]">
        {/* Subtle cyber grid backdrop */}
        <div className="absolute inset-0 opacity-20 bg-[linear-gradient(to_right,#8b5cf6_1px,transparent_1px),linear-gradient(to_bottom,#8b5cf6_1px,transparent_1px)] bg-[size:14px_14px]" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(139,92,246,0.18),transparent_75%)]" />

        <svg viewBox="0 0 400 200" className="h-full w-full select-none">
          <defs>
            <linearGradient id="attackArc1" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#a855f7" stopOpacity="0.8" />
            </linearGradient>
            <linearGradient id="attackArc2" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.8" />
            </linearGradient>
          </defs>

          {/* Continents outline representation */}
          <g fill="#1a1130" opacity="0.6">
            {/* North America */}
            <path d="M 60 40 Q 90 30 110 50 Q 130 70 120 100 Q 100 120 70 100 Q 50 70 60 40 Z" />
            {/* South America */}
            <path d="M 110 115 Q 130 125 125 155 Q 115 180 105 170 Q 95 140 110 115 Z" />
            {/* Europe */}
            <path d="M 180 40 Q 210 35 220 55 Q 210 75 190 70 Q 175 60 180 40 Z" />
            {/* Africa */}
            <path d="M 190 80 Q 220 85 225 120 Q 215 150 195 140 Q 180 110 190 80 Z" />
            {/* Asia */}
            <path d="M 230 40 Q 300 30 330 70 Q 310 110 270 95 Q 240 80 230 40 Z" />
            {/* Australia */}
            <path d="M 310 130 Q 340 130 335 155 Q 310 160 310 130 Z" />
          </g>

          {/* Attack Vector Curves */}
          <path
            d="M 280 60 Q 200 20 90 70"
            fill="none"
            stroke="url(#attackArc1)"
            strokeWidth="1.5"
            strokeDasharray="4 2"
            className="animate-pulse"
          />
          <path
            d="M 210 50 Q 150 40 115 130"
            fill="none"
            stroke="url(#attackArc2)"
            strokeWidth="1.5"
            strokeDasharray="3 3"
          />
          <path
            d="M 300 80 Q 240 120 195 120"
            fill="none"
            stroke="#c084fc"
            strokeWidth="1"
            strokeDasharray="2 2"
          />

          {/* Nodes */}
          {/* Target: North America Command */}
          <circle cx="90" cy="70" r="4" fill="#a855f7" />
          <circle cx="90" cy="70" r="8" fill="none" stroke="#a855f7" strokeWidth="1" opacity="0.6" className="animate-ping" />

          {/* Origin: Eastern Europe / Asia */}
          <circle cx="280" cy="60" r="4" fill="#ef4444" />
          <circle cx="280" cy="60" r="8" fill="none" stroke="#ef4444" strokeWidth="1" opacity="0.7" className="animate-ping" style={{ animationDuration: "1.5s" }} />

          {/* Secondary origin */}
          <circle cx="210" cy="50" r="3" fill="#f59e0b" />
          {/* Destination */}
          <circle cx="115" cy="130" r="3" fill="#38bdf8" />
        </svg>

        {/* Live Attack Metric overlay */}
        <div className="absolute bottom-2 left-3 right-3 flex items-center justify-between text-[9px] font-mono text-violet-300/80 bg-[#090414]/80 px-2 py-1 rounded border border-violet-500/20 backdrop-blur-sm">
          <span>SRC: 185.199.108.153 (RU)</span>
          <span className="text-rose-400 font-semibold">ATTACK: C2_BEACONING</span>
          <span>DST: 10.0.4.12</span>
        </div>
      </div>
    </section>
  );
}
