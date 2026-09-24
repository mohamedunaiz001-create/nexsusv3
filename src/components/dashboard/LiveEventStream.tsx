import React, { useState } from "react";
import { liveEventStream } from "@/lib/mock-data";
import { Radio } from "lucide-react";

export function LiveEventStream() {
  const [autoScroll, setAutoScroll] = useState(true);

  return (
    <footer className="relative flex items-center gap-6 overflow-x-auto rounded-xl border border-violet-500/25 bg-[#080413]/95 px-4 py-2.5 text-[11px] text-violet-300/80 shadow-[0_0_20px_rgba(147,51,234,0.15)] backdrop-blur-md">
      <div className="flex items-center gap-2 shrink-0">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-violet-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-violet-500" />
        </span>
        <span className="font-bold uppercase tracking-[0.2em] text-violet-300 shrink-0">
          Live Event Stream
        </span>
      </div>

      <div className="flex items-center gap-6 overflow-x-auto no-scrollbar font-mono text-[10px] text-violet-200/90 py-0.5">
        {liveEventStream.map((e, i) => (
          <span key={i} className="flex items-center gap-2 shrink-0">
            <span className="text-violet-400/60 font-semibold">{e.time}</span>
            <span className="text-violet-100">{e.text}</span>
            {i < liveEventStream.length - 1 && <span className="text-violet-600 select-none">•</span>}
          </span>
        ))}
      </div>

      <div className="ml-auto flex items-center gap-2 shrink-0 pl-4 border-l border-violet-500/20">
        <button
          onClick={() => setAutoScroll(!autoScroll)}
          className={`px-2 py-0.5 rounded text-[10px] font-medium transition cursor-pointer ${
            autoScroll
              ? "bg-violet-600/30 text-violet-200 border border-violet-500/40"
              : "bg-transparent text-violet-400/50 hover:text-violet-300"
          }`}
        >
          Auto Scroll
        </button>
      </div>
    </footer>
  );
}
