import React from "react";
import { Cpu, Database, HardDrive, Users, Activity } from "lucide-react";
import { systemOverview as s } from "@/lib/mock-data";

export function SystemOverview() {
  const items = [
    { label: "CPU", value: `${s.cpu}%`, icon: Cpu },
    { label: "Memory", value: `${s.memoryUsed} / ${s.memoryTotal} GB`, icon: Database },
    { label: "Disk", value: `${s.disk}%`, icon: HardDrive },
    { label: "Active Agents", value: s.activeAgents, icon: Users },
  ];

  return (
    <section className="relative rounded-xl border border-violet-500/25 bg-[#090514]/90 shadow-[0_4px_24px_-4px_rgba(147,51,234,0.2)] backdrop-blur-md">
      <div className="flex items-center justify-between border-b border-violet-500/15 px-4 py-3">
        <div className="flex items-center gap-2">
          <Activity className="h-3.5 w-3.5 text-violet-400" />
          <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-violet-300">
            System Overview
          </p>
        </div>
        <button
          onClick={() => {
            if (typeof window !== "undefined") {
              window.history.pushState({}, "", "/system-monitor");
              window.dispatchEvent(new PopStateEvent("popstate"));
            }
          }}
          className="text-[10px] font-medium text-violet-400 hover:text-violet-200 transition-colors cursor-pointer"
        >
          View All
        </button>
      </div>

      <div className="grid grid-cols-4 gap-2 p-3">
        {items.map(({ label, value, icon: Icon }) => (
          <div
            key={label}
            className="flex flex-col items-center justify-center rounded-lg border border-violet-500/20 bg-[#0d0720]/80 py-2.5 px-1 text-center shadow-inner hover:border-violet-500/40 transition-colors"
          >
            <Icon className="mb-1 h-3.5 w-3.5 text-violet-300/80" />
            <p className="font-mono text-xs font-bold text-violet-100">{value}</p>
            <p className="mt-0.5 text-[8px] font-semibold uppercase tracking-wider text-violet-400/50">{label}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
