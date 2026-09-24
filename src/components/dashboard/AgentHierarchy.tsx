import React from "react";
import type { LucideIcon } from "lucide-react";
import {
  Binary,
  Bug,
  Code2,
  FileText,
  Globe2,
  Network,
  ShieldCheck,
  Target,
  Brain,
  Cpu
} from "lucide-react";
import { specialistAgents } from "@/lib/mock-data";

const agentIcons: Record<string, LucideIcon> = {
  "MALWARE ANALYSIS": Bug,
  "IOC EXTRACTION": Target,
  "THREAT INTEL": Globe2,
  "NETWORK ANALYSIS": Network,
  "CODE REVIEW": Code2,
  "REPORT GENERATOR": FileText,
  "MEMORY AGENT": Brain,
  "VERIFICATION AGENT": ShieldCheck,
};

export function AgentHierarchy() {
  return (
    <section className="relative rounded-2xl border border-violet-500/25 bg-[#090514]/90 p-5 shadow-[0_4px_30px_-5px_rgba(147,51,234,0.25)] backdrop-blur-md">
      {/* Hierarchy Header */}
      <div className="mb-4 text-center">
        <h2 className="font-display text-sm font-bold uppercase tracking-[0.28em] text-violet-200 drop-shadow-[0_0_10px_rgba(168,85,247,0.4)]">
          Agent Orchestration Hierarchy
        </h2>
        <p className="mt-1 text-xs text-violet-400/60 font-medium">
          CEO ARCHON delegating and supervising specialist agents
        </p>
      </div>

      {/* SVG Circuit / Tree Connecting Lines */}
      <div className="hidden xl:block relative h-6 w-full -mt-1 mb-2 pointer-events-none">
        <svg className="w-full h-full" preserveAspectRatio="none" viewBox="0 0 1000 30">
          <defs>
            <linearGradient id="treeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="rgba(147, 51, 234, 0.2)" />
              <stop offset="50%" stopColor="rgba(192, 132, 252, 0.9)" />
              <stop offset="100%" stopColor="rgba(147, 51, 234, 0.2)" />
            </linearGradient>
            <filter id="glow">
              <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
              <feMerge>
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>
          {/* Vertical stem from CEO Archon */}
          <line x1="500" y1="0" x2="500" y2="12" stroke="url(#treeGrad)" strokeWidth="2" filter="url(#glow)" />
          {/* Central Junction Dot */}
          <circle cx="500" cy="12" r="3" fill="#c084fc" filter="url(#glow)" />
          {/* Horizontal Distribution Trunk */}
          <line x1="62.5" y1="12" x2="937.5" y2="12" stroke="url(#treeGrad)" strokeWidth="1.5" />
          {/* 8 Drop lines to the 8 agent cards */}
          {[62.5, 187.5, 312.5, 437.5, 562.5, 687.5, 812.5, 937.5].map((x, i) => (
            <g key={i}>
              <circle cx={x} cy="12" r="2.5" fill="#a855f7" />
              <line x1={x} y1="12" x2={x} y2="30" stroke="#8b5cf6" strokeWidth="1.5" strokeDasharray="3 2" />
            </g>
          ))}
        </svg>
      </div>

      {/* 8 Specialist Agent Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-8 gap-3">
        {specialistAgents.map((agent) => {
          const Icon = agentIcons[agent.name] ?? Cpu;
          return (
            <div
              key={agent.name}
              className="group relative flex flex-col items-center justify-between rounded-xl border border-violet-500/20 bg-[#0d0720]/80 p-3 text-center transition-all duration-200 hover:border-violet-400/60 hover:bg-[#12082b] hover:shadow-[0_0_20px_rgba(168,85,247,0.3)] hover:-translate-y-0.5"
            >
              {/* Title & Role */}
              <div className="w-full">
                <p className="text-[10px] font-bold uppercase tracking-wider text-violet-200 group-hover:text-white transition-colors truncate">
                  {agent.name}
                </p>
                <p className="text-[9px] text-violet-400/50 uppercase tracking-widest">{agent.role}</p>
              </div>

              {/* Glowing Icon in Round Badge */}
              <div className="my-2.5 flex h-11 w-11 items-center justify-center rounded-full border border-violet-500/40 bg-gradient-to-b from-violet-950/70 to-purple-900/40 shadow-[0_0_12px_rgba(147,51,234,0.35)] group-hover:scale-105 transition-transform">
                <Icon className="h-5 w-5 text-violet-300 group-hover:text-violet-100 transition-colors" />
              </div>

              {/* Status Indicator */}
              <div className="mb-1.5 flex items-center justify-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_6px_#34d399]" />
                <span className="text-[9px] font-semibold uppercase tracking-wider text-emerald-400">
                  {agent.status}
                </span>
              </div>

              {/* Model */}
              <div className="w-full text-center">
                <p className="text-[8px] uppercase tracking-wider text-violet-400/50">Model</p>
                <p className="text-[11px] font-semibold text-violet-100 truncate">{agent.model}</p>
              </div>

              {/* Task */}
              <div className="w-full mt-1.5 text-center min-h-[32px]">
                <p className="text-[8px] uppercase tracking-wider text-violet-400/50">Task</p>
                <p className="text-[10px] text-violet-300/80 leading-tight line-clamp-2">{agent.task}</p>
              </div>

              {/* Progress Bar & Percentage */}
              <div className="mt-2.5 w-full">
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-violet-950/80 border border-violet-500/20">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-violet-500 to-fuchsia-500 transition-all duration-500 shadow-[0_0_8px_rgba(168,85,247,0.5)]"
                    style={{ width: `${agent.progress}%` }}
                  />
                </div>
                <p className="mt-1 text-[9px] font-mono font-medium text-violet-300/70">{agent.progress}%</p>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
