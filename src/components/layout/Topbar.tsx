"use client";

import React, { useState } from "react";
import { Bell, HelpCircle, Search, Settings, Sparkles, Crosshair, ChevronDown, Activity } from "lucide-react";

function StatPill({
  label,
  value,
  tone = "default",
  icon: Icon,
}: {
  label: string;
  value: string;
  tone?: "default" | "danger" | "emerald";
  icon?: any;
}) {
  return (
    <div className="flex flex-col items-end border-r border-violet-500/15 pr-4 last:border-none last:pr-0">
      <span className="text-[9px] uppercase tracking-[0.18em] text-violet-400/60 font-medium">{label}</span>
      <span
        className={
          tone === "danger"
            ? "flex items-center gap-1.5 text-xs font-bold text-rose-400 font-mono tracking-wider drop-shadow-[0_0_6px_rgba(244,63,94,0.6)]"
            : tone === "emerald"
            ? "flex items-center gap-1.5 text-xs font-bold text-emerald-400 font-mono"
            : "flex items-center gap-1.5 text-xs font-semibold text-violet-100 font-mono"
        }
      >
        {tone === "emerald" && <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#34d399]" />}
        {Icon && <Icon className="h-3 w-3" />}
        {value}
      </span>
    </div>
  );
}

export function Topbar() {
  const [searchVal, setSearchVal] = useState("");

  return (
    <header className="flex h-16 flex-none items-center justify-between border-b border-violet-500/20 bg-[#07040d]/90 px-6 backdrop-blur-md z-20">
      {/* Search Input Bar with Command Shortcut */}
      <div className="flex w-full max-w-md items-center gap-2.5 rounded-xl border border-violet-500/20 bg-[#0d0720]/80 px-3.5 py-2 shadow-inner focus-within:border-violet-400 focus-within:ring-1 focus-within:ring-violet-400/40 transition">
        <Search className="h-4 w-4 text-violet-400/60" />
        <input
          value={searchVal}
          onChange={(e) => setSearchVal(e.target.value)}
          placeholder="Search cases, IOCs, reports, agents, anything..."
          className="w-full bg-transparent text-xs text-violet-100 placeholder:text-violet-400/40 focus:outline-none"
        />
        <kbd className="rounded border border-violet-500/30 bg-violet-950/60 px-1.5 py-0.5 text-[9px] font-mono text-violet-300">
          ⌘ K
        </kbd>
      </div>

      {/* Telemetry Stats & Profile Header */}
      <div className="flex items-center gap-6">
        <div className="hidden lg:flex items-center gap-6">
          <StatPill label="System Status" value="Operational" tone="emerald" />
          <StatPill label="Active Agents" value="7 / 8" />
          <StatPill label="Threat Level" value="HIGH" tone="danger" icon={Crosshair} />
        </div>

        <div className="flex items-center gap-3 pl-2">
          <button
            onClick={() => {
              if (typeof window !== "undefined") {
                window.history.pushState({}, "", "/playground");
                window.dispatchEvent(new PopStateEvent("popstate"));
              }
            }}
            title="AI Playground"
            className="p-1.5 rounded-lg text-violet-400/80 hover:text-violet-200 hover:bg-violet-600/10 transition cursor-pointer"
          >
            <Sparkles className="h-4 w-4" />
          </button>

          <button
            onClick={() => {
              if (typeof window !== "undefined") {
                window.history.pushState({}, "", "/timeline");
                window.dispatchEvent(new PopStateEvent("popstate"));
              }
            }}
            title="Notifications"
            className="relative p-1.5 rounded-lg text-violet-400/80 hover:text-violet-200 hover:bg-violet-600/10 transition cursor-pointer"
          >
            <Bell className="h-4 w-4" />
            <span className="absolute 0 top-0.5 right-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full bg-rose-500 text-[8px] font-bold text-white shadow-[0_0_8px_rgba(244,63,94,0.8)]">
              1
            </span>
          </button>

          <button
            title="Help & Documentation"
            onClick={() => {
              if (typeof window !== "undefined") {
                window.history.pushState({}, "", "/reports");
                window.dispatchEvent(new PopStateEvent("popstate"));
              }
            }}
            className="p-1.5 rounded-lg text-violet-400/80 hover:text-violet-200 hover:bg-violet-600/10 transition cursor-pointer"
          >
            <HelpCircle className="h-4 w-4" />
          </button>

          <button
            title="Settings"
            onClick={() => {
              if (typeof window !== "undefined") {
                window.history.pushState({}, "", "/settings");
                window.dispatchEvent(new PopStateEvent("popstate"));
              }
            }}
            className="p-1.5 rounded-lg text-violet-400/80 hover:text-violet-200 hover:bg-violet-600/10 transition cursor-pointer"
          >
            <Settings className="h-4 w-4" />
          </button>

          {/* User Profile Pill */}
          <div
            onClick={() => {
              if (typeof window !== "undefined") {
                window.history.pushState({}, "", "/chat");
                window.dispatchEvent(new PopStateEvent("popstate"));
              }
            }}
            className="flex items-center gap-2.5 rounded-xl border border-violet-500/30 bg-[#0d0720]/90 px-2.5 py-1.5 hover:border-violet-400 hover:bg-[#150a2e] transition shadow-sm cursor-pointer"
          >
            <div className="relative flex h-7 w-7 items-center justify-center rounded-full bg-gradient-to-tr from-violet-600 to-fuchsia-600 border border-violet-400/50 shadow-[0_0_10px_rgba(168,85,247,0.5)]">
              <span className="text-[10px] font-bold text-white">Ω</span>
              <span className="absolute bottom-0 right-0 h-2 w-2 rounded-full bg-emerald-400 border border-[#0d0720]" />
            </div>
            <div className="leading-tight hidden sm:block text-left">
              <p className="text-[9px] uppercase tracking-wider text-violet-400/60 font-semibold">CEO Agent</p>
              <p className="text-xs font-bold text-violet-100 font-display">ARCHON</p>
            </div>
            <ChevronDown className="h-3 w-3 text-violet-400/60" />
          </div>
        </div>
      </div>
    </header>
  );
}
