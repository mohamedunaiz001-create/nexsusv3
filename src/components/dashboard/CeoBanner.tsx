import React from "react";
import { MessageCircleMore, Brain, Terminal, Shield, Sparkles } from "lucide-react";
import { ceoAgent } from "@/lib/mock-data";

export function CeoBanner() {
  return (
    <section className="relative overflow-hidden rounded-2xl border border-violet-500/30 bg-[#090514] shadow-[0_0_40px_-10px_rgba(147,51,234,0.35)]">
      {/* Background Throne Art & Ambient Ethereal Glow */}
      <div className="absolute inset-0 pointer-events-none select-none">
        <img
          src="/archon_throne_bg.jpg"
          alt="ARCHON Throne"
          className="h-full w-full object-cover object-center opacity-85 brightness-95 contrast-110"
        />
        {/* Soft edge gradients so text and panels pop with pristine contrast */}
        <div className="absolute inset-0 bg-gradient-to-r from-[#07040d]/95 via-[#07040d]/40 to-[#07040d]/90" />
        <div className="absolute inset-0 bg-gradient-to-t from-[#07040d] via-transparent to-[#07040d]/60" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_40%,rgba(7,4,13,0.7)_80%)]" />
      </div>

      <div className="relative z-10 grid gap-6 p-6 lg:p-8 xl:grid-cols-[1.3fr_1.1fr_1.1fr] items-center">
        {/* Left Column: CEO Telemetry & Specs */}
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-violet-400 animate-ping opacity-75" />
            <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-violet-300/80 drop-shadow">
              {ceoAgent.title}
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="font-display text-4xl lg:text-5xl font-bold tracking-wider text-violet-50 drop-shadow-[0_2px_12px_rgba(168,85,247,0.5)]">
              {ceoAgent.name}
            </h1>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-950/60 px-2.5 py-1 text-[11px] font-semibold text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.3)]">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              {ceoAgent.status}
            </span>
          </div>

          <p className="text-sm font-medium text-violet-200/90 leading-snug drop-shadow">
            {ceoAgent.tagline}
          </p>
          <p className="text-xs text-violet-300/70 max-w-md leading-relaxed drop-shadow">
            I delegate, analyze, and bring the best minds together to uncover the truth.
          </p>

          {/* 4 Telemetry Spec Cards */}
          <div className="pt-2">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              <div className="rounded-lg border border-violet-500/25 bg-[#0e081e]/80 p-2.5 backdrop-blur-sm shadow-inner">
                <p className="text-[9px] font-semibold uppercase tracking-wider text-violet-400/60">Model</p>
                <p className="mt-0.5 text-xs font-semibold text-violet-100 truncate">{ceoAgent.model}</p>
              </div>

              <div className="rounded-lg border border-violet-500/25 bg-[#0e081e]/80 p-2.5 backdrop-blur-sm shadow-inner">
                <p className="text-[9px] font-semibold uppercase tracking-wider text-violet-400/60">Context Window</p>
                <p className="mt-0.5 text-xs font-semibold text-violet-100 truncate">{ceoAgent.contextWindow}</p>
              </div>

              <div className="rounded-lg border border-violet-500/25 bg-[#0e081e]/80 p-2.5 backdrop-blur-sm shadow-inner">
                <p className="text-[9px] font-semibold uppercase tracking-wider text-violet-400/60">Temperature</p>
                <p className="mt-0.5 text-xs font-semibold text-violet-100 truncate">{ceoAgent.temperature}</p>
              </div>

              <div className="rounded-lg border border-violet-500/25 bg-[#0e081e]/80 p-2.5 backdrop-blur-sm shadow-inner">
                <div className="flex items-center justify-between">
                  <p className="text-[9px] font-semibold uppercase tracking-wider text-violet-400/60">Memory</p>
                  <Brain className="h-3 w-3 text-violet-400/80" />
                </div>
                <p className="mt-0.5 text-xs font-semibold text-violet-100 truncate">{ceoAgent.memory}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Center: Open Space for Archon Throne Art with Arcane Portal */}
        <div className="hidden xl:flex flex-col items-center justify-center pointer-events-none py-2">
          <div className="relative flex flex-col items-center text-center">
            {/* Ambient decorative arcane badge */}
            <div className="inline-flex items-center gap-2 rounded-full border border-violet-500/30 bg-[#12082b]/80 px-4 py-1.5 backdrop-blur-md shadow-[0_0_20px_rgba(168,85,247,0.3)]">
              <Sparkles className="h-3.5 w-3.5 text-violet-400 animate-spin" style={{ animationDuration: "12s" }} />
              <span className="text-[10px] font-semibold uppercase tracking-[0.25em] text-violet-200">
                Strategic Commander
              </span>
            </div>
            <p className="mt-2 text-[10px] text-violet-400/50 font-mono tracking-wider">
              SESSION: 0xARCHON_CORE_ONLINE
            </p>
          </div>
        </div>

        {/* Right Column: CEO Mandate Card */}
        <div className="flex flex-col justify-between rounded-xl border border-violet-500/30 bg-[#0d0720]/85 p-5 backdrop-blur-md shadow-[0_4px_24px_-4px_rgba(147,51,234,0.4)]">
          <div>
            <div className="flex items-center justify-between">
              <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-violet-400/70">
                CEO Mandate
              </p>
              <span className="text-2xl font-serif text-violet-400/40 select-none">“</span>
            </div>
            <p className="mt-1 text-xs italic leading-relaxed text-violet-100/90 font-sans">
              &ldquo;{ceoAgent.mandate}&rdquo;
            </p>
          </div>

          <div className="mt-5 pt-3 border-t border-violet-500/20 flex flex-col sm:flex-row gap-2.5">
            <button
              onClick={() => {
                if (typeof window !== "undefined") {
                  window.history.pushState({}, "", "/chat");
                  window.dispatchEvent(new PopStateEvent("popstate"));
                }
              }}
              className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-violet-600 to-purple-600 px-4 py-2.5 text-xs font-semibold text-white shadow-[0_0_15px_rgba(147,51,234,0.5)] transition hover:from-violet-500 hover:to-purple-500 hover:shadow-[0_0_20px_rgba(147,51,234,0.7)] cursor-pointer active:scale-[0.99]"
            >
              <MessageCircleMore className="h-4 w-4" /> Open CEO Chat
            </button>
            <button
              onClick={() => {
                if (typeof window !== "undefined") {
                  window.history.pushState({}, "", "/agents");
                  window.dispatchEvent(new PopStateEvent("popstate"));
                }
              }}
              className="flex items-center justify-center gap-1.5 rounded-lg border border-violet-500/30 bg-violet-950/40 px-3 py-2.5 text-xs font-medium text-violet-200 transition hover:bg-violet-900/50 hover:text-white cursor-pointer"
            >
              <Shield className="h-3.5 w-3.5 text-violet-400" /> Inspect
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
