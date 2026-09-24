import React from "react";
import { currentMission } from "@/lib/mock-data";
import { cn } from "@/lib/utils";
import { Flame, CheckCircle2, Clock, CircleDot, AlertTriangle } from "lucide-react";

export function CurrentMission() {
  return (
    <section className="relative rounded-2xl border border-violet-500/25 bg-[#090514]/90 p-5 shadow-[0_4px_30px_-5px_rgba(147,51,234,0.2)] backdrop-blur-md">
      <div className="grid gap-6 lg:grid-cols-[1.2fr_0.9fr_1fr]">
        {/* Left Column: Mission Overview */}
        <div className="flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-violet-400 animate-ping" />
              <p className="text-[10px] font-bold uppercase tracking-[0.25em] text-violet-400">
                CURRENT MISSION
              </p>
            </div>
            <h3 className="mt-2 text-lg font-bold text-violet-50 tracking-wide">
              {currentMission.title}
            </h3>
            <div className="mt-1.5 flex items-center gap-2 text-xs">
              <span className="font-mono text-violet-300/70">Case ID: {currentMission.caseId}</span>
              <span className="text-violet-500">•</span>
              <span className="inline-flex items-center gap-1 font-semibold text-rose-400">
                Priority: <Flame className="h-3 w-3 fill-rose-500 text-rose-500 animate-pulse" /> {currentMission.priority}
              </span>
            </div>
            <p className="mt-3 text-xs leading-relaxed text-violet-200/70">
              {currentMission.description}
            </p>
          </div>

          <div className="mt-4 flex items-center gap-2 text-[11px] text-violet-400/60 font-mono">
            <span>TARGET_STATUS: ACTIVE_REVERSE_ENGINEERING</span>
          </div>
        </div>

        {/* Middle Column: Progress & Timeline */}
        <div className="flex flex-col justify-between rounded-xl border border-violet-500/15 bg-[#0d0720]/60 p-4">
          <div>
            <div className="flex items-center justify-between">
              <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-violet-400/70">
                Progress
              </p>
              <span className="text-xs font-mono font-bold text-violet-100">{currentMission.progress}%</span>
            </div>
            <div className="mt-2.5 h-2 w-full overflow-hidden rounded-full bg-violet-950/80 border border-violet-500/20">
              <div
                className="h-full rounded-full bg-gradient-to-r from-violet-500 via-fuchsia-500 to-pink-500 shadow-[0_0_12px_rgba(236,72,153,0.6)]"
                style={{ width: `${currentMission.progress}%` }}
              />
            </div>
          </div>

          <dl className="mt-4 space-y-2 text-xs">
            <div className="flex justify-between border-b border-violet-500/10 pb-1.5">
              <dt className="text-violet-400/50">Started At</dt>
              <dd className="font-mono text-violet-200/90">{currentMission.startedAt}</dd>
            </div>
            <div className="flex justify-between border-b border-violet-500/10 pb-1.5">
              <dt className="text-violet-400/50">Estimated Completion</dt>
              <dd className="font-mono text-violet-200/90">{currentMission.estimatedCompletion}</dd>
            </div>
            <div className="flex justify-between pt-0.5">
              <dt className="text-violet-400/50">Delegated By</dt>
              <dd className="font-semibold text-violet-300">{currentMission.delegatedBy}</dd>
            </div>
          </dl>
        </div>

        {/* Right Column: Mission Output (Live) Checklist */}
        <div className="rounded-xl border border-violet-500/15 bg-[#0d0720]/60 p-4">
          <div className="flex items-center justify-between pb-2 border-b border-violet-500/15">
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-violet-400/70">
              Mission Output (Live)
            </p>
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
          </div>

          <ul className="mt-3 space-y-2 text-xs">
            {currentMission.steps.map((step) => {
              const isCompleted = step.status === "Completed";
              const isInProgress = step.status === "In Progress";
              return (
                <li key={step.label} className="flex items-center justify-between group">
                  <span className={cn(
                    "transition-colors",
                    isCompleted ? "text-violet-200 font-medium" : isInProgress ? "text-violet-100 font-medium" : "text-violet-400/40"
                  )}>
                    {step.label}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {isCompleted ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-medium text-emerald-400">
                        <CheckCircle2 className="h-3 w-3 text-emerald-400" /> Completed
                      </span>
                    ) : isInProgress ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-medium text-amber-400">
                        <Clock className="h-3 w-3 text-amber-400 animate-spin" style={{ animationDuration: "4s" }} /> In Progress
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] font-medium text-violet-400/40">
                        <CircleDot className="h-2.5 w-2.5 text-violet-400/30" /> Pending
                      </span>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </section>
  );
}
