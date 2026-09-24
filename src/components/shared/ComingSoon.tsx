import { Construction } from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";

export function ComingSoon({ title, blurb }: { title: string; blurb: string }) {
  return (
    <DashboardShell>
      <div className="panel flex h-[70vh] flex-col items-center justify-center gap-3 text-center">
        <Construction className="h-8 w-8 text-violet-400/50" />
        <h2 className="font-display text-2xl text-violet-100">{title}</h2>
        <p className="max-w-md text-sm text-violet-400/50">{blurb}</p>
        <p className="mt-2 text-[10px] uppercase tracking-[0.2em] text-violet-500/40">
          Scaffolded route — implementation lands in a later phase
        </p>
      </div>
    </DashboardShell>
  );
}
