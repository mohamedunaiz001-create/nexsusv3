import Link from "next/link";
import { ShieldHalf, ArrowRight } from "lucide-react";

export default function LandingPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-void-950 bg-radial-fade px-6 text-center text-violet-100">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-violet-600/20 shadow-glow">
        <ShieldHalf className="h-8 w-8 text-violet-300" />
      </div>
      <h1 className="mt-6 font-display text-4xl tracking-wide text-violet-50 sm:text-5xl">
        CyberResearch-X <span className="text-violet-400">Enterprise</span>
      </h1>
      <p className="mt-3 max-w-xl text-sm text-violet-300/60">
        An AI-powered cybersecurity operating system — CEO/Hermes orchestration, specialist
        agents, threat intelligence, investigation workflows, and enterprise reporting.
      </p>
      <Link
        href="/dashboard"
        className="mt-8 flex items-center gap-2 rounded-lg bg-violet-600/90 px-5 py-2.5 text-sm font-medium text-white shadow-glow-sm transition hover:bg-violet-600"
      >
        Enter Command Center <ArrowRight className="h-4 w-4" />
      </Link>
      <p className="mt-10 text-[10px] uppercase tracking-[0.3em] text-violet-500/40">
        Phase 1 — Foundation &amp; Architecture
      </p>
    </div>
  );
}
