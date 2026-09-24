"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheck, Sparkles, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import { navSections, brand } from "./NavConfig";

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex h-screen w-64 flex-none flex-col border-r border-violet-500/20 bg-[#07040d]/95 backdrop-blur-md select-none z-20">
      {/* Brand Header */}
      <div className="flex items-center gap-3 border-b border-violet-500/15 px-5 py-4">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-violet-600/30 to-purple-800/40 border border-violet-500/30 shadow-[0_0_15px_rgba(147,51,234,0.4)]">
          <ShieldCheck className="h-5 w-5 text-violet-300" />
        </div>
        <div>
          <p className="font-display text-sm font-bold tracking-wider text-violet-100">{brand.name}</p>
          <p className="text-[9px] uppercase tracking-[0.25em] text-violet-400/60 font-semibold">{brand.tagline}</p>
        </div>
      </div>

      {/* Navigation Sections */}
      <nav className="flex-1 overflow-y-auto px-3 py-2 space-y-1">
        {navSections.map((section) => (
          <div key={section.label} className="pb-1">
            <p className="px-3 pt-3 pb-1 text-[9px] font-bold uppercase tracking-[0.25em] text-violet-400/50">
              {section.label}
            </p>
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const active = pathname === item.href;
                const Icon = item.icon;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      "flex items-center gap-3 rounded-lg px-3 py-2 text-xs font-medium transition-all duration-150 cursor-pointer",
                      active
                        ? "bg-violet-600/20 text-white border border-violet-500/40 shadow-[0_0_15px_rgba(147,51,234,0.35)]"
                        : "text-violet-300/70 hover:bg-violet-500/10 hover:text-violet-100 hover:translate-x-0.5"
                    )}
                  >
                    <Icon className={cn("h-4 w-4 shrink-0", active ? "text-violet-300" : "text-violet-400/60")} />
                    <span>{item.label}</span>
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Bottom Brand Card from Screenshot */}
      <div className="border-t border-violet-500/15 p-3.5 bg-[#090514]/60">
        <div className="rounded-xl border border-violet-500/20 bg-gradient-to-b from-[#12082b] to-[#0a0518] p-3 text-center shadow-inner">
          <div className="mx-auto mb-1.5 flex h-7 w-7 items-center justify-center rounded-full bg-violet-600/20 border border-violet-500/30">
            <Sparkles className="h-3.5 w-3.5 text-violet-300" />
          </div>
          <p className="font-display text-[10px] font-bold tracking-widest text-violet-200 uppercase">
            {brand.name}
          </p>
          <p className="mt-0.5 text-[8px] font-mono uppercase tracking-wider text-violet-400/60">
            Every byte tells a story
          </p>
          <p className="text-[8px] font-mono font-bold tracking-widest text-violet-300">
            LET'S UNCOVER IT
          </p>
        </div>
      </div>
    </aside>
  );
}
