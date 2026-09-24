import React from "react";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";

export function DashboardShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen bg-[#06030c] text-violet-100 relative overflow-hidden">
      {/* Background Throne Ambient Layer */}
      <div
        className="fixed inset-0 pointer-events-none opacity-15 bg-cover bg-center"
        style={{ backgroundImage: "url('/archon_throne_bg.jpg')" }}
      />
      {/* Ambient Deep Radial Vignette Overlay */}
      <div className="fixed inset-0 pointer-events-none bg-gradient-to-b from-[#07040d]/85 via-[#07040d]/95 to-[#06030b]" />

      <Sidebar />
      <div className="relative z-10 flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="flex-1 overflow-y-auto p-5 lg:p-6 space-y-5 no-scrollbar">{children}</main>
      </div>
    </div>
  );
}
