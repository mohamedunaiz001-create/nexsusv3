"use client";

import Link from "next/link";
import { Settings, Server, Brain, Zap } from "lucide-react";
import { ComingSoon } from "@/components/shared/ComingSoon";

export default function Page() {
  return (
    <div className="space-y-6">
      <section className="panel p-6">
        <h1 className="font-display text-xl text-violet-50 mb-2">Settings</h1>
        <p className="text-xs text-violet-400/50 mb-6">Configure providers, model routing, and workspace preferences.</p>
        
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <Link 
            href="/settings/providers" 
            className="panel p-4 flex items-center gap-3 border-violet-500/20 hover:border-violet-500/40 transition-colors"
          >
            <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-violet-500/20 bg-violet-600/10">
              <Server className="h-6 w-6 text-violet-400" />
            </div>
            <div>
              <h3 className="font-medium text-violet-100">Provider Hub</h3>
              <p className="text-xs text-violet-400/50 mt-1">Manage AI providers, credentials, and model discovery</p>
            </div>
          </Link>
          
          <Link 
            href="/settings/model-routing" 
            className="panel p-4 flex items-center gap-3 border-violet-500/20 hover:border-violet-500/40 transition-colors"
          >
            <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-violet-500/20 bg-violet-600/10">
              <Brain className="h-6 w-6 text-violet-400" />
            </div>
            <div>
              <h3 className="font-medium text-violet-100">Model Routing</h3>
              <p className="text-xs text-violet-400/50 mt-1">Assign models to agents and configure routing strategies</p>
            </div>
          </Link>
          
          <div className="panel p-4 flex items-center gap-3 border-violet-500/20 opacity-50">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-violet-500/10 bg-violet-500/5">
              <Zap className="h-6 w-6 text-violet-400/30" />
            </div>
            <div>
              <h3 className="font-medium text-violet-400/50">Workspace</h3>
              <p className="text-xs text-violet-400/30 mt-1">General workspace settings (coming soon)</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}