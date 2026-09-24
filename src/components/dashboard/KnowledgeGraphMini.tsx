import React from "react";
import { Network, Share2 } from "lucide-react";

export function KnowledgeGraphMini() {
  const nodes = [
    { label: "malware.exe", x: 60, y: 35, type: "artifact" },
    { label: "185.199.108.153", x: 210, y: 30, type: "ip" },
    { label: "bad-domain.com", x: 220, y: 120, type: "domain" },
    { label: "CVE-2023-50801", x: 140, y: 145, type: "cve" },
    { label: "APT29", x: 50, y: 120, type: "actor" },
  ];

  return (
    <section className="relative rounded-xl border border-violet-500/25 bg-[#090514]/90 shadow-[0_4px_24px_-4px_rgba(147,51,234,0.2)] backdrop-blur-md">
      <div className="flex items-center justify-between border-b border-violet-500/15 px-4 py-3">
        <div className="flex items-center gap-2">
          <Share2 className="h-3.5 w-3.5 text-violet-400" />
          <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-violet-300">
            Knowledge Graph
          </p>
        </div>
        <button
          onClick={() => {
            if (typeof window !== "undefined") {
              window.history.pushState({}, "", "/knowledge-graph");
              window.dispatchEvent(new PopStateEvent("popstate"));
            }
          }}
          className="text-[10px] font-medium text-violet-400 hover:text-violet-200 transition-colors cursor-pointer"
        >
          Explore
        </button>
      </div>

      <div className="relative flex h-48 items-center justify-center p-2 overflow-hidden bg-[#070311]">
        {/* SVG Connections */}
        <svg className="absolute inset-0 h-full w-full" viewBox="0 0 280 180">
          <defs>
            <linearGradient id="edgeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#8b5cf6" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#c084fc" stopOpacity="0.2" />
            </linearGradient>
          </defs>
          {/* Edges from Center (140, 90) to nodes */}
          {nodes.map((n, i) => (
            <g key={i}>
              <line
                x1="140"
                y1="90"
                x2={n.x}
                y2={n.y}
                stroke="url(#edgeGrad)"
                strokeWidth="1.5"
                strokeDasharray="3 2"
              />
              <circle cx={(140 + n.x) / 2} cy={(90 + n.y) / 2} r="2" fill="#c084fc" opacity="0.8" />
            </g>
          ))}
          {/* Secondary correlation edge */}
          <line x1="60" y1="35" x2="210" y2="30" stroke="#a855f7" strokeWidth="1" strokeDasharray="2 2" opacity="0.4" />
          <line x1="50" y1="120" x2="140" y2="145" stroke="#a855f7" strokeWidth="1" strokeDasharray="2 2" opacity="0.4" />
        </svg>

        {/* Center Node: Case ID */}
        <div className="absolute z-10 flex h-16 w-16 items-center justify-center rounded-full border-2 border-violet-400 bg-gradient-to-br from-violet-900/90 to-purple-950/90 text-center shadow-[0_0_20px_rgba(168,85,247,0.5)]">
          <div>
            <span className="text-[8px] font-bold uppercase tracking-wider text-violet-300">CASE:</span>
            <p className="text-[10px] font-mono font-bold text-white">2024-017</p>
          </div>
        </div>

        {/* Outer Satellite Nodes */}
        {nodes.map((node, i) => (
          <div
            key={node.label}
            className="absolute z-10 rounded border border-violet-500/30 bg-[#0d0720]/90 px-2 py-0.5 text-[9px] font-mono text-violet-200 shadow-sm backdrop-blur-sm hover:border-violet-400 hover:text-white transition-colors cursor-pointer"
            style={{
              left: `${(node.x / 280) * 100}%`,
              top: `${(node.y / 180) * 100}%`,
              transform: "translate(-50%, -50%)",
            }}
          >
            {node.label}
          </div>
        ))}
      </div>
    </section>
  );
}
