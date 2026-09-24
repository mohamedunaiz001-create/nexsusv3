import React, { useState } from 'react';
import { ArrowUpRight, Share2, ZoomIn, ZoomOut, RefreshCw, Info } from 'lucide-react';
import { GothicCornerFiligree } from '../common/GothicCornerFiligree';
import { INITIAL_GRAPH_NODES, INITIAL_GRAPH_EDGES } from '../../data/mockData';
import { GraphNode, GraphEdge } from '../../types';

interface KnowledgeGraphProps {
  onExplore?: () => void;
  nodes?: GraphNode[];
  edges?: GraphEdge[];
}

export const KnowledgeGraph: React.FC<KnowledgeGraphProps> = ({ 
  onExplore,
  nodes = INITIAL_GRAPH_NODES,
  edges = INITIAL_GRAPH_EDGES
}) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  // Position nodes in an aesthetically balanced orbital layout
  const nodePositions: Record<string, { x: number; y: number }> = {
    'node-case': { x: 175, y: 75 },       // Center: Case
    'node-malware': { x: 95, y: 50 },      // Left: malware
    'node-ip': { x: 45, y: 95 },          // Far Left: IP
    'node-c2': { x: 100, y: 125 },        // Bottom Left: C2
    'node-apt': { x: 260, y: 45 },        // Top Right: APT28
    'node-cve': { x: 175, y: 22 },        // Top Center: CVE
    'node-phish': { x: 255, y: 110 },     // Bottom Right: Phishing
    'node-hash': { x: 305, y: 80 },       // Far Right: evil.exe
  };

  return (
    <div
      id="knowledge-graph-card"
      className="rounded-xl bg-[#090317]/95 border border-purple-500/30 p-3 shadow-[0_0_15px_rgba(168,85,247,0.2)] flex flex-col justify-between relative overflow-hidden h-full"
    >
      <GothicCornerFiligree size="sm" opacity="text-purple-400/50" />
      
      {/* Header */}
      <div className="flex items-center justify-between border-b border-purple-500/20 pb-1.5 mb-1.5">
        <div className="flex items-center gap-1.5">
          <Share2 className="w-3.5 h-3.5 text-purple-400" />
          <span className="text-xs font-cyber font-bold text-white tracking-wider">KNOWLEDGE GRAPH</span>
          <span className="text-[9px] font-mono text-purple-300/70 bg-purple-950/60 px-1.5 py-0.2 rounded border border-purple-500/30">
            {nodes.length} Nodes · {edges.length} Edges
          </span>
        </div>
        {onExplore && (
          <button 
            onClick={onExplore} 
            className="text-[10px] font-mono text-purple-400 hover:text-purple-200 flex items-center gap-0.5 transition-colors"
          >
            <span>Explore</span>
            <ArrowUpRight className="w-3 h-3" />
          </button>
        )}
      </div>

      {/* Network Graph Interactive Canvas */}
      <div className="relative h-44 rounded-lg bg-[#070312] border border-purple-500/25 overflow-hidden flex items-center justify-center p-1">
        {/* Subtle Background Radial Glow */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(168,85,247,0.08)_0%,transparent_70%)] pointer-events-none" />

        <svg viewBox="0 0 350 150" className="w-full h-full select-none">
          <defs>
            <linearGradient id="edge-grad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#a855f7" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#ec4899" stopOpacity="0.4" />
            </linearGradient>
            <marker id="arrow" viewBox="0 0 10 10" refX="18" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#a855f7" opacity="0.6" />
            </marker>
          </defs>

          {/* Edges / Relationship Connections */}
          {edges.map((edge, idx) => {
            const p1 = nodePositions[edge.source] || { x: 50, y: 50 };
            const p2 = nodePositions[edge.target] || { x: 200, y: 100 };
            const isHovered = hoveredNode === edge.source || hoveredNode === edge.target;

            return (
              <g key={`edge-${idx}`}>
                <line
                  x1={p1.x}
                  y1={p1.y}
                  x2={p2.x}
                  y2={p2.y}
                  stroke={isHovered ? '#c084fc' : '#6b21a8'}
                  strokeWidth={isHovered ? 1.8 : 1}
                  strokeOpacity={isHovered ? 0.9 : 0.45}
                  strokeDasharray={edge.label.includes('beacon') ? '3 2' : undefined}
                />
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((node) => {
            const pos = nodePositions[node.id] || { x: 100, y: 75 };
            const isHovered = hoveredNode === node.id;
            const isSelected = selectedNode?.id === node.id;
            const isCenter = node.id === 'node-case';

            return (
              <g
                key={node.id}
                className="cursor-pointer transition-all"
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
                onClick={() => setSelectedNode(node)}
              >
                {/* Glow ring */}
                {(isHovered || isSelected || isCenter) && (
                  <circle
                    cx={pos.x}
                    cy={pos.y}
                    r={isCenter ? 18 : 13}
                    fill="none"
                    stroke={node.color || '#a855f7'}
                    strokeWidth="1.2"
                    strokeOpacity={0.6}
                    className="animate-pulse"
                  />
                )}

                {/* Node Core Circle */}
                <circle
                  cx={pos.x}
                  cy={pos.y}
                  r={isCenter ? 12 : 8}
                  fill="#100624"
                  stroke={node.color || '#a855f7'}
                  strokeWidth={isSelected ? 2.5 : 1.5}
                />

                {/* Inner Icon / Glyph Dot */}
                <circle
                  cx={pos.x}
                  cy={pos.y}
                  r={isCenter ? 4 : 2.5}
                  fill={node.color || '#a855f7'}
                />

                {/* Label text */}
                <text
                  x={pos.x}
                  y={pos.y + (isCenter ? 20 : 15)}
                  textAnchor="middle"
                  fontSize={isCenter ? '7' : '6'}
                  fontWeight={isCenter ? 'bold' : 'normal'}
                  fill={isHovered || isSelected ? '#ffffff' : '#c084fc'}
                  fontFamily="monospace"
                  className="pointer-events-none drop-shadow"
                >
                  {node.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected or Hovered Node Info Overlay */}
        {(selectedNode || hoveredNode) && (
          <div className="absolute bottom-1.5 left-1.5 right-1.5 bg-[#0e0622]/95 border border-purple-500/40 rounded px-2 py-1 text-[9px] font-mono flex items-center justify-between z-10">
            <span className="text-white font-bold truncate">
              {selectedNode ? selectedNode.label : nodes.find(n => n.id === hoveredNode)?.label}
            </span>
            <span className="text-purple-300 font-semibold uppercase text-[8px] bg-purple-900/60 px-1 rounded">
              Type: {selectedNode ? selectedNode.type : nodes.find(n => n.id === hoveredNode)?.type}
            </span>
          </div>
        )}
      </div>

      {/* Footer Metrics */}
      <div className="mt-1.5 pt-1.5 border-t border-purple-500/20 bg-[#070312]/80 rounded-lg p-1.5 font-mono text-[9px] flex items-center justify-between text-purple-300/80">
        <span>Attribution: APT28 · CobaltStrike</span>
        <span className="text-emerald-400 font-medium">STIX 2.1 Graph Sync</span>
      </div>
    </div>
  );
};
