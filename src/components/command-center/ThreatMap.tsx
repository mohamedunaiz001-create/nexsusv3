import React, { useState } from 'react';
import { ArrowUpRight, Globe, Shield, Radio, Activity, Target, Zap } from 'lucide-react';
import { GothicCornerFiligree } from '../common/GothicCornerFiligree';

interface ThreatMapProps {
  onViewMap?: () => void;
}

interface AttackVector {
  id: string;
  source: string;
  target: string;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  type: string;
  color: string;
}

export const ThreatMap: React.FC<ThreatMapProps> = ({ onViewMap }) => {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  const attackVectors: AttackVector[] = [
    { id: 'atk-1', source: 'Eastern Europe (185.199.108.153)', target: 'US-East (Target SOC)', x1: 225, y1: 42, x2: 95, y2: 52, type: 'C2 Beacon', color: '#ef4444' },
    { id: 'atk-2', source: 'East Asia (45.77.32.11)', target: 'Western Europe', x1: 285, y1: 58, x2: 175, y2: 45, type: 'DDoS / Syn Flood', color: '#f59e0b' },
    { id: 'atk-3', source: 'South America (190.2.14.88)', target: 'US-West', x1: 120, y1: 105, x2: 70, y2: 55, type: 'SSH Brute Force', color: '#ec4899' },
    { id: 'atk-4', source: 'Central Asia', target: 'East Coast Datacenter', x1: 245, y1: 48, x2: 95, y2: 52, type: 'DNS Tunneling', color: '#a855f7' }
  ];

  const hotspots = [
    { id: 'node-us', name: 'US-East Hub', x: 95, y: 52, status: 'defending', count: '14 Blkd', color: '#38bdf8' },
    { id: 'node-eu', name: 'EU-Central Node', x: 175, y: 45, status: 'alert', count: '6 Alerts', color: '#a855f7' },
    { id: 'node-c2', name: 'C2 Origin (AS13335)', x: 225, y: 42, status: 'malicious', count: 'Active C2', color: '#ef4444' },
    { id: 'node-asia', name: 'East Asia Proxy', x: 285, y: 58, status: 'suspicious', count: 'Scanning', color: '#f59e0b' },
    { id: 'node-sa', name: 'South America', x: 120, y: 105, status: 'probing', count: 'Probe', color: '#ec4899' },
  ];

  return (
    <div id="threat-map-card" className="rounded-xl bg-[#090317]/95 border border-purple-500/30 p-3 shadow-[0_0_15px_rgba(168,85,247,0.2)] flex flex-col justify-between relative overflow-hidden h-full">
      <GothicCornerFiligree size="sm" opacity="text-purple-400/50" />
      
      {/* Header */}
      <div className="flex items-center justify-between border-b border-purple-500/20 pb-1.5 mb-1.5">
        <div className="flex items-center gap-1.5">
          <Globe className="w-3.5 h-3.5 text-purple-400 animate-pulse" />
          <span className="text-xs font-cyber font-bold text-white tracking-wider">THREAT MAP (LIVE)</span>
          <span className="flex items-center gap-1 text-[8.5px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.2 rounded border border-emerald-500/40">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
            LIVE
          </span>
        </div>
        {onViewMap && (
          <button 
            onClick={onViewMap} 
            className="text-[10px] font-mono text-purple-400 hover:text-purple-200 flex items-center gap-0.5 transition-colors"
          >
            <span>View Map</span>
            <ArrowUpRight className="w-3 h-3" />
          </button>
        )}
      </div>

      {/* Vector Interactive Map */}
      <div className="relative h-44 rounded-lg bg-[#070312] border border-purple-500/25 overflow-hidden flex items-center justify-center p-1">
        {/* Ambient Grid Lines */}
        <div 
          className="absolute inset-0 opacity-15 pointer-events-none"
          style={{
            backgroundImage: `linear-gradient(to right, rgba(168,85,247,0.3) 1px, transparent 1px), linear-gradient(to bottom, rgba(168,85,247,0.3) 1px, transparent 1px)`,
            backgroundSize: '24px 24px'
          }}
        />

        <svg 
          viewBox="0 0 360 160" 
          className="w-full h-full select-none"
          style={{ filter: 'drop-shadow(0 0 8px rgba(168,85,247,0.25))' }}
        >
          {/* Stylized Simplified Continents Geo-paths */}
          {/* North America */}
          <path 
            d="M 45,35 Q 70,25 110,32 Q 125,48 115,75 Q 95,85 75,70 Q 55,60 45,35 Z" 
            fill="#180c35" 
            stroke="#a855f7" 
            strokeWidth="0.8" 
            strokeOpacity="0.4"
          />
          {/* South America */}
          <path 
            d="M 100,85 Q 125,90 120,120 Q 110,145 95,140 Q 88,115 100,85 Z" 
            fill="#180c35" 
            stroke="#a855f7" 
            strokeWidth="0.8" 
            strokeOpacity="0.4"
          />
          {/* Europe */}
          <path 
            d="M 160,32 Q 195,28 200,48 Q 185,62 165,58 Q 155,45 160,32 Z" 
            fill="#180c35" 
            stroke="#a855f7" 
            strokeWidth="0.8" 
            strokeOpacity="0.4"
          />
          {/* Africa */}
          <path 
            d="M 165,65 Q 195,65 190,105 Q 175,130 165,115 Q 150,85 165,65 Z" 
            fill="#180c35" 
            stroke="#a855f7" 
            strokeWidth="0.8" 
            strokeOpacity="0.4"
          />
          {/* Asia / Eurasia */}
          <path 
            d="M 205,30 Q 280,25 315,50 Q 290,95 260,85 Q 235,70 210,65 Q 200,45 205,30 Z" 
            fill="#180c35" 
            stroke="#a855f7" 
            strokeWidth="0.8" 
            strokeOpacity="0.4"
          />
          {/* Australia / Oceania */}
          <path 
            d="M 285,110 Q 320,110 315,135 Q 285,140 285,110 Z" 
            fill="#180c35" 
            stroke="#a855f7" 
            strokeWidth="0.8" 
            strokeOpacity="0.4"
          />

          {/* Curved Glowing Ballistic Trajectory Arcs */}
          {attackVectors.map((vec) => {
            const midX = (vec.x1 + vec.x2) / 2;
            const midY = Math.min(vec.y1, vec.y2) - 22;

            return (
              <g key={vec.id}>
                <path 
                  d={`M ${vec.x1},${vec.y1} Q ${midX},${midY} ${vec.x2},${vec.y2}`}
                  fill="none"
                  stroke={vec.color}
                  strokeWidth="1.4"
                  strokeOpacity="0.75"
                  strokeDasharray="4 2"
                  className="animate-pulse"
                />
                {/* Moving Pulse Particle along trajectory */}
                <circle 
                  cx={midX} 
                  cy={midY + 4} 
                  r="2" 
                  fill={vec.color} 
                  className="animate-ping"
                />
              </g>
            );
          })}

          {/* Hotspot Nodes with Pulsing Radar Rings */}
          {hotspots.map((node) => {
            const isHovered = hoveredNode === node.id;
            return (
              <g 
                key={node.id} 
                className="cursor-pointer"
                onMouseEnter={() => setHoveredNode(node.id)}
                onMouseLeave={() => setHoveredNode(null)}
              >
                {/* Outer Ring */}
                <circle 
                  cx={node.x} 
                  cy={node.y} 
                  r={isHovered ? 8 : 5} 
                  fill="none" 
                  stroke={node.color} 
                  strokeWidth="1" 
                  strokeOpacity="0.6"
                  className="animate-ping" 
                />
                {/* Core Dot */}
                <circle 
                  cx={node.x} 
                  cy={node.y} 
                  r={isHovered ? 4 : 2.5} 
                  fill={node.color} 
                />
                {/* Label */}
                <text 
                  x={node.x} 
                  y={node.y - 7} 
                  textAnchor="middle" 
                  fontSize="6.5" 
                  fill="#ffffff" 
                  fontWeight="bold"
                  fontFamily="monospace"
                >
                  {node.count}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Hover Information Banner */}
        {hoveredNode && (
          <div className="absolute top-2 left-2 right-2 bg-[#0d051f]/95 border border-purple-500/40 rounded px-2 py-1 text-[9px] font-mono text-purple-200 z-10 flex items-center justify-between">
            <span className="font-bold text-white">
              {hotspots.find(h => h.id === hoveredNode)?.name}
            </span>
            <span className="text-emerald-400">
              {hotspots.find(h => h.id === hoveredNode)?.count}
            </span>
          </div>
        )}
      </div>

      {/* Legend & Active Vector Metrics */}
      <div id="threat-map-legend" className="mt-1.5 pt-1.5 border-t border-purple-500/20 bg-[#070312]/80 rounded-lg p-1.5 font-mono text-[9px] flex items-center justify-between text-purple-300/80">
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1 text-rose-400 font-bold">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
            4 Active Vectors
          </span>
          <span className="text-purple-400/40">|</span>
          <span className="text-slate-300">Origin: AS13335 (EE)</span>
        </div>
        <span className="text-cyan-400 font-medium">Target: SOC :443</span>
      </div>
    </div>
  );
};
