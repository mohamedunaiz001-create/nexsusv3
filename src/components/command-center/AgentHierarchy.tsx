import React, { useState, useRef, useEffect, useCallback } from 'react';
import { 
  Radio, 
  Terminal, 
  Activity, 
  ChevronRight, 
  Cpu, 
  Zap, 
  CheckCircle2, 
  Clock, 
  AlertCircle,
  BarChart2,
  X,
  FileCode,
  Eye,
  Crosshair,
  Sparkles
} from 'lucide-react';
import { SpecialistAgent } from '../../types';
import { CustomAgentIcon } from '../common/CustomAgentIcon';
import { AgentTelemetryModal } from '../modals/AgentTelemetryModal';
import { AgentSparkline } from './AgentSparkline';

interface AgentHierarchyProps {
  agents: SpecialistAgent[];
  selectedAgent?: SpecialistAgent | null;
  onSelectAgent: (agent: SpecialistAgent) => void;
}

export const AgentHierarchy: React.FC<AgentHierarchyProps> = ({
  agents,
  selectedAgent,
  onSelectAgent,
}) => {
  const [telemetryAgent, setTelemetryAgent] = useState<SpecialistAgent | null>(null);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const innerContainerRef = useRef<HTMLDivElement>(null);
  const cardRefs = useRef<(HTMLDivElement | null)[]>([]);
  const [cardPositions, setCardPositions] = useState<number[]>([]);
  const [containerWidth, setContainerWidth] = useState<number>(1040);

  const updatePositions = useCallback(() => {
    if (!innerContainerRef.current) return;
    const measuredWidth = innerContainerRef.current.scrollWidth || innerContainerRef.current.offsetWidth || 1040;
    setContainerWidth(measuredWidth);

    const positions: number[] = [];
    const count = agents.length;
    cardRefs.current.forEach((el, idx) => {
      if (el) {
        positions.push(el.offsetLeft + el.offsetWidth / 2);
      } else {
        const estCol = (measuredWidth - (count - 1) * 8) / count;
        positions.push(idx * (estCol + 8) + estCol / 2);
      }
    });

    if (positions.length > 0) {
      setCardPositions(positions);
    }
  }, [agents.length]);

  useEffect(() => {
    updatePositions();
    const handleResize = () => updatePositions();
    window.addEventListener('resize', handleResize);

    let observer: ResizeObserver | null = null;
    if (typeof ResizeObserver !== 'undefined' && innerContainerRef.current) {
      observer = new ResizeObserver(() => updatePositions());
      observer.observe(innerContainerRef.current);
    }

    // Secondary timer to guarantee measurements after CSS styles / layout settle
    const timer = setTimeout(updatePositions, 100);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (observer) observer.disconnect();
      clearTimeout(timer);
    };
  }, [updatePositions]);

  // Fallback if measurement hasn't run yet
  const resolvedPositions = cardPositions.length === agents.length 
    ? cardPositions 
    : agents.map((_, idx) => {
        const estWidth = containerWidth || 1040;
        const colW = (estWidth - (agents.length - 1) * 8) / agents.length;
        return idx * (colW + 8) + colW / 2;
      });

  const firstX = resolvedPositions[0] ?? 65;
  const lastX = resolvedPositions[resolvedPositions.length - 1] ?? (containerWidth - 65);
  const stemX = containerWidth / 2;

  return (
    <div id="agent-hierarchy-section" className="space-y-2">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-1">
        <div>
          <h3 className="text-xs sm:text-sm font-cyber font-bold uppercase tracking-widest text-white flex items-center gap-2">
            <span>AGENT ORCHESTRATION HIERARCHY</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-950/80 text-purple-300 border border-purple-500/40">
              8 SPECIALISTS
            </span>
          </h3>
          <p className="text-[10.5px] font-mono text-purple-300/80 mt-0.5">
            CEO ARCHON delegating live multi-threaded security operations
          </p>
        </div>

        {/* Patrol Mode Status Legend */}
        <div className="flex items-center gap-3 text-[10px] font-mono bg-[#0c051a] px-2.5 py-1 rounded-lg border border-purple-500/30">
          <span className="flex items-center gap-1.5 text-emerald-300 font-semibold">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span>Active Patrol (Scanning)</span>
          </span>
        </div>
      </div>

      {/* Unified Synchronized Container for Connecting Line Bus Bar and 8 Agent Cards */}
      <div 
        ref={scrollContainerRef}
        className="w-full overflow-x-auto pb-1.5 custom-scrollbar"
      >
        <div 
          ref={innerContainerRef} 
          className="min-w-[1040px] w-full flex flex-col relative"
        >
          {/* Dynamic SVG Neural Bus Bar */}
          <div className="relative w-full h-7 overflow-visible pointer-events-none select-none">
            <svg 
              width={containerWidth}
              height={28}
              viewBox={`0 0 ${containerWidth} 28`}
              className="w-full h-full overflow-visible"
            >
              <defs>
                <linearGradient id="activeBusGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#34d399" stopOpacity="0.8" />
                  <stop offset="50%" stopColor="#38bdf8" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#a855f7" stopOpacity="0.8" />
                </linearGradient>
                <filter id="glowGreen" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="2" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              {/* Central Ingress Stem from ARCHON Commander */}
              <line 
                x1={stemX} 
                y1={0} 
                x2={stemX} 
                y2={12} 
                stroke="#a855f7" 
                strokeWidth="1.5" 
                strokeOpacity="0.85"
              />

              {/* Central Junction Hub */}
              <circle cx={stemX} cy={12} r="3" fill="#c084fc" />
              <circle cx={stemX} cy={12} r="5" fill="none" stroke="#a855f7" strokeWidth="1" strokeOpacity="0.5" />

              {/* Main Horizontal Distribution Bus Bar */}
              <line 
                x1={firstX} 
                y1={12} 
                x2={lastX} 
                y2={12} 
                stroke="#581c87" 
                strokeWidth="1.5" 
                strokeOpacity="0.6"
              />

              {/* Active Segments & Drop Lines for Each Specialist Agent */}
              {agents.map((agent, index) => {
                const isActive = agent.status === 'ACTIVE';
                const isSelected = selectedAgent?.id === agent.id;
                const targetX = resolvedPositions[index] ?? (50 + index * 120);

                return (
                  <g key={agent.id}>
                    {/* Active Bus Segment from Central Stem to Agent */}
                    {isActive && (
                      <line
                        x1={stemX}
                        y1={12}
                        x2={targetX}
                        y2={12}
                        stroke="#10b981"
                        strokeWidth="1.5"
                        strokeOpacity="0.9"
                        filter="url(#glowGreen)"
                      />
                    )}

                    {/* Drop Line Down into Card Top */}
                    <line
                      x1={targetX}
                      y1={12}
                      x2={targetX}
                      y2={28}
                      stroke={isActive ? '#10b981' : isSelected ? '#a855f7' : '#6b21a8'}
                      strokeWidth={isActive || isSelected ? '1.5' : '1'}
                      strokeOpacity={isActive ? 1 : isSelected ? 0.9 : 0.45}
                      strokeDasharray={isActive ? undefined : '2 2'}
                    />

                    {/* Joint Node on Bus Bar */}
                    <circle 
                      cx={targetX} 
                      cy={12} 
                      r={isActive ? 2.5 : 1.5} 
                      fill={isActive ? '#34d399' : '#9333ea'} 
                      opacity={isActive ? 1 : 0.7}
                    />

                    {/* Terminal Node at Top Edge of Agent Card */}
                    <circle 
                      cx={targetX} 
                      cy={28} 
                      r={isActive ? 3 : 2} 
                      fill={isActive ? '#10b981' : '#7e22ce'} 
                      stroke={isActive ? '#ffffff' : '#38126b'}
                      strokeWidth="1"
                    />
                  </g>
                );
              })}
            </svg>
          </div>

          {/* 8 Agent Cards in Strict 8-Column Grid Layout */}
          <div 
            className="grid gap-1.5 sm:gap-2 xl:gap-2.5 w-full"
            style={{ gridTemplateColumns: 'repeat(8, minmax(120px, 1fr))' }}
          >
            {agents.map((agent, index) => {
              const isActive = agent.status === 'ACTIVE';
              const isSelected = selectedAgent?.id === agent.id;

              return (
                <div
                  key={agent.id}
                  id={`agent-node-${agent.id}`}
                  ref={(el) => { cardRefs.current[index] = el; }}
                  onClick={() => onSelectAgent(agent)}
                  className={`group cursor-pointer rounded-xl bg-gradient-to-b from-[#140b2e] via-[#0e0622] to-[#090418] border ${
                    isSelected
                      ? 'border-purple-300 glow-purple-lg ring-1 ring-purple-400'
                      : isActive 
                        ? 'border-purple-500/50 glow-purple' 
                        : 'border-purple-500/25'
                  } hover:border-purple-300 hover:glow-purple-lg p-2 sm:p-2.5 xl:p-3 flex flex-col justify-between transition-all duration-200 hover:-translate-y-1 min-w-0 relative overflow-hidden`}
                >
                  {/* Top Accent Gradient Bar */}
                  <div 
                    className={`absolute top-0 left-0 right-0 h-[2px] ${
                      isActive ? 'bg-gradient-to-r from-emerald-400 via-cyan-400 to-purple-500' : 'bg-purple-500/30'
                    }`}
                  />

                  {/* Card Top: Name & Role/Category */}
                  <div className="text-center pb-1 sm:pb-1.5 border-b border-purple-500/15 w-full">
                    <div 
                      className="w-full font-mono font-bold text-white tracking-tight leading-tight group-hover:text-purple-200 min-h-[2.4em] flex flex-wrap items-center justify-center text-center px-0.5 text-[9.5px] sm:text-[10px] xl:text-[11px]"
                      title={agent.name}
                    >
                      <span className="w-full break-words leading-tight">{agent.name.toUpperCase()}</span>
                    </div>
                    <div className="text-[8px] sm:text-[8.5px] font-mono text-purple-300/80 truncate mt-0.5" title={agent.category}>
                      {agent.category}
                    </div>
                  </div>

                  {/* Card Center: Icon with Patrol-Path Scanning */}
                  <div className="py-1.5 flex flex-col items-center justify-center space-y-1">
                    <div className="relative flex items-center justify-center">
                      {/* Fading Ring Patrol Radar Animations */}
                      {isActive ? (
                        <>
                          <span 
                            className="absolute inset-0 rounded-xl border border-emerald-400/50 animate-patrol-ring-1 pointer-events-none" 
                            aria-hidden="true" 
                          />
                          <span 
                            className="absolute inset-0 rounded-xl border border-emerald-500/40 animate-patrol-ring-2 pointer-events-none" 
                            aria-hidden="true" 
                          />
                        </>
                      ) : (
                        <span 
                          className="absolute -inset-0.5 rounded-xl border border-cyan-500/30 animate-patrol-idle pointer-events-none" 
                          aria-hidden="true" 
                        />
                      )}

                      {/* Icon Box */}
                      <div className={`relative w-8 h-8 sm:w-9 sm:h-9 xl:w-10 xl:h-10 rounded-xl bg-[#1d0f3c] border ${
                        isActive 
                          ? 'border-emerald-400/70 shadow-[0_0_12px_rgba(16,185,129,0.3)]' 
                          : 'border-purple-500/40 glow-purple-sm'
                      } flex items-center justify-center shadow-inner group-hover:border-purple-300 group-hover:scale-105 transition-all shrink-0 z-10`}>
                        <CustomAgentIcon type={agent.id} className="w-4 h-4 sm:w-4.5 sm:h-4.5 xl:w-5 xl:h-5" glow={true} />
                        
                        {/* Corner Radar Signal Dot */}
                        <span 
                          className={`absolute -top-1 -right-1 w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full flex items-center justify-center border text-[7px] ${
                            isActive 
                              ? 'bg-emerald-950 border-emerald-400 text-emerald-300 shadow-[0_0_6px_#10b981]' 
                              : 'bg-[#150a2d] border-cyan-500/50 text-cyan-300/80'
                          }`}
                        >
                          {isActive ? (
                            <Radio className="w-1.5 h-1.5 sm:w-2 sm:h-2 text-emerald-300 animate-pulse" />
                          ) : (
                            <Eye className="w-1.5 h-1.5 text-cyan-400/70" />
                          )}
                        </span>
                      </div>
                    </div>

                    {/* Status Indicator Chip */}
                    <div className="flex items-center gap-1 pt-0.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${isActive ? 'bg-emerald-400 animate-ping' : 'bg-purple-400'}`} />
                      <span className={`text-[8.5px] sm:text-[9px] font-mono font-bold ${isActive ? 'text-emerald-300' : 'text-purple-300/80'}`}>
                        {isActive ? 'ACTIVE' : 'STANDBY'}
                      </span>
                    </div>
                  </div>

                  {/* Model & Task Info */}
                  <div className="py-1 px-1 rounded-lg bg-[#0b0417]/80 border border-purple-500/15 space-y-0.5 text-[8px] sm:text-[8.5px] font-mono">
                    <div className="flex items-center justify-between text-purple-300/80 truncate">
                      <span className="text-purple-400">Model:</span>
                      <span className="text-white font-medium truncate ml-1">{agent.model.replace('gemini-', 'Gemini ').replace('gpt-', 'GPT-')}</span>
                    </div>
                    <div className="text-purple-300/80 truncate">
                      <span className="text-purple-400">Task: </span>
                      <span className="text-slate-200 truncate" title={agent.currentTask}>{agent.currentTask}</span>
                    </div>
                  </div>

                  {/* Card Bottom: Progress Bar, Sparkline & Telemetry Trigger */}
                  <div className="space-y-1 sm:space-y-1.5 pt-1.5 border-t border-purple-500/15">
                    <div className="flex items-center justify-between text-[8px] sm:text-[8.5px] font-mono text-purple-300/80">
                      <span>Cycle</span>
                      <span className="font-bold text-white">{agent.progress}%</span>
                    </div>
                    
                    <div className="w-full h-1 rounded-full bg-[#1b0d38] border border-purple-500/30 overflow-hidden">
                      <div 
                        className={`h-full transition-all duration-500 ${
                          isActive 
                            ? 'bg-gradient-to-r from-emerald-400 to-teal-300 shadow-[0_0_6px_#34d399]' 
                            : 'bg-gradient-to-r from-purple-500 to-indigo-400'
                        }`}
                        style={{ width: `${agent.progress}%` }}
                      />
                    </div>

                    {/* Mini Real-Time Sparkline */}
                    <div className="w-full h-4.5 rounded bg-[#090317] border border-purple-500/20 overflow-hidden flex items-center justify-center p-0.5">
                      <AgentSparkline agentId={agent.id} isActive={isActive} type="cpu" />
                    </div>

                    {/* On-Demand Telemetry Popover Button */}
                    <button
                      type="button"
                      id={`view-logs-btn-${agent.id}`}
                      onClick={(e) => {
                        e.stopPropagation();
                        setTelemetryAgent(agent);
                      }}
                      className="w-full py-0.5 px-1 rounded-lg bg-[#180c33] hover:bg-purple-900/50 border border-purple-500/30 hover:border-purple-400/60 text-[8px] sm:text-[8.5px] font-mono text-purple-200 hover:text-white flex items-center justify-center gap-1 transition-all group/btn cursor-pointer"
                      title="View live terminal logs and system diagnostics"
                    >
                      <Terminal className="w-2.5 h-2.5 text-purple-400 group-hover/btn:text-cyan-300 shrink-0" />
                      <span className="truncate">Logs</span>
                      <ChevronRight className="w-2 h-2 text-purple-400 group-hover/btn:translate-x-0.5 transition-transform shrink-0" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Telemetry Logs Modal */}
      {telemetryAgent && (
        <AgentTelemetryModal
          agent={telemetryAgent}
          isOpen={!!telemetryAgent}
          onClose={() => setTelemetryAgent(null)}
        />
      )}
    </div>
  );
};

