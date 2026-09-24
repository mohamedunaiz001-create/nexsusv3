import React from "react";
import { CeoBanner } from "./CeoBanner";
import { AgentHierarchy } from "./AgentHierarchy";
import { CurrentMission } from "./CurrentMission";
import { ThreatLevelGauge } from "./ThreatLevelGauge";
import { RecentCases } from "./RecentCases";
import { ThreatMap } from "./ThreatMap";
import { AgentPerformance } from "./AgentPerformance";
import { ProviderStatus } from "./ProviderStatus";
import { KnowledgeGraphMini } from "./KnowledgeGraphMini";
import { TopIocs } from "./TopIocs";
import { SystemOverview } from "./SystemOverview";
import { LiveActivity } from "./LiveActivity";
import { LiveEventStream } from "./LiveEventStream";

interface DashboardViewProps {
  onSelectNav: (id: string) => void;
  onOpenUploadEvidence?: (caseId?: string) => void;
}

export function DashboardView({ onSelectNav, onOpenUploadEvidence }: DashboardViewProps) {
  return (
    <div className="mx-auto max-w-7xl space-y-6">
      {/* 1. CEO Orchestrator Archon Banner */}
      <CeoBanner onOpenChat={() => onSelectNav("chat")} />

      {/* 2. 8 Specialist Agent Fleet Hierarchy */}
      <AgentHierarchy onSelectAgent={() => onSelectNav("agents")} />

      {/* 3. Active Incident Mission */}
      <CurrentMission onInspectCase={() => onSelectNav("cases")} />

      {/* 4. Threat Telemetry & Geographic Map */}
      <div className="grid gap-6 md:grid-cols-2">
        <ThreatLevelGauge
          score={7.8}
          level="HIGH"
          onViewDetails={() => onSelectNav("threat-intel")}
        />
        <ThreatMap onViewDetails={() => onSelectNav("threat-intel")} />
      </div>

      {/* 5. Investigations & Indicators */}
      <div className="grid gap-6 md:grid-cols-2">
        <RecentCases
          onViewAll={() => onSelectNav("cases")}
          onSelectCase={() => onSelectNav("cases")}
        />
        <TopIocs onViewAll={() => onSelectNav("iocs")} />
      </div>

      {/* 6. AI Throughput & Provider Health */}
      <div className="grid gap-6 md:grid-cols-2">
        <AgentPerformance onViewAnalytics={() => onSelectNav("analytics")} />
        <ProviderStatus onManageProviders={() => onSelectNav("providers")} />
      </div>

      {/* 7. Knowledge Graph & Node Telemetry */}
      <div className="grid gap-6 md:grid-cols-2">
        <KnowledgeGraphMini onExploreGraph={() => onSelectNav("knowledge-graph")} />
        <SystemOverview onViewMonitor={() => onSelectNav("system-monitor")} />
      </div>

      {/* 8. Live Activity Feed */}
      <LiveActivity onViewAll={() => onSelectNav("timeline")} />

      {/* 9. Live Event Ticker Stream */}
      <LiveEventStream />
    </div>
  );
}
