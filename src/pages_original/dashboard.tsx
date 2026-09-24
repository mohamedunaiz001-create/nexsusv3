import { DashboardShell } from "@/components/layout/DashboardShell";
import { CeoBanner } from "@/components/dashboard/CeoBanner";
import { AgentHierarchy } from "@/components/dashboard/AgentHierarchy";
import { CurrentMission } from "@/components/dashboard/CurrentMission";
import { RecentCases } from "@/components/dashboard/RecentCases";
import { ThreatMap } from "@/components/dashboard/ThreatMap";
import { AgentPerformance } from "@/components/dashboard/AgentPerformance";
import { ProviderStatus } from "@/components/dashboard/ProviderStatus";
import { KnowledgeGraphMini } from "@/components/dashboard/KnowledgeGraphMini";
import { LiveActivity } from "@/components/dashboard/LiveActivity";
import { ThreatLevelGauge } from "@/components/dashboard/ThreatLevelGauge";
import { TopIocs } from "@/components/dashboard/TopIocs";
import { SystemOverview } from "@/components/dashboard/SystemOverview";
import { LiveEventStream } from "@/components/dashboard/LiveEventStream";

// Phase 1: static layout rendered from placeholder data in lib/mock-data.ts.
// Phase 2 wires each section to /api/v1 (agents, cases, providers, audit-logs)
// via TanStack Query and replaces the mock imports below.
export default function DashboardPage() {
  return (
    <DashboardShell>
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[1fr_320px]">
        <div className="space-y-5">
          <CeoBanner />
          <AgentHierarchy />
          <CurrentMission />

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
            <RecentCases />
            <ThreatMap />
            <AgentPerformance />
          </div>
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <ProviderStatus />
            <KnowledgeGraphMini />
          </div>
        </div>

        <div className="space-y-5">
          <LiveActivity />
          <ThreatLevelGauge />
          <TopIocs />
          <SystemOverview />
        </div>
      </div>

      <div className="mt-5">
        <LiveEventStream />
      </div>
    </DashboardShell>
  );
}
