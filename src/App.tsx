import { useCurrentPath } from "./lib/router";
import DashboardPage from "./pages_original/dashboard";
import CeoChatPage from "./pages_original/chat";
import PlaygroundPage from "./pages_original/playground";
import BattleModePage from "./pages_original/battle-mode";
import AgentCenterPage from "./pages_original/agents";
import AgentDetailPage from "./pages_original/agent-detail";
import CasesPage from "./pages_original/cases";
import ReportsPage from "./pages_original/reports";
import ThreatIntelPage from "./pages_original/threat-intel";
import KnowledgeGraphPage from "./pages_original/knowledge-graph";
import AnalyticsPage from "./pages_original/analytics";
import SettingsPage from "./pages_original/settings";
import ModelRoutingPage from "./pages_original/model-routing";
import ProvidersPage from "./pages_original/providers";
import { ComingSoon } from "./components/shared/ComingSoon";

export default function App() {
  const path = useCurrentPath();

  if (path === "/chat") {
    return <CeoChatPage />;
  }
  if (path === "/playground") {
    return <PlaygroundPage />;
  }
  if (path === "/battle-mode") {
    return <BattleModePage />;
  }
  if (path === "/agents") {
    return <AgentCenterPage />;
  }
  if (path.startsWith("/agents/") && path !== "/agents/providers" && path !== "/agents/routing" && path !== "/agents/prompts" && path !== "/agents/memory") {
    return <AgentDetailPage />;
  }
  if (path === "/cases") {
    return <CasesPage />;
  }
  if (path === "/cases/evidence") {
    return (
      <ComingSoon
        title="Evidence Custody"
        blurb="Cryptographic evidence storage, artifact parsing, and static disassembly."
      />
    );
  }
  if (path === "/cases/timeline") {
    return (
      <ComingSoon
        title="Incident Timeline"
        blurb="Chronological incident events, analyst notes, and agent actions."
      />
    );
  }
  if (path === "/reports") {
    return <ReportsPage />;
  }
  if (path === "/threat-intel") {
    return <ThreatIntelPage />;
  }
  if (path === "/threat-intel/iocs") {
    return (
      <ComingSoon
        title="IOC Explorer"
        blurb="Search and filter through all extracted indicators of compromise."
      />
    );
  }
  if (path === "/threat-intel/mitre") {
    return (
      <ComingSoon
        title="MITRE ATT&CK Browser"
        blurb="Tactics, techniques, and procedures mapped to detected adversarial behaviors."
      />
    );
  }
  if (path === "/knowledge-graph") {
    return <KnowledgeGraphPage />;
  }
  if (path === "/agents/providers" || path === "/settings/providers") {
    return <ProvidersPage />;
  }
  if (path === "/agents/routing" || path === "/settings/model-routing") {
    return <ModelRoutingPage />;
  }
  if (path === "/agents/prompts") {
    return (
      <ComingSoon
        title="Prompt Library"
        blurb="Agent prompt templates, system instructions, and few-shot examples."
      />
    );
  }
  if (path === "/agents/memory") {
    return (
      <ComingSoon
        title="Memory Center"
        blurb="Vector memory search, episodic incident logs, and semantic agent recall."
      />
    );
  }
  if (path === "/operations/workflows") {
    return (
      <ComingSoon
        title="Workflows"
        blurb="Automated SOAR playbooks, incident response procedures, and agent routines."
      />
    );
  }
  if (path === "/analytics") {
    return <AnalyticsPage />;
  }
  if (path === "/operations/system-monitor") {
    return (
      <ComingSoon
        title="System Monitor"
        blurb="Real-time telemetry, model latency, GPU/CPU usage, and token budgets."
      />
    );
  }
  if (path === "/settings") {
    return <SettingsPage />;
  }

  // Default: Dashboard page
  return <DashboardPage />;
}
