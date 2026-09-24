import type { LucideIcon } from "lucide-react";
import {
  Activity,
  BarChart3,
  Bot,
  Brain,
  FileText,
  Folder,
  Gauge,
  History,
  LayoutDashboard,
  MessageSquare,
  Network,
  Radar,
  Search,
  Settings,
  Share2,
  ShieldAlert,
  Sparkles,
  Swords,
  Workflow,
} from "lucide-react";

export type NavItem = { label: string; href: string; icon: LucideIcon };
export type NavSection = { label: string; items: NavItem[] };

export const navSections: NavSection[] = [
  {
    label: "AI Command",
    items: [
      { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
      { label: "CEO AI Chat", href: "/chat", icon: MessageSquare },
      { label: "AI Playground", href: "/playground", icon: Sparkles },
      { label: "AI Battle Mode", href: "/battle-mode", icon: Swords },
    ],
  },
  {
    label: "Investigations",
    items: [
      { label: "Cases", href: "/cases", icon: Folder },
      { label: "Evidence", href: "/cases/evidence", icon: FileText },
      { label: "Reports", href: "/reports", icon: FileText },
      { label: "Timeline", href: "/cases/timeline", icon: History },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { label: "Threat Intel", href: "/threat-intel", icon: Radar },
      { label: "IOC Explorer", href: "/threat-intel/iocs", icon: Search },
      { label: "MITRE Browser", href: "/threat-intel/mitre", icon: ShieldAlert },
      { label: "Knowledge Graph", href: "/knowledge-graph", icon: Share2 },
    ],
  },
  {
    label: "AI Operations",
    items: [
      { label: "Agent Center", href: "/agents", icon: Bot },
      { label: "Provider Hub", href: "/agents/providers", icon: Network },
      { label: "Model Routing", href: "/agents/routing", icon: Workflow },
      { label: "Prompt Library", href: "/agents/prompts", icon: FileText },
      { label: "Memory Center", href: "/agents/memory", icon: Brain },
    ],
  },
  {
    label: "Operations",
    items: [
      { label: "Workflows", href: "/operations/workflows", icon: Workflow },
      { label: "Analytics", href: "/analytics", icon: BarChart3 },
      { label: "System Monitor", href: "/operations/system-monitor", icon: Gauge },
      { label: "Settings", href: "/settings", icon: Settings },
    ],
  },
];

export const brand = { name: "CyberResearch-X", tagline: "AI Cybersecurity OS" };
export { Activity };
