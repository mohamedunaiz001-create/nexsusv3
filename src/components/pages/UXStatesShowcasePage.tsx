import React from 'react';
import { LayoutTemplate, ExternalLink } from 'lucide-react';
import { PageShell, Panel } from './PageShell';
import { EmptyState, NoSearchResultsState, LoadingState, ErrorState, SuccessState } from './StatusPages';

const STANDALONE_ROUTES = [
  { path: '/404', label: '404 · Not Found' },
  { path: '/403', label: '403 · Forbidden' },
  { path: '/500', label: '500 · Server Error' },
  { path: '/maintenance', label: 'Maintenance' },
  { path: '/offline', label: 'Offline' },
  { path: '/session-expired', label: 'Session Expired' },
];

/**
 * Internal QA reference — every "easy to forget" UX state in one place so
 * design/eng can eyeball them without having to force each condition
 * (offline, empty search, mid-request, etc) manually.
 */
export const UXStatesShowcasePage: React.FC = () => (
  <PageShell
    title="UX STATES GALLERY"
    subtitle="Reference for every reusable state component (embed these instead of ad-hoc spinners/blank panels), plus the standalone full-screen status pages."
    icon={<LayoutTemplate className="h-4 w-4" />}
  >
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
      <Panel title="EMPTY STATE"><EmptyState title="No Cases Yet" message="Cases you create will show up here." action={{ label: 'New Case', onClick: () => {} }} /></Panel>
      <Panel title="NO SEARCH RESULTS"><NoSearchResultsState query="ransomware" onClear={() => {}} /></Panel>
      <Panel title="LOADING STATE"><LoadingState label="Fetching cases…" /></Panel>
      <Panel title="ERROR STATE"><ErrorState message="Couldn't load IOC feed." onRetry={() => {}} /></Panel>
      <Panel title="SUCCESS STATE" className="lg:col-span-2">
        <SuccessState title="Evidence Uploaded" message="Specialist pipeline dispatched." action={{ label: 'View Case', onClick: () => {} }} />
      </Panel>
    </div>

    <Panel title="STANDALONE STATUS PAGES">
      <p className="mb-3 font-mono text-[10px] text-purple-200/50">Full-screen routes — open in a new tab (they render outside the dashboard chrome).</p>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        {STANDALONE_ROUTES.map((r) => (
          <a
            key={r.path}
            href={r.path}
            target="_blank"
            rel="noreferrer"
            className="flex items-center justify-between gap-2 rounded-md border border-purple-500/25 bg-purple-950/20 px-3 py-2 font-mono text-[10px] uppercase tracking-wider text-purple-200 transition-colors hover:border-purple-400/50 hover:bg-purple-500/10"
          >
            {r.label} <ExternalLink className="h-3 w-3 text-purple-300/50" />
          </a>
        ))}
      </div>
    </Panel>
  </PageShell>
);
