import React from 'react';
import {
  Ghost, ShieldOff, ServerCrash, Construction, WifiOff, TimerOff, Home, RefreshCw,
  Inbox, SearchX, Loader2, AlertCircle, CheckCircle2, LucideIcon,
} from 'lucide-react';
import { PublicShell, publicPrimaryBtn, publicSecondaryBtn } from './PublicShell';
import { navigate } from '../../utils/publicRouter';

/* ------------------------------------------------------------------ */
/* STANDALONE STATUS PAGES (full-screen)                              */
/* ------------------------------------------------------------------ */

const StatusScreen: React.FC<{
  code?: string;
  icon: LucideIcon;
  title: string;
  message: string;
  tone?: 'purple' | 'rose' | 'amber';
  primary?: { label: string; onClick: () => void };
  secondary?: { label: string; onClick: () => void };
}> = ({ code, icon: Icon, title, message, tone = 'purple', primary, secondary }) => {
  const toneClasses = {
    purple: 'border-purple-500/40 bg-purple-500/10 text-purple-300',
    rose: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
    amber: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  }[tone];

  return (
    <PublicShell title="" narrow>
      <div className="flex flex-col items-center gap-4 py-6 text-center">
        <div className={`flex h-16 w-16 items-center justify-center rounded-2xl border ${toneClasses}`}>
          <Icon className="h-7 w-7" />
        </div>
        {code && <p className="font-cyber text-4xl font-black tracking-widest text-white/90">{code}</p>}
        <h1 className="font-cyber text-base font-bold uppercase tracking-[0.14em] text-white">{title}</h1>
        <p className="max-w-sm font-mono text-[11px] leading-relaxed text-purple-200/60">{message}</p>
        <div className="mt-2 flex w-full max-w-xs flex-col gap-2">
          {primary && <button onClick={primary.onClick} className={publicPrimaryBtn}>{primary.label}</button>}
          {secondary && <button onClick={secondary.onClick} className={publicSecondaryBtn}>{secondary.label}</button>}
        </div>
      </div>
    </PublicShell>
  );
};

export const NotFoundPage: React.FC = () => (
  <StatusScreen
    code="404"
    icon={Ghost}
    title="Signal Not Found"
    message="This route doesn't exist in NEXSUS, or the page has moved. Double-check the URL, or head back to the command center."
    primary={{ label: 'Back to Command Center', onClick: () => navigate('/') }}
  />
);

export const ForbiddenPage: React.FC = () => (
  <StatusScreen
    code="403"
    icon={ShieldOff}
    title="Access Restricted"
    tone="rose"
    message="Your operator role doesn't have clearance for this resource. If you believe this is an error, contact your workspace administrator."
    primary={{ label: 'Back to Command Center', onClick: () => navigate('/') }}
    secondary={{ label: 'Contact Support', onClick: () => navigate('/support') }}
  />
);

export const ServerErrorPage: React.FC<{ onRetry?: () => void }> = ({ onRetry }) => (
  <StatusScreen
    code="500"
    icon={ServerCrash}
    title="Something Broke on Our End"
    tone="rose"
    message="ARCHON hit an unexpected error processing that request. Our team has been notified automatically. Try again in a moment."
    primary={{ label: 'Retry', onClick: onRetry || (() => window.location.reload()) }}
    secondary={{ label: 'Contact Support', onClick: () => navigate('/support') }}
  />
);

export const MaintenancePage: React.FC = () => (
  <StatusScreen
    icon={Construction}
    title="Scheduled Maintenance"
    tone="amber"
    message="NEXSUS is undergoing scheduled maintenance to improve platform reliability. We expect to be back shortly — no case data is affected."
    primary={{ label: 'Check Again', onClick: () => window.location.reload() }}
  />
);

export const OfflinePage: React.FC = () => (
  <StatusScreen
    icon={WifiOff}
    title="You're Offline"
    tone="amber"
    message="NEXSUS can't reach the network right now. Live threat telemetry and specialist agent updates are paused until your connection is restored."
    primary={{ label: 'Retry Connection', onClick: () => window.location.reload() }}
  />
);

export const SessionExpiredPage: React.FC = () => (
  <StatusScreen
    icon={TimerOff}
    title="Session Expired"
    tone="amber"
    message="For your security, your operator session has timed out due to inactivity. Please sign in again to resume."
    primary={{ label: 'Sign In Again', onClick: () => navigate('/login') }}
  />
);

/* ------------------------------------------------------------------ */
/* REUSABLE, EMBEDDABLE UX-STATE COMPONENTS                           */
/* (drop into any panel/widget instead of building a bespoke state)   */
/* ------------------------------------------------------------------ */

export const EmptyState: React.FC<{
  icon?: LucideIcon;
  title: string;
  message?: string;
  action?: { label: string; onClick: () => void };
}> = ({ icon: Icon = Inbox, title, message, action }) => (
  <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-purple-500/25 bg-purple-950/10 px-6 py-10 text-center">
    <Icon className="h-6 w-6 text-purple-300/50" />
    <p className="font-mono text-[11px] font-semibold uppercase tracking-wider text-purple-200/70">{title}</p>
    {message && <p className="max-w-xs font-mono text-[10px] text-purple-200/40">{message}</p>}
    {action && (
      <button onClick={action.onClick} className="mt-2 rounded-md border border-purple-500/40 bg-purple-500/10 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-purple-200 hover:bg-purple-500/20">
        {action.label}
      </button>
    )}
  </div>
);

export const NoSearchResultsState: React.FC<{ query?: string; onClear?: () => void }> = ({ query, onClear }) => (
  <EmptyState
    icon={SearchX}
    title="No Results Found"
    message={query ? `Nothing matched "${query}". Try a different term or filter.` : 'Nothing matched your search. Try a different term or filter.'}
    action={onClear ? { label: 'Clear Search', onClick: onClear } : undefined}
  />
);

export const LoadingState: React.FC<{ label?: string }> = ({ label = 'Loading…' }) => (
  <div className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center">
    <Loader2 className="h-5 w-5 animate-spin text-purple-300" />
    <p className="font-mono text-[10px] uppercase tracking-wider text-purple-200/50">{label}</p>
  </div>
);

export const ErrorState: React.FC<{ message?: string; onRetry?: () => void }> = ({
  message = 'Something went wrong loading this data.',
  onRetry,
}) => (
  <div className="flex flex-col items-center gap-2 rounded-lg border border-rose-500/25 bg-rose-500/5 px-6 py-8 text-center">
    <AlertCircle className="h-6 w-6 text-rose-300/70" />
    <p className="max-w-xs font-mono text-[11px] text-rose-200/80">{message}</p>
    {onRetry && (
      <button onClick={onRetry} className="mt-1 flex items-center gap-1.5 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-rose-200 hover:bg-rose-500/20">
        <RefreshCw className="h-3 w-3" /> Retry
      </button>
    )}
  </div>
);

export const SuccessState: React.FC<{ title: string; message?: string; action?: { label: string; onClick: () => void } }> = ({
  title,
  message,
  action,
}) => (
  <div className="flex flex-col items-center gap-2 rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-6 py-8 text-center">
    <CheckCircle2 className="h-6 w-6 text-emerald-300" />
    <p className="font-mono text-[11px] font-semibold uppercase tracking-wider text-emerald-200">{title}</p>
    {message && <p className="max-w-xs font-mono text-[10px] text-emerald-200/60">{message}</p>}
    {action && (
      <button onClick={action.onClick} className="mt-2 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-emerald-200 hover:bg-emerald-500/20">
        {action.label}
      </button>
    )}
  </div>
);

/** Maps a public status route to its component — used by PublicApp.tsx */
export const STATUS_ROUTE_COMPONENTS: Record<string, React.FC> = {
  '/404': NotFoundPage,
  '/403': ForbiddenPage,
  '/500': ServerErrorPage,
  '/maintenance': MaintenancePage,
  '/offline': OfflinePage,
  '/session-expired': SessionExpiredPage,
};
