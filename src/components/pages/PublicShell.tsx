import React from 'react';
import { Shield, ArrowLeft } from 'lucide-react';
import { navigate } from '../../utils/publicRouter';

/**
 * Chrome-free shell for pages a visitor can land on before (or outside)
 * the authenticated command-center: legal docs, auth screens, status pages.
 * Keeps the same gothic/cyber-purple identity as the dashboard without
 * pulling in Sidebar/TopBar/EventStream.
 */
export const PublicShell: React.FC<{
  title: string;
  subtitle?: string;
  narrow?: boolean;
  backTo?: { label: string; href: string };
  children: React.ReactNode;
}> = ({ title, subtitle, narrow = false, backTo, children }) => (
  <div
    className="relative min-h-screen w-full overflow-y-auto text-slate-100 font-sans"
    style={{ backgroundColor: '#06020e' }}
    data-theme="cyber-purple"
  >
    <div className="pointer-events-none fixed inset-0 cyber-grid opacity-60" />
    <div
      className="pointer-events-none fixed -top-32 -left-32 h-96 w-96 rounded-full blur-3xl"
      style={{ backgroundColor: 'rgba(147, 51, 234, 0.16)' }}
    />
    <div
      className="pointer-events-none fixed -bottom-32 -right-32 h-96 w-96 rounded-full blur-3xl"
      style={{ backgroundColor: 'rgba(109, 40, 217, 0.14)' }}
    />

    <div className="relative z-10 mx-auto flex min-h-screen w-full flex-col">
      <header className="flex items-center justify-between border-b border-purple-500/20 px-5 py-4 sm:px-8">
        <button
          onClick={() => navigate('/')}
          className="flex items-center gap-2 text-left"
        >
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-purple-500/40 bg-purple-500/10 text-purple-300">
            <Shield className="h-4 w-4" />
          </div>
          <span className="font-cyber text-sm font-bold tracking-[0.2em] text-white">NEXSUS</span>
        </button>
        {backTo && (
          <button
            onClick={() => navigate(backTo.href)}
            className="flex items-center gap-1.5 rounded-md border border-purple-500/40 bg-purple-500/10 px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-purple-200 transition-colors hover:bg-purple-500/20"
          >
            <ArrowLeft className="h-3 w-3" /> {backTo.label}
          </button>
        )}
      </header>

      <main className={`mx-auto w-full flex-1 px-5 py-10 sm:px-8 ${narrow ? 'max-w-lg' : 'max-w-3xl'}`}>
        <div className="mb-8">
          <h1 className="font-cyber text-xl font-bold tracking-[0.14em] text-white sm:text-2xl">{title}</h1>
          {subtitle && (
            <p className="mt-2 max-w-2xl font-mono text-[11px] leading-relaxed text-purple-200/60">{subtitle}</p>
          )}
        </div>
        {children}
      </main>

      <footer className="border-t border-purple-500/20 px-5 py-4 text-center sm:px-8">
        <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-purple-200/30">
          &copy; {new Date().getFullYear()} NEXSUS. All rights reserved.
        </p>
      </footer>
    </div>
  </div>
);

export const publicInput =
  'w-full rounded-md border border-purple-500/30 bg-purple-950/20 px-3 py-2.5 font-mono text-xs text-slate-100 placeholder:text-purple-200/30 outline-none transition-colors focus:border-purple-400/60';

export const publicLabel = 'mb-1.5 block font-mono text-[10px] uppercase tracking-wider text-purple-200/60';

export const publicPrimaryBtn =
  'w-full rounded-md border border-purple-400/50 bg-purple-600/80 px-4 py-2.5 text-center font-cyber text-xs font-bold uppercase tracking-widest text-white shadow-[0_0_20px_rgba(168,85,247,0.25)] transition-colors hover:bg-purple-600 disabled:cursor-not-allowed disabled:opacity-50';

export const publicSecondaryBtn =
  'w-full rounded-md border border-purple-500/30 bg-purple-500/5 px-4 py-2.5 text-center font-mono text-[11px] uppercase tracking-wider text-purple-200 transition-colors hover:bg-purple-500/10';

export const publicLink = 'text-purple-300 underline decoration-purple-500/40 underline-offset-2 hover:text-purple-200';
