/**
 * Minimal pathname-based router for standalone "logged-out" / public pages
 * (legal docs, auth screens, status pages). Intentionally dependency-free —
 * NEXSUS's authenticated shell is single-route/state-driven, so this only
 * has to cover a small, fixed table of production-grade utility routes.
 *
 * Server-side (server.ts) already falls back to index.html for every path
 * in production and Vite's `appType: 'spa'` does the same in dev, so any
 * of these paths are safe to deep-link / bookmark / share.
 */
import { useEffect, useState } from 'react';

export function usePathname(): string {
  const [pathname, setPathname] = useState(() => window.location.pathname);

  useEffect(() => {
    const onPop = () => setPathname(window.location.pathname);
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  return pathname;
}

export function navigate(path: string) {
  if (window.location.pathname === path) return;
  window.history.pushState({}, '', path);
  window.dispatchEvent(new PopStateEvent('popstate'));
}

/** Known public route prefixes — used to decide App.tsx vs PublicPages rendering. */
export const PUBLIC_ROUTE_PREFIXES = ['/legal', '/login', '/register', '/verify-email', '/forgot-password', '/reset-password', '/onboarding', '/support', '/help-center', '/404', '/403', '/500', '/maintenance', '/offline', '/session-expired'];

export function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTE_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}
