export const PUBLIC_ROUTES = [
  "/login",
  "/register",
  "/verify-email",
  "/forgot-password",
  "/reset-password",
  "/onboarding",
  "/legal",
  "/support",
  "/help-center",
  "/404",
  "/403",
  "/500",
  "/maintenance",
  "/offline",
  "/session-expired",
] as const;

export type PublicRoute = (typeof PUBLIC_ROUTES)[number] | string;

export function getPath(): string {
  if (typeof window === "undefined") return "/";
  return window.location.pathname || "/";
}

export function isPublicRoute(pathname?: string): boolean {
  const p = pathname || getPath();
  if (p === "/" || p === "/dashboard") return false;
  if (p.startsWith("/legal/")) return true;
  return PUBLIC_ROUTES.some((route) => p === route || p.startsWith(route + "/"));
}

export function navigateTo(path: string, replace = false): void {
  if (typeof window === "undefined") return;
  if (replace) {
    window.history.replaceState({}, "", path);
  } else {
    window.history.pushState({}, "", path);
  }
  window.dispatchEvent(new PopStateEvent("popstate"));
}
