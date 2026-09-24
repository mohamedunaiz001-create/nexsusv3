import { useCurrentPath, useRouterInstance } from "./router";

export function usePathname(): string {
  return useCurrentPath();
}

export function useRouter() {
  return useRouterInstance();
}

export function useSearchParams(): URLSearchParams {
  return new URLSearchParams(typeof window !== "undefined" ? window.location.search : "");
}

export function useParams<T extends Record<string, string> = Record<string, string>>(): T {
  const path = typeof window !== "undefined" ? window.location.pathname : "";
  const parts = path.split("/").filter(Boolean);
  return { agentType: parts[parts.length - 1] || "" } as unknown as T;
}
