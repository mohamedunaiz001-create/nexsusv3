import { useState, useEffect } from "react";

type Listener = (path: string) => void;
const listeners = new Set<Listener>();

function getInitialPath(): string {
  if (typeof window === "undefined") return "/dashboard";
  const path = window.location.pathname;
  if (!path || path === "/" || path === "") return "/dashboard";
  return path;
}

let currentPath = getInitialPath();

export function navigate(to: string) {
  if (to === currentPath) return;
  currentPath = to;
  if (typeof window !== "undefined") {
    window.history.pushState({}, "", to);
  }
  listeners.forEach((fn) => fn(currentPath));
}

export function useCurrentPath(): string {
  const [path, setPath] = useState(currentPath);

  useEffect(() => {
    const handlePopState = () => {
      const p = window.location.pathname || "/dashboard";
      currentPath = p;
      setPath(p);
    };

    const listener: Listener = (newPath) => {
      setPath(newPath);
    };

    listeners.add(listener);
    window.addEventListener("popstate", handlePopState);

    return () => {
      listeners.delete(listener);
      window.removeEventListener("popstate", handlePopState);
    };
  }, []);

  return path;
}

export function useRouterInstance() {
  const pathname = useCurrentPath();
  return {
    push: (url: string) => navigate(url),
    replace: (url: string) => {
      currentPath = url;
      if (typeof window !== "undefined") {
        window.history.replaceState({}, "", url);
      }
      listeners.forEach((fn) => fn(url));
    },
    back: () => {
      if (typeof window !== "undefined") {
        window.history.back();
      }
    },
    forward: () => {
      if (typeof window !== "undefined") {
        window.history.forward();
      }
    },
    pathname,
  };
}
