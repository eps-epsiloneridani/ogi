import { useSyncExternalStore } from "react";

export type ThemePreference = "light" | "dark" | "system";
export type ResolvedTheme = "light" | "dark";

const STORAGE_KEY = "ogi-theme";

const THEME_COLORS: Record<ResolvedTheme, string> = {
  dark: "#0f1117",
  light: "#ffffff",
};

const VALID_PREFERENCES: readonly ThemePreference[] = [
  "light",
  "dark",
  "system",
];

const listeners = new Set<() => void>();

function notify(): void {
  for (const listener of listeners) {
    listener();
  }
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function systemPrefersDark(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return true;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

export function getStoredPreference(): ThemePreference | null {
  if (typeof localStorage === "undefined") return null;
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    if (value && (VALID_PREFERENCES as readonly string[]).includes(value)) {
      return value as ThemePreference;
    }
  } catch {
    // localStorage may throw in private browsing; treat as no preference.
  }
  return null;
}

export function resolveTheme(pref?: ThemePreference | null): ResolvedTheme {
  const preference = pref === undefined ? getStoredPreference() : pref;
  if (preference === "light") return "light";
  if (preference === "dark") return "dark";
  // "system" or no stored preference: follow the OS, defaulting to dark when
  // the OS scheme cannot be determined.
  return systemPrefersDark() ? "dark" : "light";
}

export function getResolvedTheme(): ResolvedTheme {
  return resolveTheme();
}

function applyThemeMeta(resolved: ResolvedTheme): void {
  if (typeof document === "undefined") return;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) {
    meta.setAttribute("content", THEME_COLORS[resolved]);
  }
}

export function applyTheme(resolved: ResolvedTheme): void {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.theme = resolved;
  applyThemeMeta(resolved);
}

export function setTheme(preference: ThemePreference): void {
  if (typeof localStorage !== "undefined") {
    try {
      localStorage.setItem(STORAGE_KEY, preference);
    } catch {
      // Persistence is best-effort; the in-memory theme still applies.
    }
  }
  applyTheme(resolveTheme(preference));
  notify();
}

let systemListenerAttached = false;

/**
 * Applies the resolved theme on boot (idempotent with the inline head script)
 * and listens for OS scheme changes so the "system" position tracks the OS.
 */
export function initTheme(): void {
  applyTheme(resolveTheme());

  if (systemListenerAttached || typeof window === "undefined" || !window.matchMedia) {
    return;
  }
  systemListenerAttached = true;
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  media.addEventListener("change", () => {
    const preference = getStoredPreference();
    // Only follow the OS when no explicit light/dark preference is stored.
    if (preference === null || preference === "system") {
      applyTheme(resolveTheme());
      notify();
    }
  });
}

/** Reactive hook that returns the currently resolved theme. */
export function useResolvedTheme(): ResolvedTheme {
  return useSyncExternalStore(subscribe, getResolvedTheme, getResolvedTheme);
}
