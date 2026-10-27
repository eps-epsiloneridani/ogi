import { beforeEach, describe, expect, it, vi } from "vitest";
import { getStoredPreference, resolveTheme, setTheme } from "./theme";

const THEME_KEY = "ogi-theme";

// This jsdom environment ships without a working localStorage (see AGENTS.md:
// the pre-existing graphStore failures stem from the same gap), so the theme
// module's persistence path is exercised against an in-memory stand-in.
function installLocalStorage() {
  const store = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => (store.has(key) ? store.get(key)! : null),
    setItem: (key: string, value: string) => void store.set(key, String(value)),
    removeItem: (key: string) => void store.delete(key),
    clear: () => void store.clear(),
  });
}

function mockMatchMedia(matchesDark: boolean) {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    configurable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: query.includes("dark") ? matchesDark : !matchesDark,
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
}

describe("resolveTheme", () => {
  beforeEach(() => {
    installLocalStorage();
    delete document.documentElement.dataset.theme;
  });

  it("returns light for an explicit light preference", () => {
    expect(resolveTheme("light")).toBe("light");
  });

  it("returns dark for an explicit dark preference", () => {
    expect(resolveTheme("dark")).toBe("dark");
  });

  it("follows the OS when the preference is system (OS dark)", () => {
    mockMatchMedia(true);
    expect(resolveTheme("system")).toBe("dark");
  });

  it("follows the OS when the preference is system (OS light)", () => {
    mockMatchMedia(false);
    expect(resolveTheme("system")).toBe("light");
  });

  it("falls back to the OS when no preference is stored", () => {
    mockMatchMedia(true);
    expect(resolveTheme(null)).toBe("dark");
  });

  it("lets a stored dark win over an OS light scheme", () => {
    mockMatchMedia(false);
    localStorage.setItem(THEME_KEY, "dark");
    expect(resolveTheme()).toBe("dark");
  });

  it("lets a stored light win over an OS dark scheme", () => {
    mockMatchMedia(true);
    localStorage.setItem(THEME_KEY, "light");
    expect(resolveTheme()).toBe("light");
  });

  it("treats an invalid stored value as no preference and falls back to the OS", () => {
    mockMatchMedia(true);
    localStorage.setItem(THEME_KEY, "not-a-theme");
    expect(getStoredPreference()).toBeNull();
    expect(resolveTheme()).toBe("dark");
  });
});

describe("setTheme", () => {
  beforeEach(() => {
    installLocalStorage();
    delete document.documentElement.dataset.theme;
  });

  it("persists the preference and sets data-theme", () => {
    setTheme("light");
    expect(localStorage.getItem(THEME_KEY)).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("resolves the system preference via the OS", () => {
    mockMatchMedia(false);
    setTheme("system");
    expect(localStorage.getItem(THEME_KEY)).toBe("system");
    expect(document.documentElement.dataset.theme).toBe("light");
  });
});
