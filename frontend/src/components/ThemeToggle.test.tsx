import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ThemeToggle } from "./ThemeToggle";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const THEME_KEY = "ogi-theme";

// This jsdom environment ships without a working localStorage, so the toggle's
// persistence is exercised against an in-memory stand-in.
function installLocalStorage() {
  const store = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => (store.has(key) ? store.get(key)! : null),
    setItem: (key: string, value: string) => void store.set(key, String(value)),
    removeItem: (key: string) => void store.delete(key),
    clear: () => void store.clear(),
  });
}

function renderToggle(): { container: HTMLDivElement; unmount: () => void } {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root: Root = createRoot(container);
  act(() => {
    root.render(<ThemeToggle />);
  });
  return {
    container,
    unmount: () => {
      act(() => root.unmount());
      container.remove();
    },
  };
}

describe("ThemeToggle", () => {
  beforeEach(() => {
    installLocalStorage();
    delete document.documentElement.dataset.theme;
  });

  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("defaults to the system position when nothing is stored", () => {
    const { container, unmount } = renderToggle();
    const button = container.querySelector("button")!;
    expect(button.getAttribute("aria-label")).toBe("Theme: System");
    unmount();
  });

  it("initialises from a stored preference", () => {
    localStorage.setItem(THEME_KEY, "light");
    const { container, unmount } = renderToggle();
    expect(container.querySelector("button")!.getAttribute("aria-label")).toBe(
      "Theme: Light",
    );
    unmount();
  });

  it("cycles light → dark → system and persists each step", () => {
    const { container, unmount } = renderToggle();
    const button = container.querySelector("button")!;

    act(() => {
      button.click();
    });
    expect(localStorage.getItem(THEME_KEY)).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(button.getAttribute("aria-label")).toBe("Theme: Light");

    act(() => {
      button.click();
    });
    expect(localStorage.getItem(THEME_KEY)).toBe("dark");
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(button.getAttribute("aria-label")).toBe("Theme: Dark");

    act(() => {
      button.click();
    });
    expect(localStorage.getItem(THEME_KEY)).toBe("system");
    expect(button.getAttribute("aria-label")).toBe("Theme: System");

    unmount();
  });
});
