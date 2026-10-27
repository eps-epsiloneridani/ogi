import { describe, expect, it } from "vitest";
import {
  getActiveGraphChrome,
  getGraphChromeColors,
  setActiveGraphChrome,
} from "./graphTheme";

describe("getGraphChromeColors", () => {
  it("returns the pre-light-mode dark values byte-for-byte", () => {
    const dark = getGraphChromeColors("dark");
    expect(dark.labelColor).toBe("#e1e4ed");
    expect(dark.selectedLabelColor).toBe("#111827");
    expect(dark.selectedLabelBackground).toBe("#f3f4f6");
    expect(dark.pinnedLabelColor).toBe("#dbeafe");
    expect(dark.pinnedLabelBackground).toBe("#1e3a8a");
    expect(dark.connectionLabelColor).toBe("#fef3c7");
    expect(dark.connectionLabelBackground).toBe("#92400e");
    expect(dark.selectedEdgeColor).toBe("#60a5fa");
    expect(dark.hoveredEdgeColor).toBe("#93c5fd");
    expect(dark.labelShadowColor).toBe("rgba(15, 23, 42, 0.25)");
    expect(dark.avatarRingStroke).toBe("rgba(255, 255, 255, 0.2)");
    expect(dark.exportFallbackBackground).toBe("#0b1020");
  });

  it("inverts the selected label pill and deepens edges on light", () => {
    const light = getGraphChromeColors("light");
    expect(light.labelColor).toBe("#1a1d27");
    expect(light.selectedLabelColor).toBe("#f3f4f6");
    expect(light.selectedLabelBackground).toBe("#111827");
    expect(light.selectedEdgeColor).toBe("#2563eb");
    expect(light.hoveredEdgeColor).toBe("#3b82f6");
    expect(light.avatarRingStroke).toBe("rgba(15, 23, 42, 0.12)");
    expect(light.exportFallbackBackground).toBe("#ffffff");
  });

  it("keeps the pinned and connection pills identical across themes", () => {
    const dark = getGraphChromeColors("dark");
    const light = getGraphChromeColors("light");
    expect(light.pinnedLabelColor).toBe(dark.pinnedLabelColor);
    expect(light.pinnedLabelBackground).toBe(dark.pinnedLabelBackground);
    expect(light.connectionLabelColor).toBe(dark.connectionLabelColor);
    expect(light.connectionLabelBackground).toBe(dark.connectionLabelBackground);
  });
});

describe("active chrome holder", () => {
  it("defaults to the dark chrome", () => {
    expect(getActiveGraphChrome().labelColor).toBe("#e1e4ed");
  });

  it("tracks the last chrome set", () => {
    setActiveGraphChrome(getGraphChromeColors("light"));
    expect(getActiveGraphChrome().labelColor).toBe("#1a1d27");
    setActiveGraphChrome(getGraphChromeColors("dark"));
    expect(getActiveGraphChrome().labelColor).toBe("#e1e4ed");
  });
});
