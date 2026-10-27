import type { ResolvedTheme } from "./theme";

/**
 * Theme-dependent colours for the graph canvas CHROME (labels, selection/pin
 * highlights, hover/selection edge accents, avatar ring, export fallback).
 *
 * The entity-type node/edge DATA palette is deliberately NOT here: it stays
 * identical across themes (see types/entity.ts and backend models/entity.py),
 * so this module only owns the chrome that must react to data-theme.
 */
export interface GraphChromeColors {
  /** Canvas label text colour (matches --color-text). */
  labelColor: string;
  /** Selected-node label pill text. */
  selectedLabelColor: string;
  /** Selected-node label pill background. */
  selectedLabelBackground: string;
  /** Pinned-node label pill text. */
  pinnedLabelColor: string;
  /** Pinned-node label pill background. */
  pinnedLabelBackground: string;
  /** Connection-draft label pill text. */
  connectionLabelColor: string;
  /** Connection-draft label pill background. */
  connectionLabelBackground: string;
  /** Selected edge accent colour. */
  selectedEdgeColor: string;
  /** Hovered edge accent colour. */
  hoveredEdgeColor: string;
  /** Shadow drawn under the hovered-node label pill. */
  labelShadowColor: string;
  /** Avatar ring stroke used in the image-export path. */
  avatarRingStroke: string;
  /** Fallback canvas background for image export. */
  exportFallbackBackground: string;
}

/** Dark chrome — byte-for-byte the pre-light-mode hard-coded values. */
const DARK_CHROME: GraphChromeColors = {
  labelColor: "#e1e4ed",
  selectedLabelColor: "#111827",
  selectedLabelBackground: "#f3f4f6",
  pinnedLabelColor: "#dbeafe",
  pinnedLabelBackground: "#1e3a8a",
  connectionLabelColor: "#fef3c7",
  connectionLabelBackground: "#92400e",
  selectedEdgeColor: "#60a5fa",
  hoveredEdgeColor: "#93c5fd",
  labelShadowColor: "rgba(15, 23, 42, 0.25)",
  avatarRingStroke: "rgba(255, 255, 255, 0.2)",
  exportFallbackBackground: "#0b1020",
};

/**
 * Light chrome. The selected label pill inverts (dark pill + light text) so it
 * stays visible on a light canvas; edge accents deepen for contrast; the label
 * shadow and avatar ring soften. Pinned/connection pills are dark on both
 * themes already, so they stay identical.
 */
const LIGHT_CHROME: GraphChromeColors = {
  labelColor: "#1a1d27",
  selectedLabelColor: "#f3f4f6",
  selectedLabelBackground: "#111827",
  pinnedLabelColor: "#dbeafe",
  pinnedLabelBackground: "#1e3a8a",
  connectionLabelColor: "#fef3c7",
  connectionLabelBackground: "#92400e",
  selectedEdgeColor: "#2563eb",
  hoveredEdgeColor: "#3b82f6",
  labelShadowColor: "rgba(15, 23, 42, 0.15)",
  avatarRingStroke: "rgba(15, 23, 42, 0.12)",
  exportFallbackBackground: "#ffffff",
};

export function getGraphChromeColors(theme: ResolvedTheme): GraphChromeColors {
  return theme === "light" ? LIGHT_CHROME : DARK_CHROME;
}

/*
 * Active-chrome holder. The Sigma `defaultDrawNodeHover` callback is a module
 * function installed once at renderer init, so it cannot close over a React
 * state value. It reads the current chrome from here; GraphCanvas updates this
 * holder whenever the resolved theme changes. Defaults to dark so a renderer
 * created before React mounts still draws the (unchanged) dark chrome.
 */
let activeChrome: GraphChromeColors = DARK_CHROME;

export function setActiveGraphChrome(chrome: GraphChromeColors): void {
  activeChrome = chrome;
}

export function getActiveGraphChrome(): GraphChromeColors {
  return activeChrome;
}
