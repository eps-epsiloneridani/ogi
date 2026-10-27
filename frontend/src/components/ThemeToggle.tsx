import { useState } from "react";
import { Monitor, Moon, Sun } from "lucide-react";
import {
  getStoredPreference,
  setTheme,
  type ThemePreference,
} from "../lib/theme";

const ORDER: ThemePreference[] = ["light", "dark", "system"];

const ICONS: Record<ThemePreference, typeof Sun> = {
  light: Sun,
  dark: Moon,
  system: Monitor,
};

const LABELS: Record<ThemePreference, string> = {
  light: "Light",
  dark: "Dark",
  system: "System",
};

export function ThemeToggle() {
  const [preference, setPreference] = useState<ThemePreference>(
    () => getStoredPreference() ?? "system",
  );

  const cycle = () => {
    const next = ORDER[(ORDER.indexOf(preference) + 1) % ORDER.length];
    setPreference(next);
    setTheme(next);
  };

  const Icon = ICONS[preference];

  return (
    <button
      onClick={cycle}
      className="p-1.5 text-text-muted hover:text-text hover:bg-surface-hover rounded"
      title={`Theme: ${LABELS[preference]} (click to change)`}
      aria-label={`Theme: ${LABELS[preference]}`}
    >
      <Icon size={14} />
    </button>
  );
}
