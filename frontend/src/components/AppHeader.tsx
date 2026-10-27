import { Link } from "react-router";
import { ThemeToggle } from "./ThemeToggle";

/**
 * Slim app header for the standalone post-login pages that render outside the
 * workspace chrome (projects, security, admin invites): brand-left, theme
 * toggle right. Matches the page-header idiom TelemetryAdmin already uses
 * (h-12, bg-surface, border-b) so every protected page carries the toggle in
 * one canonical place.
 */
export function AppHeader() {
  return (
    <header className="flex items-center h-12 px-4 bg-surface border-b border-border">
      <Link
        to="/projects"
        className="text-sm font-semibold text-text hover:text-accent"
        title="OpenGraph Intel"
      >
        OpenGraph Intel
      </Link>
      <div className="ml-auto">
        <ThemeToggle />
      </div>
    </header>
  );
}