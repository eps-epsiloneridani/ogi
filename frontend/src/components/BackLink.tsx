import { useNavigate } from "react-router";
import { ArrowLeft } from "lucide-react";

/**
 * Minimal returns affordance for the standalone post-login pages that render
 * outside the workspace chrome (security, admin invites): history-back with a
 * deterministic fallback to the projects home for direct-entry arrivals.
 */
export function BackLink() {
  const navigate = useNavigate();
  return (
    <button
      onClick={() => (window.history.length > 1 ? navigate(-1) : navigate("/projects"))}
      className="flex items-center gap-1.5 text-xs text-text-muted hover:text-text"
      title="Back"
    >
      <ArrowLeft size={13} /> Back
    </button>
  );
}