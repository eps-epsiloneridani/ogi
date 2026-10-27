import type { AgentStep } from "../../../types/agent";

export function StepError({ step }: { step: AgentStep }) {
  const message =
    step.llm_output ||
    (typeof step.tool_output?.error === "string" ? step.tool_output.error : "") ||
    "This step failed.";

  return (
    <div className="space-y-1">
      <div className="text-[11px] font-semibold text-danger-text">Error</div>
      <p className="whitespace-pre-wrap text-[11px] text-danger-text">{message}</p>
    </div>
  );
}
