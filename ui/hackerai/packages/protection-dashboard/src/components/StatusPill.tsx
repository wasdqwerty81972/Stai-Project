import { CircleCheck, CircleX, TriangleAlert } from "lucide-react";
import type { ProtectionState } from "../protection-api";

const stateLabels: Record<ProtectionState, string> = {
  active: "Active",
  degraded: "Degraded",
  unavailable: "Unavailable",
};

export function StatusPill({ state }: { state: ProtectionState }) {
  const Icon =
    state === "active" ? CircleCheck : state === "degraded" ? TriangleAlert : CircleX;
  return (
    <span className={`status-pill status-${state}`}>
      <Icon aria-hidden="true" size={15} />
      {stateLabels[state]}
    </span>
  );
}
