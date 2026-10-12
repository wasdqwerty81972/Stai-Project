import { ArrowUpRight, FileWarning } from "lucide-react";
import type { DetectionRecord } from "../protection-api";

export function DetectionRow({
  detection,
  onOpen,
}: {
  detection: DetectionRecord;
  onOpen?: (detection: DetectionRecord) => void;
}) {
  const content = (
    <>
      <span className="detection-symbol" aria-hidden="true">
        <FileWarning size={17} />
      </span>
      <span className="detection-copy">
        <strong>{detection.file_path || "Path not reported"}</strong>
        <span>
          {detection.severity} · {detection.confidence} confidence · rule action: {detection.action}
        </span>
      </span>
      <span className="detection-state">
        {detection.triage_enqueued ? "Queued for AI review" : "Recorded"}
      </span>
      {onOpen && <ArrowUpRight size={16} className="detection-arrow" aria-hidden="true" />}
    </>
  );

  if (onOpen) {
    return (
      <button
        className="detection-row detection-row-button"
        onClick={() => onOpen(detection)}
        type="button"
        aria-label={`Open analysis for ${detection.file_path}`}
      >
        {content}
      </button>
    );
  }

  return <div className="detection-row">{content}</div>;
}
