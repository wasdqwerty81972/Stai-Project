import { EmptyState } from "./EmptyState";
import { DetectionRow } from "./DetectionRow";
import { PageHeading } from "./PageHeading";
import type { DetectionRecord } from "../protection-api";

export function ThreatActivity({
  threats,
  error,
}: {
  threats: DetectionRecord[] | null;
  error: string | null;
}) {
  return (
    <>
      <PageHeading
        eyebrow="LOCAL EVENT RECORDS"
        title="Threat activity"
        description="Detections are listed separately from confirmed blocks and quarantine outcomes."
      />
      <section className="panel">
        <div className="panel-heading panel-heading-wide">
          <div>
            <div className="eyebrow">DETECTION LOG</div>
            <h2>Recorded activity</h2>
          </div>
          {threats !== null && !error && <span className="subtle-count">{threats.length} recorded</span>}
        </div>
        {error ? (
          <div role="alert" className="inline-alert error-alert">{error}</div>
        ) : threats === null ? (
          <div className="loading-row"><span className="spinner" /> Loading threat activity…</div>
        ) : threats.length === 0 ? (
          <EmptyState title="No detections recorded" description="The local service has not stored any detections." />
        ) : (
          <div className="detection-list">
            {threats.map((detection) => <DetectionRow key={detection.detection_id} detection={detection} />)}
          </div>
        )}
        <p className="helper-note">A rule configured to block is not counted as blocked unless the service confirms the file operation was denied.</p>
      </section>
    </>
  );
}
