import { useState } from "react";
import { AlertCircle, CheckCircle2, Clock3, HardDrive, LoaderCircle, XCircle } from "lucide-react";
import type { ScanJob, ScanScope } from "../protection-api";
import { EmptyState } from "./EmptyState";
import { PageHeading } from "./PageHeading";

export function ScanView({
  scan,
  scanError,
  onStart,
  onCancel,
  unavailable,
}: {
  scan: ScanJob | null;
  scanError: string | null;
  onStart: (scope: ScanScope) => Promise<void>;
  onCancel: () => Promise<void>;
  unavailable: boolean;
}) {
  const [starting, setStarting] = useState<ScanScope | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const start = async (scope: ScanScope) => {
    setStarting(scope);
    setActionError(null);
    try {
      await onStart(scope);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Unable to start the scan.");
    } finally {
      setStarting(null);
    }
  };
  const busy = scan?.state === "queued" || scan?.state === "running";
  const progress =
    scan?.files_total && scan.files_total > 0
      ? Math.min(100, Math.round((scan.files_scanned / scan.files_total) * 100))
      : 0;

  return (
    <>
      <PageHeading
        eyebrow="SCAN CENTER"
        title="Scans"
        description="Start a bounded local scan and review its stored progress and results."
      />
      {(scanError || actionError) && <div className="inline-alert error-alert" role="alert">{scanError || actionError}</div>}
      <section className="panel scan-center-panel">
        <div className="panel-heading">
          <div>
            <div className="eyebrow">NEW SCAN</div>
            <h2>Choose a scan scope</h2>
          </div>
          <span className="panel-icon"><HardDrive size={18} aria-hidden="true" /></span>
        </div>
        <div className="scan-scope-grid">
          <button
            className="scope-card"
            disabled={unavailable || Boolean(busy) || starting !== null}
            onClick={() => void start("quick")}
            type="button"
          >
            <span className="scope-card-icon"><Clock3 size={20} aria-hidden="true" /></span>
            <strong>{starting === "quick" ? "Starting…" : "Quick Scan"}</strong>
            <span>Common user execution and startup locations</span>
          </button>
          <button
            className="scope-card"
            disabled={unavailable || Boolean(busy) || starting !== null}
            onClick={() => void start("system")}
            type="button"
          >
            <span className="scope-card-icon"><HardDrive size={20} aria-hidden="true" /></span>
            <strong>{starting === "system" ? "Starting…" : "System Scan"}</strong>
            <span>Accessible fixed local volumes</span>
          </button>
        </div>
        {unavailable && <p className="helper-note">Scans are disabled until the local protection service is available.</p>}
      </section>

      <section className="panel scan-result-panel">
        <div className="panel-heading">
          <div>
            <div className="eyebrow">CURRENT RESULT</div>
            <h2>Scan progress</h2>
          </div>
          {scan && <ScanStateIcon state={scan.state} />}
        </div>
        {!scan ? (
          <EmptyState title="No scan started in this session" description="Completed scan history will appear here when the local service provides it." />
        ) : (
          <div className="scan-result-content" aria-live="polite">
            <div className="scan-result-title">
              <div>
                <strong>{scan.scope === "quick" ? "Quick Scan" : "System Scan"}</strong>
                <span>Job {scan.job_id}</span>
              </div>
              <span className={`scan-state-label state-${scan.state}`}>{scan.state}</span>
            </div>
            <div className="progress-meta">
              <span>{scan.files_scanned} of {scan.files_total ?? "—"} files scanned</span>
              {scan.files_total !== null && <span>{progress}%</span>}
            </div>
            <div
              className="progress-track"
              role="progressbar"
              aria-label="Scan progress"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={progress}
            >
              <span style={{ width: `${progress}%` }} />
            </div>
            <div className="scan-result-stats">
              <div><strong>{scan.detections}</strong><span>detections</span></div>
              <div><strong>{scan.errors}</strong><span>access errors</span></div>
              <div><strong>{scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}</strong><span>started</span></div>
            </div>
            {scan.error_message && <div role="alert" className="inline-alert error-alert">{scan.error_message}</div>}
            {busy && (
              <button className="button button-secondary" onClick={() => void onCancel()} type="button">
                Cancel scan
              </button>
            )}
            {scan.state === "completed" && <div className="completion-note"><CheckCircle2 size={15} aria-hidden="true" /> Results saved by the local service</div>}
          </div>
        )}
      </section>
    </>
  );
}

function ScanStateIcon({ state }: { state: ScanJob["state"] }) {
  if (state === "running" || state === "queued") {
    return <LoaderCircle className="spin panel-icon" size={18} aria-label="Scan in progress" />;
  }
  if (state === "completed") return <CheckCircle2 className="success-icon" size={18} aria-label="Scan completed" />;
  if (state === "cancelled") return <XCircle className="muted-icon" size={18} aria-label="Scan cancelled" />;
  return <AlertCircle className="error-icon" size={18} aria-label="Scan failed" />;
}
