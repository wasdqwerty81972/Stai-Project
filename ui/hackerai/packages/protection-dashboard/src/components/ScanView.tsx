import { useEffect, useState } from "react";
import { AlertCircle, CheckCircle2, Clock3, HardDrive, LoaderCircle, XCircle } from "lucide-react";
import type { ScanFrequency, ScanJob, ScanSchedule, ScanScope } from "../protection-api";
import { EmptyState } from "./EmptyState";
import { PageHeading } from "./PageHeading";

export function ScanView({
  scan,
  scanError,
  schedule,
  scheduleError,
  onStart,
  onCancel,
  onSaveSchedule,
  unavailable,
}: {
  scan: ScanJob | null;
  scanError: string | null;
  schedule: ScanSchedule | null;
  scheduleError: string | null;
  onStart: (scope: ScanScope) => Promise<void>;
  onCancel: () => Promise<void>;
  onSaveSchedule: (config: Pick<ScanSchedule, "enabled" | "frequency" | "scope" | "local_time" | "weekday">) => Promise<ScanSchedule>;
  unavailable: boolean;
}) {
  const [starting, setStarting] = useState<ScanScope | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [scheduleEnabled, setScheduleEnabled] = useState(false);
  const [frequency, setFrequency] = useState<ScanFrequency>("daily");
  const [scheduleScope, setScheduleScope] = useState<ScanScope>("quick");
  const [localTime, setLocalTime] = useState("03:00");
  const [weekday, setWeekday] = useState(0);
  const [scheduleEditing, setScheduleEditing] = useState(false);
  const [savingSchedule, setSavingSchedule] = useState(false);
  const [scheduleActionError, setScheduleActionError] = useState<string | null>(null);
  const [scheduleSaved, setScheduleSaved] = useState(false);

  useEffect(() => {
    if (!schedule || scheduleEditing) return;
    setScheduleEnabled(schedule.enabled);
    setFrequency(schedule.frequency);
    setScheduleScope(schedule.scope);
    setLocalTime(schedule.local_time);
    setWeekday(schedule.weekday ?? 0);
  }, [schedule, scheduleEditing]);
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
  const saveSchedule = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSavingSchedule(true);
    setScheduleActionError(null);
    setScheduleSaved(false);
    try {
      const saved = await onSaveSchedule({
        enabled: scheduleEnabled,
        frequency,
        scope: scheduleScope,
        local_time: localTime,
        weekday: frequency === "weekly" ? weekday : null,
      });
      setScheduleEditing(false);
      setScheduleEnabled(saved.enabled);
      setFrequency(saved.frequency);
      setScheduleScope(saved.scope);
      setLocalTime(saved.local_time);
      setWeekday(saved.weekday ?? 0);
      setScheduleSaved(true);
    } catch (error) {
      setScheduleActionError(error instanceof Error ? error.message : "Unable to save the schedule.");
    } finally {
      setSavingSchedule(false);
    }
  };
  const changeSchedule = <T,>(setter: (value: T) => void, value: T) => {
    setter(value);
    setScheduleEditing(true);
    setScheduleSaved(false);
  };
  const busy = scan?.state === "queued" || scan?.state === "running";
  const progress =
    scan?.files_total && scan.files_total > 0
      ? Math.min(100, Math.round((scan.files_scanned / scan.files_total) * 100))
      : 0;
  // A finished scan only proves coverage when the service reported a total,
  // actually read files, and recorded no errors, skips or unknown verdicts.
  const hasCoverageGaps = Boolean(
    scan && (
      scan.errors > 0 ||
      (scan.unknown_verdicts ?? 0) > 0 ||
      (scan.files_skipped ?? 0) > 0 ||
      scan.files_total === null ||
      scan.files_scanned === 0 ||
      (scan.files_total !== null && scan.files_scanned < scan.files_total)
    ),
  );

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

      <section className="panel scan-schedule-panel">
        <div className="panel-heading">
          <div>
            <div className="eyebrow">AUTOMATION</div>
            <h2>Scheduled scan</h2>
          </div>
          <span className="panel-icon"><Clock3 size={18} aria-hidden="true" /></span>
        </div>
        {scheduleError && <div role="alert" className="inline-alert error-alert">{scheduleError}</div>}
        <p className="panel-description">The local Windows protection service runs this schedule while it is installed and running.</p>
        <form className="schedule-form" onSubmit={(event) => void saveSchedule(event)}>
          <label className="schedule-toggle">
            <input
              checked={scheduleEnabled}
              disabled={unavailable || savingSchedule}
              onChange={(event) => changeSchedule(setScheduleEnabled, event.target.checked)}
              type="checkbox"
            />
            <span>Run scans automatically</span>
          </label>
          <div className="schedule-fields">
            <label>Frequency
              <select value={frequency} disabled={unavailable || savingSchedule} onChange={(event) => changeSchedule(setFrequency, event.target.value as ScanFrequency)}>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
            </label>
            <label>Scan type
              <select value={scheduleScope} disabled={unavailable || savingSchedule} onChange={(event) => changeSchedule(setScheduleScope, event.target.value as ScanScope)}>
                <option value="quick">Quick scan</option>
                <option value="system">System scan</option>
              </select>
            </label>
            <label>Local time
              <input value={localTime} disabled={unavailable || savingSchedule} onChange={(event) => changeSchedule(setLocalTime, event.target.value)} type="time" required />
            </label>
            {frequency === "weekly" && <label>Day
              <select value={weekday} disabled={unavailable || savingSchedule} onChange={(event) => changeSchedule(setWeekday, Number(event.target.value))}>
                {(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]).map((day, index) => <option key={day} value={index}>{day}</option>)}
              </select>
            </label>}
          </div>
          <button className="button button-secondary" disabled={unavailable || savingSchedule} type="submit">
            {savingSchedule ? "Saving…" : "Save schedule"}
          </button>
        </form>
        {(scheduleActionError || scheduleSaved) && <div role={scheduleActionError ? "alert" : "status"} className={`inline-alert ${scheduleActionError ? "error-alert" : "success-alert"}`}>
          {scheduleActionError || "Schedule saved on this device."}
        </div>}
        {schedule && <div className="schedule-status" aria-live="polite">
          <div><span>Next run</span><strong>{schedule.enabled && schedule.next_run_at ? new Date(schedule.next_run_at).toLocaleString() : "Not scheduled"}</strong></div>
          <div><span>Last result</span><strong>{schedule.last_result ? schedule.last_result.replaceAll("_", " ") : "No scheduled scan yet"}</strong></div>
          {schedule.error_message && <p role="status">{schedule.error_message}</p>}
        </div>}
        {unavailable && <p className="helper-note">Schedule controls are unavailable until the local protection service is ready.</p>}
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
          <EmptyState title="No current scan" description="Scan progress appears here while a local scan is running. Completed scan history is stored by the protection service." />
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
              <span>{busy
                ? `Scanned ${scan.files_scanned}; discovered ${scan.files_total ?? 0} so far`
                : `${scan.files_scanned} of ${scan.files_total ?? "—"} files scanned`}</span>
              {!busy && scan.files_total !== null && <span>{progress}%</span>}
            </div>
            {scan.engine_version && <div className="scan-version-meta">
              Scan used scanner v{scan.engine_version} and rules v{scan.rules_version || "unknown"} across {scan.root_snapshot === undefined ? "an unreported number of" : scan.root_snapshot.length} locations.
            </div>}
            <div
              className={`progress-track${busy ? " is-indeterminate" : ""}`}
              role="progressbar"
              aria-label="Scan progress"
              aria-valuemin={busy ? undefined : 0}
              aria-valuemax={busy ? undefined : 100}
              aria-valuenow={busy ? undefined : progress}
              aria-valuetext={busy ? `Scanning. ${scan.files_scanned} scanned; ${scan.files_total ?? 0} discovered so far.` : `${progress}%`}
            >
              <span style={busy ? undefined : { width: `${progress}%` }} />
            </div>
            <div className="scan-result-stats">
              <div><strong>{scan.detections}</strong><span>detections</span></div>
              <div><strong>{scan.unknown_verdicts ?? 0}</strong><span>unknown verdicts</span></div>
              <div><strong>{scan.files_skipped ?? 0}</strong><span>skipped</span></div>
              <div><strong>{scan.errors}</strong><span>access errors</span></div>
              <div><strong>{scan.duration_ms == null ? "—" : `${(scan.duration_ms / 1000).toFixed(1)}s`}</strong><span>duration</span></div>
              <div><strong>{scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}</strong><span>started</span></div>
            </div>
            {scan.error_message && <div role="alert" className="inline-alert error-alert">{scan.error_message}</div>}
            {busy && (
              <button className="button button-secondary" onClick={() => void onCancel()} type="button">
                Cancel scan
              </button>
            )}
            {(scan.state === "completed" || scan.state === "partial") && (hasCoverageGaps ? (
              <div className="inline-alert coverage-gap" role="status">
                Coverage is incomplete. This result does not establish that the selected locations are clean.
              </div>
            ) : (
              <div className="completion-note">
                <CheckCircle2 size={15} aria-hidden="true" /> Scan finished for the listed locations. Review detections above.
              </div>
            ))}
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
  if (state === "partial") return <AlertCircle className="warning-icon" size={18} aria-label="Scan completed with coverage gaps" />;
  if (state === "cancelled") return <XCircle className="muted-icon" size={18} aria-label="Scan cancelled" />;
  return <AlertCircle className="error-icon" size={18} aria-label="Scan failed" />;
}
