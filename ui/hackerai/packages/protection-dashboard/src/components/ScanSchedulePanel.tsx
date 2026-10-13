import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { CalendarClock } from "lucide-react";
import type { ScanCadence, ScanSchedule, ScanScheduleInput, ScanWeekday } from "../protection-api";

const weekdays: { value: ScanWeekday; label: string; fullName: string }[] = [
  { value: "mon", label: "Mon", fullName: "Monday" },
  { value: "tue", label: "Tue", fullName: "Tuesday" },
  { value: "wed", label: "Wed", fullName: "Wednesday" },
  { value: "thu", label: "Thu", fullName: "Thursday" },
  { value: "fri", label: "Fri", fullName: "Friday" },
  { value: "sat", label: "Sat", fullName: "Saturday" },
  { value: "sun", label: "Sun", fullName: "Sunday" },
];

interface ScheduleDraft {
  enabled: boolean;
  cadence: ScanCadence;
  localTime: string;
  daysOfWeek: ScanWeekday[];
}

const defaultDraft: ScheduleDraft = {
  enabled: false,
  cadence: "daily",
  localTime: "09:00",
  daysOfWeek: [],
};

function draftFromSchedule(schedule: ScanSchedule): ScheduleDraft {
  return {
    enabled: schedule.enabled,
    cadence: schedule.cadence ?? "daily",
    localTime: schedule.local_time ?? "09:00",
    daysOfWeek: schedule.days_of_week ?? [],
  };
}

function displayLocalDate(value: string | null | undefined): string {
  if (!value) return "Not scheduled";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function ScanSchedulePanel({
  schedule,
  loading,
  saving,
  error,
  unavailable,
  onSave,
}: {
  schedule: ScanSchedule | null;
  loading: boolean;
  saving: boolean;
  error: string | null;
  unavailable: boolean;
  onSave: (input: ScanScheduleInput) => Promise<void>;
}) {
  const [draft, setDraft] = useState<ScheduleDraft>(defaultDraft);
  const [formError, setFormError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (schedule) setDraft(draftFromSchedule(schedule));
  }, [schedule]);

  const toggleWeekday = (day: ScanWeekday) => {
    setDraft((current) => ({
      ...current,
      daysOfWeek: current.daysOfWeek.includes(day)
        ? current.daysOfWeek.filter((item) => item !== day)
        : weekdays.filter((item) => current.daysOfWeek.includes(item.value) || item.value === day).map((item) => item.value),
    }));
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError(null);
    setSaved(false);
    if (draft.cadence === "weekly" && draft.daysOfWeek.length === 0) {
      setFormError("Choose at least one day for a weekly scan.");
      return;
    }
    const input: ScanScheduleInput = {
      ...draft,
      daysOfWeek: draft.cadence === "daily" ? [] : draft.daysOfWeek,
    };
    try {
      await onSave(input);
      setSaved(true);
    } catch {
      // The parent owns and displays the bridge error beside this form.
    }
  };

  const disabled = loading || saving || unavailable || Boolean(error);
  const nextRun = schedule?.enabled ? displayLocalDate(schedule.next_run_local) : "Not scheduled";
  const lastResult = schedule?.last_result
    ? schedule.last_result.replaceAll("_", " ")
    : "No completed runs yet";

  return (
    <section className="panel schedule-panel" aria-labelledby="scheduled-quick-scan-title">
      <div className="panel-heading">
        <div>
          <div className="eyebrow">AUTOMATION</div>
          <h2 id="scheduled-quick-scan-title">Scheduled Quick Scan</h2>
        </div>
        <span className="panel-icon"><CalendarClock size={18} aria-hidden="true" /></span>
      </div>
      <p className="panel-description">
        Choose when the local service scans the enrolled user’s Desktop, Downloads, and Startup folders.
      </p>

      {loading && <div className="schedule-loading" role="status">Loading schedule…</div>}
      {error && <div className="inline-alert error-alert" role="alert">Schedule unavailable: {error}</div>}
      {formError && <div className="inline-alert error-alert" role="alert">{formError}</div>}
      {unavailable && !error && (
        <div className="inline-alert" role="status">Connect to the local protection service to manage schedules.</div>
      )}

      <form className="schedule-form" onSubmit={(event) => void submit(event)}>
        <label className="schedule-enable-row">
          <span>
            <strong>Enable scheduled Quick Scan</strong>
            <small>{draft.enabled ? "The service will start scans at the selected time." : "No scan will run until you enable this schedule."}</small>
          </span>
          <input
            aria-label="Enable scheduled Quick Scan"
            checked={draft.enabled}
            disabled={disabled}
            onChange={(event) => setDraft((current) => ({ ...current, enabled: event.target.checked }))}
            type="checkbox"
          />
        </label>

        <div className="schedule-fields">
          <label className="schedule-field">
            <span>Frequency</span>
            <select
              aria-label="Frequency"
              disabled={disabled}
              onChange={(event) => setDraft((current) => ({ ...current, cadence: event.target.value as ScanCadence }))}
              value={draft.cadence}
            >
              <option value="daily">Every day</option>
              <option value="weekly">Weekly</option>
            </select>
          </label>
          <label className="schedule-field">
            <span>Local time</span>
            <input
              aria-label="Local time"
              disabled={disabled}
              onChange={(event) => setDraft((current) => ({ ...current, localTime: event.target.value }))}
              required
              type="time"
              value={draft.localTime}
            />
          </label>
        </div>

        {draft.cadence === "weekly" && (
          <fieldset className="schedule-weekdays" disabled={disabled}>
            <legend>Run on</legend>
            <div className="weekday-options">
              {weekdays.map((day) => (
                <label className="weekday-option" key={day.value}>
                  <input
                    aria-label={day.fullName}
                    checked={draft.daysOfWeek.includes(day.value)}
                    onChange={() => toggleWeekday(day.value)}
                    type="checkbox"
                  />
                  <span>{day.label}</span>
                </label>
              ))}
            </div>
          </fieldset>
        )}

        <div className="schedule-summary" aria-label="Schedule status">
          <div><span>Next run</span><strong>{nextRun}</strong></div>
          <div><span>Last result</span><strong className="capitalize">{lastResult}</strong></div>
        </div>

        <div className="schedule-footer">
          <span className="helper-note">Times use the enrolled Windows account’s local time.</span>
          <button className="button button-primary" disabled={disabled} type="submit">
            {saving ? "Saving…" : "Save schedule"}
          </button>
        </div>
        {saved && <div className="completion-note" role="status">Schedule saved.</div>}
      </form>
    </section>
  );
}
