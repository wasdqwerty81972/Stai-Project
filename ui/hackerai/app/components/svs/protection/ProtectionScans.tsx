"use client";

import { ScanLine, Loader2, XCircle, CheckCircle2, AlertTriangle } from "lucide-react";
import type { ScanJob, ScanScope } from "@/lib/stai-protection-api";
import { formatTimestamp } from "./ProtectionPrimitives";

interface Props {
  job: ScanJob | null;
  starting: boolean;
  error: string | null;
  onStart: (scope: ScanScope) => void;
  onCancel: () => void;
  /** "compact" trims the explanatory copy for the dashboard summary. */
  variant?: "full" | "compact";
}

function isActive(job: ScanJob | null): boolean {
  return !!job && (job.state === "running" || job.state === "queued");
}

const TERMINAL_STYLE: Record<string, { Icon: typeof CheckCircle2; cls: string; label: string }> = {
  completed: { Icon: CheckCircle2, cls: "text-emerald-300", label: "Completed" },
  cancelled: { Icon: XCircle, cls: "text-muted-foreground", label: "Cancelled" },
  failed: { Icon: AlertTriangle, cls: "text-destructive", label: "Failed" },
};

export function ProtectionScans({
  job,
  starting,
  error,
  onStart,
  onCancel,
  variant = "full",
}: Props) {
  const active = isActive(job);
  const percent =
    job && job.files_total > 0
      ? Math.min(100, Math.round((job.files_scanned / job.files_total) * 100))
      : null;
  const terminal = job ? TERMINAL_STYLE[job.state] : undefined;

  return (
    <section
      aria-label="Scans"
      className="rounded-xl border border-border bg-card/40 p-5"
    >
      <div className="flex items-center gap-2">
        <ScanLine className="size-4 text-cyan-300" aria-hidden="true" />
        <h3 className="text-sm font-semibold text-foreground">Scans</h3>
      </div>
      {variant === "full" ? (
        <p className="mt-1 text-xs text-muted-foreground">
          Quick scan targets common execution and startup locations. System scan
          covers accessible local fixed volumes and reports inaccessible paths.
          Both are cancellable.
        </p>
      ) : null}

      <div className="mt-3 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => onStart("quick")}
          disabled={starting || active}
          className="inline-flex items-center gap-2 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-sm font-medium text-cyan-100 transition-colors hover:bg-cyan-500/20 focus-visible:outline-2 focus-visible:outline-ring disabled:cursor-not-allowed disabled:opacity-50"
        >
          {starting ? (
            <Loader2 className="size-4 motion-safe:animate-spin" aria-hidden="true" />
          ) : (
            <ScanLine className="size-4" aria-hidden="true" />
          )}
          Quick scan
        </button>
        <button
          type="button"
          onClick={() => onStart("system")}
          disabled={starting || active}
          className="inline-flex items-center gap-2 rounded-md border border-border bg-background px-3 py-1.5 text-sm font-medium text-foreground transition-colors hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring disabled:cursor-not-allowed disabled:opacity-50"
        >
          <ScanLine className="size-4" aria-hidden="true" />
          System scan
        </button>
      </div>

      {error ? (
        <p
          role="alert"
          className="mt-3 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive"
        >
          {error}
        </p>
      ) : null}

      {job ? (
        <div
          className="mt-4 rounded-lg border border-border bg-background/50 p-4"
          aria-label={`Scan job ${job.job_id}`}
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="inline-flex items-center gap-2 text-sm font-medium text-foreground">
              {active ? (
                <Loader2
                  className="size-4 text-cyan-300 motion-safe:animate-spin"
                  aria-hidden="true"
                />
              ) : terminal ? (
                <terminal.Icon className={`size-4 ${terminal.cls}`} aria-hidden="true" />
              ) : null}
              <span className="capitalize">{job.scope} scan</span>
              <span className="text-muted-foreground">
                · {terminal ? terminal.label : job.state}
              </span>
            </span>
            {active ? (
              <button
                type="button"
                onClick={onCancel}
                className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1 text-xs font-medium text-foreground transition-colors hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring"
              >
                <XCircle className="size-3.5" aria-hidden="true" />
                Cancel
              </button>
            ) : null}
          </div>

          <div className="mt-3">
            <div
              className="h-2 w-full overflow-hidden rounded-full bg-border"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={job.files_total || undefined}
              aria-valuenow={percent != null ? job.files_scanned : undefined}
              aria-label="Scan progress"
            >
              <div
                className={`h-full rounded-full ${active ? "bg-cyan-400" : "bg-emerald-400"} ${percent == null && active ? "w-1/3 motion-safe:animate-pulse" : ""}`}
                style={percent != null ? { width: `${percent}%` } : undefined}
              />
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {job.files_scanned.toLocaleString()}
              {job.files_total > 0 ? ` / ${job.files_total.toLocaleString()}` : ""}{" "}
              files scanned
              {percent != null ? ` (${percent}%)` : ""}
            </p>
          </div>

          <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-3">
            <div className="flex items-center justify-between gap-2 sm:flex-col sm:items-start">
              <dt className="text-muted-foreground">Detections found</dt>
              <dd className="font-medium text-cyan-200">{job.detections}</dd>
            </div>
            <div className="flex items-center justify-between gap-2 sm:flex-col sm:items-start">
              <dt className="text-muted-foreground">Scan errors</dt>
              <dd className="font-medium text-foreground">{job.errors}</dd>
            </div>
            <div className="flex items-center justify-between gap-2 sm:flex-col sm:items-start">
              <dt className="text-muted-foreground">Started</dt>
              <dd className="font-medium text-foreground">
                {formatTimestamp(job.started_at)}
              </dd>
            </div>
          </dl>

          <p className="mt-2 text-[11px] text-muted-foreground">
            Scan detections are files matched during this scan; they are counted
            separately from on-access confirmed blocks shown on the dashboard.
          </p>

          {job.error_message ? (
            <p
              role="alert"
              className="mt-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive"
            >
              {job.error_message}
            </p>
          ) : null}
          {job.completed_at ? (
            <p className="mt-2 text-[11px] text-muted-foreground">
              Finished {formatTimestamp(job.completed_at)}
            </p>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
