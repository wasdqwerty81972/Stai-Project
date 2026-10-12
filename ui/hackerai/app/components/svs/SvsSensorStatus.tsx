"use client";

import { useCallback, useEffect, useState } from "react";
import { Activity, CircleAlert, Shield } from "lucide-react";
import {
  getSensorRuntimeStatus,
  respondToStaiApproval,
  startSensorMonitoring,
  stopSensorMonitoring,
  type SensorRuntimeStatus,
  type SensorRegistryEntry,
} from "@/lib/stai-api";

function sourceReady(state: string): boolean {
  return ["active", "available", "ready"].includes(state.toLowerCase());
}

export function SvsSensorStatus() {
  const [status, setStatus] = useState<SensorRuntimeStatus | null>(null);
  const [loadError, setLoadError] = useState("");
  const [pending, setPending] = useState(false);
  const [respondingToApproval, setRespondingToApproval] = useState("");
  const [registryFilter, setRegistryFilter] = useState("");

  const refresh = useCallback(async () => {
    try {
      setStatus(await getSensorRuntimeStatus());
      setLoadError("");
    } catch {
      setLoadError("Sensor status unavailable");
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 15_000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  async function toggleMonitoring() {
    if (!status) return;
    setPending(true);
    setLoadError("");
    try {
      setStatus(
        status.running
          ? await stopSensorMonitoring()
          : await startSensorMonitoring(),
      );
    } catch {
      setLoadError("Could not update sensor monitoring");
      await refresh();
    } finally {
      setPending(false);
    }
  }

  async function resolveApproval(approvalId: string, approved: boolean) {
    setRespondingToApproval(approvalId);
    setLoadError("");
    try {
      await respondToStaiApproval(approvalId, approved);
      await refresh();
    } catch {
      setLoadError("Could not resolve containment approval");
      await refresh();
    } finally {
      setRespondingToApproval("");
    }
  }

  const capabilities = status?.capabilities ?? [];
  const registry = status?.registry ?? [];
  const sourceReadyCount = capabilities.filter((sensor) =>
    sourceReady(sensor.state),
  ).length;
  const isWindows = status?.platform.toLowerCase().includes("win") ?? false;
  const visibleRegistry = registry.filter((sensor) => {
    const needle = registryFilter.trim().toLowerCase();
    if (!needle) return true;
    return [
      sensor.name,
      sensor.category,
      sensor.description,
      sensor.telemetry_source,
      sensor.operational_status,
      sensor.runtime_state,
    ].some((value) => value.toLowerCase().includes(needle));
  });

  function registryStatusLabel(sensor: SensorRegistryEntry): string {
    if (sensor.runtime_state !== "registered_only") {
      return sensor.runtime_state.replaceAll("_", " ");
    }
    return sensor.operational_status.replaceAll("_", " ");
  }

  return (
    <section
      aria-label="Security sensor status"
      className="relative flex flex-wrap items-center justify-between gap-x-3 gap-y-2 border-b border-border/60 bg-card/35 px-4 py-2 text-xs"
    >
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1.5">
        <span
          role="status"
          aria-live="polite"
          className="inline-flex items-center gap-1.5 font-medium text-foreground"
        >
          {loadError ? (
            <CircleAlert className="size-3.5 text-amber-500" aria-hidden="true" />
          ) : status?.running ? (
            <Activity className="size-3.5 text-emerald-500" aria-hidden="true" />
          ) : (
            <Shield className="size-3.5 text-muted-foreground" aria-hidden="true" />
          )}
          {loadError ||
            (status
              ? status.running
                ? "Windows monitoring active"
                : "Windows monitoring stopped"
              : "Checking sensor status…")}
        </span>
        {status && (
          <span className="text-muted-foreground">
            {capabilities.length} Phase 1 mappings · {sourceReadyCount} sources readable; audit coverage unverified
          </span>
        )}
        {status && (
          <span className="text-muted-foreground">
            Queue {status.queue.depth}/{status.queue.capacity} · dropped {status.queue.dropped}
            {status.queue.backpressure ? ` · backpressure ${status.queue.backpressure}` : ""}
          </span>
        )}
        {status?.last_error && (
          <span className="text-amber-600 dark:text-amber-400" role="status">
            {status.last_error}
          </span>
        )}
        {status?.last_event_time && (
          <time
            dateTime={status.last_event_time}
            className="text-muted-foreground"
          >
            Last event {new Date(status.last_event_time).toLocaleTimeString()}
          </time>
        )}
        {registry.length > 0 && (
          <details className="group">
            <summary className="cursor-pointer list-none text-cyan-700 underline decoration-dotted underline-offset-2 dark:text-cyan-300">
              Sensor registry ({registry.length})
            </summary>
            <div className="absolute z-20 mt-2 flex max-h-[min(36rem,calc(100vh-8rem))] w-[min(42rem,calc(100vw-2rem))] flex-col rounded-lg border border-border bg-background p-2 shadow-xl">
              <label className="sr-only" htmlFor="sensor-registry-filter">Filter sensor registry</label>
              <input
                id="sensor-registry-filter"
                value={registryFilter}
                onChange={(event) => setRegistryFilter(event.target.value)}
                placeholder="Filter by name, category, source, or status"
                className="mb-2 rounded-md border border-border bg-background px-2.5 py-2 text-xs text-foreground outline-none focus:ring-2 focus:ring-ring"
              />
              <p className="mb-1 text-muted-foreground">
                Showing {visibleRegistry.length} of {registry.length}. Only the Phase 1 rows have collectors in this build; other rows are catalogued capabilities.
              </p>
              <ul className="min-h-0 flex-1 overflow-y-auto rounded-md border border-border/60">
              {visibleRegistry.map((sensor) => (
                <li
                  key={sensor.id}
                  className="border-b border-border/60 px-2 py-2 last:border-0"
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-medium text-foreground">
                      #{sensor.id} {sensor.name}
                    </span>
                    <span className="shrink-0 text-right text-muted-foreground">
                      runtime {registryStatusLabel(sensor)} · host {sensor.host_support.replaceAll("_", " ")}
                    </span>
                  </div>
                  <p className="mt-0.5 text-muted-foreground">
                    {sensor.category} · {sensor.kind.replaceAll("_", " ")} · implementation {sensor.operational_status.replaceAll("_", " ")} · cost {sensor.performance_cost.class}{sensor.performance_cost.measured ? " (measured)" : " (estimate)"}
                  </p>
                  <p className="mt-0.5 text-foreground/80">{sensor.description}</p>
                  <p className="mt-1 break-words text-muted-foreground">
                    OS support: {Object.entries(sensor.platform_support).map(([platform, support]) => `${platform.replaceAll("_", " ")} ${support.replaceAll("_", " ")}`).join(" · ")}
                  </p>
                  <p className="mt-1 break-words text-muted-foreground">Source: {sensor.telemetry_source}</p>
                  <p className="mt-0.5 break-words text-muted-foreground">Collector: {sensor.shared_collector_id} · method: {sensor.collection_method}</p>
                  <p className="mt-0.5 break-words text-muted-foreground">Permissions: {sensor.required_permissions.join(", ")}</p>
                  <p className="mt-0.5 break-words text-muted-foreground">Schema: {sensor.event_schema.id} · required: {sensor.event_schema.required_fields.join(", ")} · specific: {sensor.event_schema.specific_fields.join(", ")}</p>
                  <p className="mt-0.5 break-words text-muted-foreground">Tests: {sensor.test_refs.join(", ")}</p>
                  {sensor.phase1_requested_id != null && sensor.phase1_requested_name && (
                    <p className="mt-0.5 text-cyan-700 dark:text-cyan-300">
                      Phase 1 request #{sensor.phase1_requested_id}: {sensor.phase1_requested_name}
                    </p>
                  )}
                  {sensor.runtime_error && (
                    <p className="mt-0.5 break-words text-amber-600 dark:text-amber-400">{sensor.runtime_error}</p>
                  )}
                </li>
              ))}
              </ul>
            </div>
            <p className="mt-2 max-w-[min(32rem,calc(100vw-2rem))] text-muted-foreground">
              Privacy: file paths {status?.privacy.collect_file_paths ? "collected" : "hashed"}; DNS names {status?.privacy.collect_dns_names ? "collected" : "hashed"}; command lines {status?.privacy.collect_command_lines ? "collected" : "omitted"}.
            </p>
          </details>
        )}
      </div>
      <button
        type="button"
        onClick={() => void toggleMonitoring()}
        disabled={!status || pending || (!status.running && !isWindows)}
        className="rounded-md border border-border bg-background px-2.5 py-1 font-medium text-foreground transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
      >
        {pending
          ? "Updating…"
          : status?.running
            ? "Stop monitoring"
            : "Start monitoring"}
      </button>
      {(status?.pending_approvals.length ?? 0) > 0 && (
        <div className="basis-full space-y-2 rounded-md border border-amber-500/40 bg-amber-500/5 p-3">
          <h3 className="font-semibold text-foreground">Containment needs approval</h3>
          {status?.pending_approvals.map((approval) => (
            <article
              key={approval.approval_id}
              className="flex flex-wrap items-center justify-between gap-3 rounded border border-border bg-background p-3"
            >
              <div className="min-w-0 flex-1">
                <p className="font-medium">{approval.severity}: {approval.summary}</p>
                <p className="mt-1 text-muted-foreground">
                  Proposed: {approval.proposed_actions.join(", ") || "Review alert"}
                </p>
              </div>
              <div className="flex shrink-0 gap-2">
                <button
                  type="button"
                  onClick={() => void resolveApproval(approval.approval_id, false)}
                  disabled={respondingToApproval !== ""}
                  className="rounded-md border border-border px-2.5 py-1 font-medium hover:bg-accent disabled:opacity-50"
                >
                  Deny
                </button>
                <button
                  type="button"
                  onClick={() => void resolveApproval(approval.approval_id, true)}
                  disabled={respondingToApproval !== ""}
                  className="rounded-md bg-foreground px-2.5 py-1 font-medium text-background hover:opacity-80 disabled:opacity-50"
                >
                  {respondingToApproval === approval.approval_id ? "Resolving…" : "Approve"}
                </button>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
