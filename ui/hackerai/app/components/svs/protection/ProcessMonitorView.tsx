"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Activity, ArrowDownUp, ChevronDown, ChevronRight, CircleHelp, Pause, Play, Search } from "lucide-react";
import {
  getProcessConnections,
  getProcessDetails,
  scanProcessExecutable,
  setProcessMonitorProfile,
  subscribeToProcessMonitor,
  type ProcessConnection,
  type ProcessScanResult,
  type MonitoredProcess,
  type ProcessMonitorEvent,
  type ProcessMonitorHealth,
} from "@/lib/stai-protection-api";

type SortKey = "name" | "pid" | "cpu_percent" | "memory_bytes";
type StreamState = "connecting" | "connected" | "disconnected" | "error";

function applyEvent(
  current: Map<string, MonitoredProcess>,
  event: ProcessMonitorEvent,
): Map<string, MonitoredProcess> {
  if (event.type === "snapshot") {
    return new Map<string, MonitoredProcess>(
      (event.processes ?? []).map((process): [string, MonitoredProcess] => [process.instance_id, process]),
    );
  }
  if (!event.instance_id && !event.process?.instance_id) return current;
  const id = event.instance_id ?? event.process?.instance_id;
  if (!id) return current;
  const next = new Map(current);
  if (event.type === "process_removed") next.delete(id);
  if ((event.type === "process_added" || event.type === "process_metrics_updated") && event.process) {
    next.set(id, { ...next.get(id), ...event.process });
  }
  return next;
}

function bytes(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return "Unavailable";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let scaled = value;
  let unit = -1;
  do { scaled /= 1024; unit += 1; } while (scaled >= 1024 && unit < units.length - 1);
  return `${scaled.toFixed(1)} ${units[unit]}`;
}

function percent(value: number | null): string {
  return value == null || !Number.isFinite(value) ? "—" : `${value.toFixed(1)}%`;
}

function sourceLabel(health: ProcessMonitorHealth | null): string {
  if (!health) return "Waiting for monitor";
  if (health.source === "protection_service") return health.state === "running" ? "Protection service · live telemetry" : "Protection service unavailable";
  if (health.source === "local_fallback") return "Local process fallback";
  if (health.source === "unavailable") return "Process monitor unavailable";
  if (health.event_source === "running") return "Process events live";
  if (health.state === "running" && ["degraded", "unavailable"].includes(health.event_source)) return "Snapshot reconciliation";
  if (health.state === "running") return "Starting process monitor";
  return "Process monitor unavailable";
}

export function ProcessMonitorView() {
  const [records, setRecords] = useState<Map<string, MonitoredProcess>>(() => new Map());
  const [health, setHealth] = useState<ProcessMonitorHealth | null>(null);
  const [streamState, setStreamState] = useState<StreamState>("connecting");
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortOrder, setSortOrder] = useState<string[]>([]);
  const [liveSort, setLiveSort] = useState(false);
  const [paused, setPaused] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [connections, setConnections] = useState<ProcessConnection[]>([]);
  const [connectionsAvailable, setConnectionsAvailable] = useState<boolean | null>(null);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [scanBusy, setScanBusy] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<Record<string, ProcessScanResult>>({});
  const [connectionsOnly, setConnectionsOnly] = useState(false);
  const [riskFilter, setRiskFilter] = useState<"all" | "unassessed" | "detected" | "clean">("all");
  const [groupByParent, setGroupByParent] = useState(false);
  const [showParentColumn, setShowParentColumn] = useState(false);
  const [showPathColumn, setShowPathColumn] = useState(false);
  const pausedRef = useRef(false);
  const pendingRef = useRef<ProcessMonitorEvent[]>([]);

  const handleEvent = useCallback((event: ProcessMonitorEvent) => {
    if (event.health) setHealth(event.health);
    if (event.type === "health" || event.type === "heartbeat") return;
    if (pausedRef.current) {
      pendingRef.current.push(event);
      if (pendingRef.current.length > 4096) pendingRef.current = pendingRef.current.slice(-2048);
      return;
    }
    setRecords((current) => applyEvent(current, event));
  }, []);

  useEffect(() => subscribeToProcessMonitor(handleEvent, setStreamState), [handleEvent]);

  const togglePaused = () => {
    const next = !paused;
    pausedRef.current = next;
    setPaused(next);
    if (!next && pendingRef.current.length) {
      const pending = pendingRef.current;
      pendingRef.current = [];
      setRecords((current) => pending.reduce(applyEvent, current));
    }
  };

  const rows = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    const filtered = [...records.values()].filter((process) => {
      const matchesQuery = !needle || process.name.toLocaleLowerCase().includes(needle) || String(process.pid).includes(needle);
      const matchesConnections = !connectionsOnly || (process.network_connection_count ?? 0) > 0;
      const verdict = scanResults[process.instance_id]?.status ?? process.scan_status;
      const matchesRisk = riskFilter === "all"
        || (riskFilter === "unassessed" && !verdict)
        || (riskFilter === "detected" && verdict === "detected")
        || (riskFilter === "clean" && verdict === "clean");
      return matchesQuery && matchesConnections && matchesRisk;
    });
    if (liveSort || sortOrder.length === 0) {
      filtered.sort((a, b) => compareProcesses(a, b, sortKey));
    } else {
      const position = new Map(sortOrder.map((id, index) => [id, index]));
      filtered.sort((a, b) => (position.get(a.instance_id) ?? Number.MAX_SAFE_INTEGER) - (position.get(b.instance_id) ?? Number.MAX_SAFE_INTEGER));
    }
    return filtered;
  }, [records, query, sortKey, sortOrder, liveSort, connectionsOnly, riskFilter, scanResults]);

  const parentGroups = useMemo(() => {
    if (!groupByParent) return null;
    const groups = new Map<string, { label: string; processes: MonitoredProcess[] }>();
    for (const process of rows) {
      const key = process.parent_pid == null ? "unavailable" : String(process.parent_pid);
      const group = groups.get(key) ?? { label: process.parent_pid == null ? "Unavailable" : String(process.parent_pid), processes: [] };
      group.processes.push(process);
      groups.set(key, group);
    }
    return [...groups.entries()].sort(([left], [right]) => left.localeCompare(right, undefined, { numeric: true }));
  }, [rows, groupByParent]);

  const selected = selectedId ? records.get(selectedId) ?? null : null;

  const changeProfile = async (profile: "low" | "normal" | "high") => {
    setProfileError(null);
    try {
      setHealth(await setProcessMonitorProfile(profile));
    } catch (error) {
      setProfileError(error instanceof Error ? error.message : "Could not change process sampling profile");
    }
  };

  const changeSort = (key: SortKey) => {
    setSortKey(key);
    setSortOrder([...records.values()].sort((a, b) => compareProcesses(a, b, key)).map((process) => process.instance_id));
  };

  const scanSelectedExecutable = async () => {
    if (!selectedId || scanBusy) return;
    setScanBusy(true);
    setScanError(null);
    try {
      const result = await scanProcessExecutable(selectedId);
      setScanResults((previous) => ({ ...previous, [selectedId]: result }));
    } catch (error) {
      setScanError(error instanceof Error ? error.message : "Could not scan process executable");
    } finally {
      setScanBusy(false);
    }
  };

  useEffect(() => {
    if (!selectedId) {
      setConnections([]);
      setConnectionsAvailable(null);
      return;
    }
    let cancelled = false;
    setConnections([]);
    setConnectionsAvailable(null);
    setScanError(null);
    void getProcessDetails(selectedId).then((detail) => {
      if (!cancelled) {
        setRecords((current) => {
          if (!current.has(selectedId)) return current;
          const next = new Map(current);
          const latest = next.get(selectedId)!;
          next.set(selectedId, {
            ...detail,
            ...latest,
            parent_pid: detail.parent_pid,
            username: detail.username,
            exe: detail.exe,
            status: detail.status,
            thread_count: detail.thread_count,
          });
          return next;
        });
      }
    }).catch(() => undefined);
    void getProcessConnections(selectedId).then((result) => {
      if (!cancelled) {
        setConnections(result.connections);
        setConnectionsAvailable(result.available);
      }
    }).catch(() => {
      if (!cancelled) setConnectionsAvailable(false);
    });
    return () => { cancelled = true; };
  }, [selectedId]);

  return (
    <section aria-label="Live process monitor" className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-card/40 px-4 py-3">
        <div className="flex items-center gap-3">
          <span className={`flex size-9 items-center justify-center rounded-md border ${streamState === "connected" ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300" : "border-amber-400/30 bg-amber-400/10 text-amber-300"}`}>
            <Activity className="size-4" aria-hidden="true" />
          </span>
          <div>
            <p className="text-sm font-semibold text-foreground">{sourceLabel(health)}</p>
            <p className="text-xs text-muted-foreground">
              {health ? `Sampled every ${health.sample_interval_seconds}s · reconciled every ${health.reconcile_interval_seconds}s` : "Waiting for local Windows telemetry"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span role="status" aria-live="polite" className="inline-flex items-center gap-1.5">
            <span className={`size-1.5 rounded-full ${streamState === "connected" ? "bg-emerald-400" : streamState === "error" ? "bg-red-400" : "bg-amber-400"}`} />
            {streamState}
          </span>
          <span>{rows.length} processes</span>
        </div>
      </div>

      {health?.event_source_error ? (
        <p className="rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-100">
          Process event subscription is unavailable: {health.event_source_error}. The monitor uses periodic reconciliation.
        </p>
      ) : null}
      {health?.source === "local_fallback" ? (
        <p role="status" className="rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-100">
          The Windows protection service is not connected. Showing local process data.{health.source_error ? ` ${health.source_error}` : ""}
        </p>
      ) : null}
      {health?.source === "unavailable" ? (
        <p role="alert" className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-200">
          No process collector is available. Process data is not being updated.{health.source_error ? ` ${health.source_error}` : ""}
        </p>
      ) : null}
      {health?.last_error ? (
        <p role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">{health.last_error}</p>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <label className="relative min-w-52 flex-1">
          <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <input aria-label="Search processes" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search name or PID" className="h-9 w-full rounded-md border border-border bg-background pl-8 pr-3 text-sm text-foreground outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/60" />
        </label>
        <label className="inline-flex h-9 items-center gap-2 rounded-md border border-border bg-background px-2.5 text-xs text-muted-foreground">
          <ArrowDownUp className="size-3.5" aria-hidden="true" />
          <select aria-label="Sort processes by" value={sortKey} onChange={(event) => changeSort(event.target.value as SortKey)} className="bg-transparent text-foreground outline-none">
            <option value="name">Name</option><option value="pid">PID</option><option value="cpu_percent">CPU</option><option value="memory_bytes">Memory</option>
          </select>
        </label>
        <label className="inline-flex h-9 items-center gap-2 rounded-md border border-border bg-background px-2.5 text-xs text-muted-foreground">
          Sampling
          <select aria-label="Sampling frequency" value={health?.sampling_profile === "low" || health?.sampling_profile === "high" ? health.sampling_profile : "normal"} onChange={(event) => void changeProfile(event.target.value as "low" | "normal" | "high")} className="bg-transparent text-foreground outline-none">
            <option value="low">Low resource · 10s</option><option value="normal">Normal · 5s</option><option value="high">High frequency · 1s</option>
          </select>
        </label>
        <label className="inline-flex h-9 items-center gap-2 rounded-md border border-border bg-background px-2.5 text-xs text-muted-foreground">
          Risk
          <select aria-label="Filter by risk" value={riskFilter} onChange={(event) => setRiskFilter(event.target.value as typeof riskFilter)} className="bg-transparent text-foreground outline-none">
            <option value="all">All</option><option value="unassessed">Not assessed</option><option value="detected">Detected</option><option value="clean">No known match</option>
          </select>
        </label>
        <details className="relative rounded-md border border-border bg-background px-2.5 py-2 text-xs text-muted-foreground">
          <summary className="cursor-pointer">Columns</summary>
          <div className="absolute right-0 z-20 mt-2 grid min-w-44 gap-2 rounded-md border border-border bg-card p-3 shadow-lg">
            <label className="flex items-center gap-2"><input type="checkbox" checked={showParentColumn} onChange={(event) => setShowParentColumn(event.target.checked)} /> Parent PID</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={showPathColumn} onChange={(event) => setShowPathColumn(event.target.checked)} /> Executable path</label>
          </div>
        </details>
        <label className="inline-flex h-9 items-center gap-2 rounded-md border border-border px-2.5 text-xs text-muted-foreground">
          <input type="checkbox" aria-label="Group by parent" checked={groupByParent} onChange={(event) => setGroupByParent(event.target.checked)} /> Group by parent
        </label>
        <label className="inline-flex h-9 items-center gap-2 rounded-md border border-border px-2.5 text-xs text-muted-foreground">
          <input type="checkbox" checked={liveSort} onChange={(event) => {
            const enabled = event.target.checked;
            if (!enabled) setSortOrder(rows.map((process) => process.instance_id));
            setLiveSort(enabled);
          }} /> Live sort
        </label>
        <label className="inline-flex h-9 items-center gap-2 rounded-md border border-border px-2.5 text-xs text-muted-foreground">
          <input type="checkbox" checked={connectionsOnly} onChange={(event) => setConnectionsOnly(event.target.checked)} /> Network activity
        </label>
        <button type="button" onClick={togglePaused} className="inline-flex h-9 items-center gap-2 rounded-md border border-border px-3 text-xs font-medium text-foreground hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring">
          {paused ? <Play className="size-3.5" aria-hidden="true" /> : <Pause className="size-3.5" aria-hidden="true" />}{paused ? "Resume display" : "Pause display"}
        </button>
      </div>
      {profileError ? <p role="alert" className="text-xs text-destructive">Sampling setting was not changed: {profileError}</p> : null}

      <div className="overflow-hidden rounded-lg border border-border bg-card/30">
        <div className="max-h-[55vh] overflow-auto">
          <table className="w-full min-w-[760px] border-collapse text-left text-xs">
            <thead className="sticky top-0 z-10 bg-background/95 text-muted-foreground backdrop-blur">
              <tr className="border-b border-border">
                <th className="w-8 px-3 py-2.5" aria-label="Details" />
                <th className="px-2 py-2.5 font-medium">Process</th><th className="px-2 py-2.5 font-medium">PID</th>
                {showParentColumn ? <th className="px-2 py-2.5 font-medium">Parent PID</th> : null}
                {showPathColumn ? <th className="px-2 py-2.5 font-medium">Executable path</th> : null}
                <th className="px-2 py-2.5 font-medium">Status</th><th className="px-2 py-2.5 text-right font-medium">CPU</th>
                <th className="px-2 py-2.5 text-right font-medium">Memory</th><th className="px-2 py-2.5 text-right font-medium">Entropy / 8</th><th className="px-2 py-2.5 text-right font-medium">Connections</th><th className="px-2 py-2.5 text-right font-medium">I/O bytes (read / write)</th>
                <th className="px-3 py-2.5 text-right font-medium">Risk</th>
              </tr>
            </thead>
            <tbody>
              {(parentGroups ? parentGroups.flatMap(([key, group]) => [
                <tr key={`parent-${key}`} className="border-b border-border bg-muted/30"><th colSpan={10 + Number(showParentColumn) + Number(showPathColumn)} className="px-3 py-2 text-left font-medium text-muted-foreground">Parent {group.label}</th></tr>,
                ...group.processes.map((process) => renderProcessRow(process)),
              ]) : rows.map((process) => renderProcessRow(process)))}
              {rows.length === 0 ? <tr><td colSpan={10 + Number(showParentColumn) + Number(showPathColumn)} className="px-4 py-12 text-center text-sm text-muted-foreground">{streamState === "connected" ? "No accessible processes match this filter." : "Waiting for a process snapshot from the local monitor."}</td></tr> : null}
            </tbody>
          </table>
        </div>
      </div>

      {selected ? (
        <section aria-label={`Details for ${selected.name}`} className="rounded-lg border border-border bg-card/30 p-4">
          <div className="mb-3 flex items-start justify-between gap-3">
            <div><h2 className="text-sm font-semibold text-foreground">{selected.name}</h2><p className="text-xs text-muted-foreground">Process instance {selected.instance_id}</p></div>
            <span className={`rounded border px-2 py-1 text-[10px] ${selected.identity_verified ? "border-emerald-500/30 text-emerald-200" : "border-amber-500/30 text-amber-100"}`}>{selected.identity_verified ? "Identity verified" : "Identity unverified"}</span>
          </div>
          <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2 lg:grid-cols-3">
            <Detail label="PID" value={String(selected.pid)} /><Detail label="Parent PID" value={selected.parent_pid == null ? "Unavailable" : String(selected.parent_pid)} />
            <Detail label="Created" value={selected.create_time == null ? "Unavailable" : new Date(selected.create_time * 1000).toLocaleString()} />
            <Detail label="Executable" value={selected.exe || "Access denied or unavailable"} /><Detail label="CPU" value={percent(selected.cpu_percent)} />
            <Detail label="Working set" value={bytes(selected.memory_bytes)} /><Detail label="Threads" value={selected.thread_count == null ? "Unavailable" : String(selected.thread_count)} />
            <Detail label="Publisher" value="Unavailable — publisher verification is not connected" /><Detail label="Digital signature" value="Unavailable — signature verification is not connected" />
            <Detail label="Network connections" value={connectionsAvailable === null ? "Loading…" : connectionsAvailable ? String(connections.length) : "Unavailable — Windows denied connection enumeration"} />
            <Detail label="I/O source" value={selected.io_semantics || "Unavailable"} />
            <Detail label="Executable entropy" value={selected.entropy_state === "available" && selected.entropy_score != null ? `${selected.entropy_score.toFixed(2)} bits per byte (sampled file)` : selected.entropy_state === "pending" ? "Analysis pending" : "Unavailable"} />
            <Detail label="Automatic scan" value={selected.auto_scan_status || "Pending process analysis"} />
          </dl>
          {connections.length > 0 ? (
            <div className="mt-4 overflow-x-auto border-t border-border/60 pt-3">
              <h3 className="mb-2 text-xs font-semibold text-foreground">Observed connections</h3>
              <table className="w-full min-w-[460px] text-left text-[11px]">
                <thead className="text-muted-foreground"><tr><th className="py-1 pr-3">Protocol</th><th className="py-1 pr-3">Local</th><th className="py-1 pr-3">Remote</th><th className="py-1 pr-3">State</th><th className="py-1">Throughput</th></tr></thead>
                <tbody>{connections.map((connection, index) => <tr key={`${connection.protocol}-${connection.local_port}-${connection.remote_port}-${index}`} className="border-t border-border/50 text-foreground"><td className="py-1 pr-3">{connection.protocol}</td><td className="py-1 pr-3">{connection.local_address ?? "—"}:{connection.local_port ?? "—"}</td><td className="py-1 pr-3">{connection.remote_address ?? "—"}:{connection.remote_port ?? "—"}</td><td className="py-1 pr-3">{connection.state}</td><td className="py-1">{connection.throughput_bytes_per_second == null ? "Unavailable" : `${bytes(connection.throughput_bytes_per_second)}/s`}</td></tr>)}</tbody>
              </table>
            </div>
          ) : null}
          <p className="mt-3 border-t border-border/60 pt-3 text-[11px] text-muted-foreground">Executable entropy is sampled file entropy from 0–8 bits per byte. High scores schedule an asynchronous antivirus scan; entropy alone is not a malware verdict.</p>
          <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-border/60 pt-3">
            <button type="button" onClick={() => void scanSelectedExecutable()} disabled={scanBusy || !selected.exe} className="rounded-md border border-cyan-400/30 bg-cyan-400/10 px-3 py-2 text-xs font-medium text-cyan-100 hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-ring">
              {scanBusy ? "Scanning executable…" : "Scan executable"}
            </button>
            {!selected.exe ? <span className="text-[11px] text-muted-foreground">Executable path is not available yet.</span> : null}
          </div>
          {scanError ? <p role="alert" className="mt-2 text-xs text-destructive">Scan failed: {scanError}</p> : null}
          {scanResults[selected.instance_id] ? <ProcessScanEvidence result={scanResults[selected.instance_id]} /> : null}
        </section>
      ) : null}
    </section>
  );

  function renderProcessRow(process: MonitoredProcess) {
                const expanded = selectedId === process.instance_id;
                return (
                  <tr key={process.instance_id} className={`border-b border-border/60 ${expanded ? "bg-cyan-400/5" : "hover:bg-accent/40"}`}>
                    <td className="px-3 py-2 align-top">
                      <button type="button" aria-label={`${expanded ? "Hide" : "Show"} details for ${process.name}`} onClick={() => setSelectedId(expanded ? null : process.instance_id)} className="rounded p-0.5 text-muted-foreground hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring">
                        {expanded ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
                      </button>
                    </td>
                    <td className="max-w-64 truncate px-2 py-2 font-medium text-foreground" title={process.exe ?? process.name}>{process.name}</td>
                    <td className="px-2 py-2 font-mono text-muted-foreground">{process.pid}</td>
                    {showParentColumn ? <td className="px-2 py-2 font-mono text-muted-foreground">{process.parent_pid ?? "Unavailable"}</td> : null}
                    {showPathColumn ? <td className="max-w-64 truncate px-2 py-2 text-muted-foreground" title={process.exe ?? undefined}>{process.exe ?? "Unavailable"}</td> : null}
                    <td className="px-2 py-2 text-muted-foreground">{process.status || "Unavailable"}</td>
                    <td className="px-2 py-2 text-right tabular-nums text-foreground">{percent(process.cpu_percent)}</td>
                    <td className="px-2 py-2 text-right tabular-nums text-foreground">{bytes(process.memory_bytes)}</td>
                    <td className={`px-2 py-2 text-right tabular-nums ${process.entropy_state === "available" && process.entropy_score != null && process.entropy_score >= (process.entropy_threshold ?? 7.2) ? "text-red-300" : "text-muted-foreground"}`} title={`${process.entropy_source ?? "Executable entropy"} · threshold ${process.entropy_threshold ?? 7.2} bits per byte`}>{process.entropy_state === "available" && process.entropy_score != null ? `${process.entropy_score.toFixed(2)}` : process.entropy_state === "pending" ? "Analyzing…" : process.entropy_state === "queue_full" ? "Queued later" : "Unavailable"}</td>
                    <td className="px-2 py-2 text-right tabular-nums text-muted-foreground">{process.network_connection_count == null ? "Unavailable" : process.network_connection_count}</td>
                    <td className="px-2 py-2 text-right tabular-nums text-muted-foreground">
                      {process.io_read_bytes == null && process.io_write_bytes == null ? "Unavailable" : `${bytes(process.io_read_bytes)} / ${bytes(process.io_write_bytes)}`}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <RiskLabel result={scanResults[process.instance_id]} process={process} />
                    </td>
                  </tr>
                );
  }
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0 border-b border-border/50 py-1.5"><dt className="text-[10px] text-muted-foreground">{label}</dt><dd className="break-all text-xs text-foreground">{value}</dd></div>;
}

function compareProcesses(a: MonitoredProcess, b: MonitoredProcess, sortKey: SortKey): number {
  const left = a[sortKey];
  const right = b[sortKey];
  if (typeof left === "string" && typeof right === "string") return left.localeCompare(right);
  return (Number(right) || 0) - (Number(left) || 0);
}

function RiskLabel({ result, process }: { result?: ProcessScanResult; process: MonitoredProcess }) {
  const status = result?.status ?? process.scan_status;
  if (!status) return <span className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground"><CircleHelp className="size-3" aria-hidden="true" /> {process.auto_scan_status === "scanning" || process.auto_scan_status === "queued" ? "Scan pending" : "Not assessed"}</span>;
  const detected = status === "detected";
  return <span className={`rounded border px-1.5 py-0.5 text-[10px] ${detected ? "border-red-400/30 text-red-200" : "border-border text-muted-foreground"}`}>{detected ? "Detected" : status === "clean" ? "No known match" : "Unknown"}</span>;
}

function ProcessScanEvidence({ result }: { result: ProcessScanResult }) {
  return (
    <div role="status" className={`mt-3 rounded-md border p-3 text-xs ${result.status === "detected" ? "border-red-400/30 bg-red-400/5" : "border-border bg-background/40"}`}>
      <p className="font-medium text-foreground">Executable scan: {result.status} · {result.action}</p>
      <p className="mt-1 text-muted-foreground">{result.reason}</p>
      {result.rule_id ? <p className="mt-1 text-muted-foreground">Rule {result.rule_id} · version {result.rule_version}</p> : null}
      {result.sha256 ? <p className="mt-1 break-all font-mono text-[10px] text-muted-foreground">SHA-256 {result.sha256}</p> : null}
      {result.quarantine ? <p className="mt-1 text-muted-foreground">Quarantine: {result.quarantine.state}{result.quarantine.error ? ` — ${result.quarantine.error}` : ""}</p> : null}
    </div>
  );
}
