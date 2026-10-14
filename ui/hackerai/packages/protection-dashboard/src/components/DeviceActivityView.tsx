import { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Cpu, Network, Search } from "lucide-react";
import { getDeviceActivity, type DeviceActivity, type LiveProcess, type ProcessAssessment } from "../protection-api";
import { describeRuleMatching } from "../protection-status";
import { PageHeading } from "./PageHeading";

const labels: Record<ProcessAssessment["classification"], string> = {
  known_threat: "Known threat", needs_review: "Needs review", no_known_match: "No known match",
  unavailable: "Not assessed", pending: "Checking…",
};

/** Row caps keep a 400-process machine from re-rendering a 400-row table every poll. */
const ROW_LIMIT = 150;
const SCORE_LIMIT = 30;

function bytes(value: number | null): string {
  if (value === null) return "Sampling…";
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${Math.round(value)} B`;
}

function Assessment({ assessment }: { assessment: ProcessAssessment }) {
  return <span className={`activity-verdict verdict-${assessment.classification}`} title={assessment.reason}>{labels[assessment.classification]}</span>;
}

const processKey = (process: LiveProcess) => process.process_identity || `pid:${process.pid}`;

export function DeviceActivityView({ mode }: { mode: "processes" | "network" }) {
  const [snapshot, setSnapshot] = useState<DeviceActivity | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [sort, setSort] = useState<"name" | "cpu" | "memory" | "entropy">("cpu");
  const [descending, setDescending] = useState(true);
  const [selectedIdentity, setSelectedIdentity] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const current = await getDeviceActivity();
        if (!stopped) { setSnapshot(current); setError(null); }
      } catch (cause) {
        if (!stopped) setError(cause instanceof Error ? cause.message : "Live device activity is unavailable.");
      } finally {
        if (!stopped) timer = window.setTimeout(() => void poll(), 10000);
      }
    };
    void poll();
    return () => { stopped = true; if (timer !== undefined) window.clearTimeout(timer); };
  }, []);

  useEffect(() => { setQuery(""); setFilter("all"); setShowAll(false); }, [mode]);

  const processes = useMemo(() => {
    const text = query.toLowerCase();
    return (snapshot?.processes ?? []).filter((process) =>
      `${process.name} ${process.pid} ${process.username ?? ""} ${process.exe ?? ""}`.toLowerCase().includes(text) &&
      (filter === "all" || process.assessment.classification === filter),
    ).sort((a, b) => {
      const difference = sort === "name" ? (a.name || "").localeCompare(b.name || "") :
        sort === "cpu" ? (a.cpu_percent ?? -1) - (b.cpu_percent ?? -1) :
        sort === "memory" ? (a.memory_bytes ?? -1) - (b.memory_bytes ?? -1) :
        (a.assessment.entropy ?? -1) - (b.assessment.entropy ?? -1);
      return (descending ? -difference : difference) || a.pid - b.pid;
    });
  }, [snapshot, query, filter, sort, descending]);
  const byPid = useMemo(() => new Map(snapshot?.processes.map((process) => [process.pid, process]) ?? []), [snapshot]);
  const byIdentity = useMemo(() => new Map(snapshot?.processes.map((process) => [processKey(process), process]) ?? []), [snapshot]);
  // Resolve each socket's owner once per snapshot instead of three times per render.
  const connections = useMemo(() => {
    const text = query.toLowerCase();
    const owner = (connection: DeviceActivity["connections"][number]) => {
      if (connection.ownership_status && connection.ownership_status !== "verified_snapshot") return undefined;
      if (connection.process_identity) return byIdentity.get(connection.process_identity);
      return connection.pid === null ? undefined : byPid.get(connection.pid);
    };
    return (snapshot?.connections ?? [])
      .filter((connection) =>
        `${connection.process_name} ${connection.pid ?? ""} ${connection.local_address} ${connection.remote_address}`.toLowerCase().includes(text) &&
        (filter === "all" || connection.state === filter),
      )
      .map((connection) => ({ connection, owner: owner(connection) }));
  }, [snapshot, query, filter, byPid, byIdentity]);
  const selected = selectedIdentity === null ? null : byIdentity.get(selectedIdentity);
  const scores = useMemo(
    () => [...(mode === "processes" ? processes : snapshot?.processes ?? [])]
      .sort((a, b) => (b.assessment.entropy ?? -1) - (a.assessment.entropy ?? -1)),
    [mode, processes, snapshot],
  );
  const totalRows = mode === "processes" ? processes.length : connections.length;
  const visibleProcesses = showAll ? processes : processes.slice(0, ROW_LIMIT);
  const visibleConnections = showAll ? connections : connections.slice(0, ROW_LIMIT);
  const visibleScores = showAll ? scores : scores.slice(0, SCORE_LIMIT);
  const truncated = !showAll && totalRows > ROW_LIMIT;
  const ruleMatching = useMemo(() => describeRuleMatching(snapshot?.database), [snapshot]);
  const chooseSort = (next: typeof sort) => {
    if (next === sort) setDescending((value) => !value);
    else { setSort(next); setDescending(next !== "name"); }
  };
  const sortButton = (key: typeof sort, label: string) => <button type="button" className="activity-sort" onClick={() => chooseSort(key)}>{label}{sort === key && (descending ? <ArrowDown size={12} /> : <ArrowUp size={12} />)}</button>;

  return <>
    <PageHeading eyebrow="LIVE DEVICE ACTIVITY" title={mode === "processes" ? "Running processes" : "Network activity"}
      description={mode === "processes" ? "Running tasks with executable analysis and verified rule matches." : "Current TCP and UDP connections, associated tasks, and device traffic."}
      action={<span className={`activity-live ${error ? "is-stale" : ""}`}>{error ? "Connection interrupted" : snapshot?.collecting ? "Refreshing inventory…" : snapshot ? "Live · updates every 10s" : "Connecting…"}</span>} />
    {error && <div className="inline-alert error-alert" role="alert">{error} {snapshot ? "Showing the last successful snapshot while reconnecting." : "Retrying automatically."}</div>}
    {snapshot?.errors.map((message) => <div className="inline-alert" key={message}>{message}</div>)}
    <div className="activity-summary">
      <span><Cpu size={16} /> <strong>{snapshot?.processes.length ?? "—"}</strong> running processes</span>
      <span><Network size={16} /> <strong>{snapshot?.connections.length ?? "—"}</strong> connections</span>
      {snapshot && <><span>↓ {bytes(snapshot.network.download_bytes_sec)} /s</span><span>↑ {bytes(snapshot.network.upload_bytes_sec)} /s</span>
        <span className="activity-observed">Observed {new Date(snapshot.observed_at).toLocaleTimeString()}</span></>}
    </div>
    <div className="activity-layout">
      <section className="panel activity-main" aria-label={mode === "processes" ? "Process list" : "Connection list"}>
        <div className="activity-controls">
          <label className="activity-search"><Search size={16} aria-hidden="true" /><input aria-label="Search device activity" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={mode === "processes" ? "Search name, PID, user or path" : "Search process, PID or address"} /></label>
          <select aria-label="Filter device activity" value={filter} onChange={(event) => setFilter(event.target.value)}>
            <option value="all">All {mode === "processes" ? "processes" : "connections"}</option>
            {mode === "processes" ? Object.entries(labels).map(([value, label]) => <option key={value} value={value}>{label}</option>) : <><option value="ESTABLISHED">Established</option><option value="LISTEN">Listening</option><option value="NONE">UDP / no state</option></>}
          </select>
        </div>
        {!snapshot ? <div className="loading-row" role="status">{error ? "Waiting for the local activity API…" : "Reading running tasks…"}</div> : <div className="activity-table-scroll">
          {mode === "processes" ? <table className="activity-table"><thead><tr>
            <th scope="col">{sortButton("name", "Process")}</th><th scope="col">PID</th><th scope="col">User</th><th scope="col">{sortButton("cpu", "CPU")}</th><th scope="col">{sortButton("memory", "Memory")}</th><th scope="col">{sortButton("entropy", "Entropy")}</th><th scope="col">Assessment</th>
          </tr></thead><tbody>{visibleProcesses.map((process) => <ProcessRow key={processKey(process)} process={process} selected={selectedIdentity === processKey(process)} onSelect={() => setSelectedIdentity(processKey(process))} />)}</tbody></table> :
          <table className="activity-table"><thead><tr><th scope="col">Process / PID</th><th scope="col">Protocol</th><th scope="col">Local address</th><th scope="col">Remote address</th><th scope="col">State</th><th scope="col">Assessment</th></tr></thead><tbody>{visibleConnections.map(({ connection, owner }, index) => <tr key={`${connection.pid}-${connection.local_address}-${connection.remote_address}-${index}`}>
            <td><button type="button" className="activity-process-button" onClick={() => setSelectedIdentity(owner ? processKey(owner) : null)}>{connection.process_name || "Unknown owner"}<small>{connection.pid ?? "PID unavailable"}</small></button></td>
            <td>{connection.protocol}</td><td className="activity-address">{connection.local_address || "—"}</td><td className="activity-address">{connection.remote_address || "—"}</td><td>{connection.state}</td>
            <td>{owner ? <Assessment assessment={owner.assessment} /> : "Owner unavailable"}</td>
          </tr>)}</tbody></table>}
          {totalRows === 0 && <div className="loading-row">No {mode === "processes" ? "processes" : "connections"} match this filter.</div>}
          {truncated && <div className="activity-truncated" role="status">
            Showing the first {ROW_LIMIT} of {totalRows} {mode === "processes" ? "processes" : "connections"}. Search or filter to narrow the list.
            <button type="button" className="text-button" onClick={() => setShowAll(true)}>Show all {totalRows}</button>
          </div>}
        </div>}
        <p className="activity-footnote">{mode === "processes" ? "CPU is a share of total machine capacity. Restricted process details are shown as unavailable." : "Connections are read by user-mode polling, not by a network filter: this list observes traffic and does not block it. Traffic rates are totals for the device; Windows does not provide per-connection bandwidth here."}</p>
      </section>
      <aside className="panel activity-entropy" aria-label="Entropy scores and threat evidence">
        <h2>Entropy & evidence</h2>
        <p>Executable byte entropy, 0–8 bits/byte. A high score can indicate packing or encryption; it does not confirm malware.</p>
        <div className={`activity-database${ruleMatching.matching ? "" : " is-degraded"}`}>
          <strong>{snapshot ? ruleMatching.label : "Rule database not read yet"}</strong>
          <span>{snapshot?.database.version ?? "Not reported"} · {snapshot?.database.rule_count == null ? "count not reported" : `${snapshot.database.rule_count} rules`}</span>
          <small>{snapshot ? (snapshot.database.coverage || ruleMatching.detail) : "Waiting for the first snapshot."}</small>
          {snapshot && !ruleMatching.matching && <small className="activity-database-warning">{ruleMatching.detail}</small>}
        </div>
        {selected && <section className="activity-evidence"><strong>{selected.name} · PID {selected.pid}</strong><Assessment assessment={selected.assessment} /><p>{selected.assessment.reason}</p><span>{selected.exe ?? "Executable path is restricted"}</span>{selected.visibility_errors?.map((message) => <small key={message}>{message}</small>)}{selected.assessment.rule_id && <span>Matched rule: {selected.assessment.rule_id}</span>}{selected.assessment.sha256 && <details><summary>SHA-256</summary><code>{selected.assessment.sha256}</code></details>}<small>Entropy sample: {bytes(selected.assessment.sampled_bytes)}</small></section>}
        <div className="activity-score-list">{visibleScores.map((process) => <button type="button" key={processKey(process)} className={`activity-score${selectedIdentity === processKey(process) ? " selected" : ""}`} onClick={() => setSelectedIdentity(processKey(process))}>
          <span>{process.name}<small>PID {process.pid}</small></span><strong>{process.assessment.entropy?.toFixed(2) ?? "—"}</strong>
          {process.assessment.entropy === null
            ? <small className="activity-score-unmeasured">Entropy not measured</small>
            : <meter min={0} max={8} value={process.assessment.entropy} aria-label={`File entropy for ${process.name}, PID ${process.pid}`} />}
        </button>)}
        {!showAll && scores.length > SCORE_LIMIT && <button type="button" className="text-button" onClick={() => setShowAll(true)}>Show all {scores.length} entropy scores</button>}
        </div>
      </aside>
    </div>
  </>;
}

function ProcessRow({ process, selected, onSelect }: { process: LiveProcess; selected: boolean; onSelect: () => void }) {
  return <tr className={selected ? "selected" : undefined}>
    <td><button type="button" className="activity-process-button" onClick={onSelect} title={process.exe ?? "Executable path unavailable"}>{process.name}<small>{process.status}</small></button></td>
    <td>{process.pid}</td><td>{process.username ?? "Restricted"}</td><td>{process.cpu_percent === null ? "Sampling…" : `${process.cpu_percent.toFixed(1)}%`}</td><td>{process.memory_bytes === null ? "Restricted" : bytes(process.memory_bytes)}</td><td>{process.assessment.entropy?.toFixed(2) ?? "—"}</td><td><Assessment assessment={process.assessment} /></td>
  </tr>;
}
