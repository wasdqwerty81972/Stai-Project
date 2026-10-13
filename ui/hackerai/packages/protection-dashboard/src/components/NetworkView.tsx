import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowUpFromLine,
  CircleHelp,
  Globe2,
  RefreshCw,
  Search,
  Shield,
  X,
} from "lucide-react";
import type { NetworkConnectionRecord, NetworkSnapshot } from "../protection-api";
import { PageHeading } from "./PageHeading";
import { StatusPill } from "./StatusPill";

function formatRate(value: number | null | undefined) {
  if (value == null) return "—";
  if (value < 1024) return `${value.toLocaleString()} B/s`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB/s`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB/s`;
}

function endpoint(address: string | null, port: number | null) {
  if (!address) return "—";
  return port == null ? address : `${address}:${port}`;
}

function timestamp(value: string | null | undefined) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleTimeString();
}

export function NetworkView({
  snapshot,
  error,
  loading,
  onRefresh,
}: {
  snapshot: NetworkSnapshot | null;
  error: string | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  const [filter, setFilter] = useState("");
  const [protocol, setProtocol] = useState("all");
  const [selected, setSelected] = useState<NetworkConnectionRecord | null>(null);
  const [onionizeOpen, setOnionizeOpen] = useState(false);
  const [rateHistory, setRateHistory] = useState<Array<{ at: string; down: number | null; up: number | null }>>([]);

  useEffect(() => {
    if (!snapshot?.observed_at) return;
    setRateHistory((current) => {
      if (current.at(-1)?.at === snapshot.observed_at) return current;
      return [...current, {
        at: snapshot.observed_at,
        down: snapshot.throughput.download_bytes_per_second,
        up: snapshot.throughput.upload_bytes_per_second,
      }].slice(-60);
    });
  }, [snapshot]);

  const connections = snapshot?.connections ?? [];
  const visibleConnections = useMemo(() => connections.filter((connection) => {
    const query = filter.trim().toLowerCase();
    const matchesQuery = !query || [
      connection.process_name,
      connection.executable_path,
      connection.local_address,
      connection.remote_address,
      String(connection.local_port ?? ""),
      String(connection.remote_port ?? ""),
      connection.state,
    ].some((value) => value?.toLowerCase().includes(query));
    return matchesQuery && (protocol === "all" || connection.protocol === protocol);
  }), [connections, filter, protocol]);

  const tcpCount = connections.filter((item) => item.protocol === "tcp").length;
  const udpCount = connections.filter((item) => item.protocol === "udp").length;
  const destinations = new Set(connections.map((item) => item.remote_address).filter(Boolean));

  return (
    <>
      <PageHeading
        eyebrow="NETWORK DEFENSE"
        title="Network"
        description="Live socket and interface observations from this device. Payloads are not captured."
        action={(
          <div className="network-heading-actions">
            <StatusPill state={snapshot?.state ?? "unavailable"} />
            <button className="secondary-button compact-button" onClick={onRefresh} type="button" disabled={loading}>
              <RefreshCw size={14} aria-hidden="true" /> Refresh
            </button>
            <button className="onionize-button" onClick={() => setOnionizeOpen(true)} type="button">
              <Globe2 size={15} aria-hidden="true" /> ONIONIZE
            </button>
          </div>
        )}
      />

      {error && <div className="inline-alert error-alert" role="alert">{error}</div>}
      {snapshot?.state === "unavailable" && !error && (
        <div className="inline-alert warning-alert" role="status">
          <AlertTriangle size={16} aria-hidden="true" /> Network collection is unavailable. No empty or safe result is being inferred.
        </div>
      )}

      <section className="network-metrics" aria-label="Network summary">
        <NetworkMetric icon={ArrowDownToLine} label="Interface download" value={formatRate(snapshot?.throughput.download_bytes_per_second)} note="Aggregate interface counters" />
        <NetworkMetric icon={ArrowUpFromLine} label="Interface upload" value={formatRate(snapshot?.throughput.upload_bytes_per_second)} note="Aggregate interface counters" />
        <NetworkMetric icon={Activity} label="TCP sockets" value={snapshot?.connections ? tcpCount.toLocaleString() : "—"} note="Current snapshot" />
        <NetworkMetric icon={Globe2} label="UDP endpoints" value={snapshot?.connections ? udpCount.toLocaleString() : "—"} note={`${destinations.size} observed destinations`} />
      </section>

      <RateHistory history={rateHistory} />

      <section className="network-layout">
        <div className="panel network-table-panel">
          <div className="panel-heading network-panel-heading">
            <div><div className="eyebrow">ACTIVE SOCKET SNAPSHOT</div><h2>Connections and endpoints</h2></div>
            <span className="network-last-seen">Updated {timestamp(snapshot?.observed_at)}</span>
          </div>
          <div className="network-controls">
            <label className="network-search"><Search size={15} aria-hidden="true" /><span className="sr-only">Search connections</span><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Process, address, or port" /></label>
            <label className="network-protocol"><span className="sr-only">Protocol filter</span><select value={protocol} onChange={(event) => setProtocol(event.target.value)}><option value="all">All protocols</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
          </div>
          <div className="network-table-scroll">
            <table className="network-table">
              <thead><tr><th>Process</th><th>Local endpoint</th><th>Remote endpoint</th><th>Protocol</th><th>State</th><th>Direction</th><th aria-label="Actions" /></tr></thead>
              <tbody>
                {!snapshot?.connections && <tr><td className="network-table-empty" colSpan={7}>{loading ? "Reading local network state…" : "Connection details are unavailable."}</td></tr>}
                {snapshot?.connections && visibleConnections.length === 0 && <tr><td className="network-table-empty" colSpan={7}>{connections.length ? "No connections match these filters." : "No active sockets were observed in this snapshot."}</td></tr>}
                {visibleConnections.slice(0, 500).map((connection) => (
                  <tr key={connection.connection_id} className={selected?.connection_id === connection.connection_id ? "is-selected" : ""} onClick={() => setSelected(connection)}>
                    <td><strong>{connection.process_name ?? "Unknown process"}</strong><small>{connection.pid ? `PID ${connection.pid}` : "PID unavailable"}</small></td>
                    <td className="mono-cell">{endpoint(connection.local_address, connection.local_port)}</td>
                    <td className="mono-cell">{endpoint(connection.remote_address, connection.remote_port)}</td>
                    <td><span className={`protocol-tag ${connection.protocol}`}>{connection.protocol.toUpperCase()}</span><small>{connection.family.toUpperCase()}</small></td>
                    <td>{connection.state || "—"}</td>
                    <td><span className="muted-inline"><CircleHelp size={12} aria-hidden="true" /> Unknown</span></td>
                    <td><button className="row-action" type="button" aria-label={`Inspect ${connection.process_name ?? "connection"}`} onClick={(event) => { event.stopPropagation(); setSelected(connection); }}>Inspect</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="network-table-foot">Showing up to 500 of {visibleConnections.length.toLocaleString()} matching sockets · Observed {timestamp(snapshot?.observed_at)}</div>
        </div>

        <aside className="network-side-column">
          <section className="panel network-side-panel">
            <div className="panel-heading"><div><div className="eyebrow">INTERFACES</div><h2>Network adapters</h2></div><span className="panel-icon"><Activity size={17} aria-hidden="true" /></span></div>
            {!snapshot?.interfaces ? <p className="network-muted">Adapter inventory unavailable.</p> : snapshot.interfaces.length === 0 ? <p className="network-muted">No adapters were reported.</p> : <div className="interface-list">{snapshot.interfaces.map((networkInterface) => <article className="interface-item" key={networkInterface.name}><div><strong>{networkInterface.name}</strong><span className={`interface-state ${networkInterface.is_up ? "up" : "down"}`}>{networkInterface.is_up === null ? "Unknown" : networkInterface.is_up ? "Up" : "Down"}</span></div><small>{networkInterface.addresses.map((item) => item.address).join(" · ") || "No IP addresses reported"}</small></article>)}</div>}
          </section>
          <section className="panel network-side-panel">
            <div className="panel-heading"><div><div className="eyebrow">VISIBILITY</div><h2>Collection coverage</h2></div><span className="panel-icon"><Shield size={17} aria-hidden="true" /></span></div>
            <CoverageLine label="Socket snapshot" value={snapshot?.coverage.connections} />
            <CoverageLine label="Process attribution" value={snapshot?.coverage.process_attribution} />
            <CoverageLine label="Traffic direction" value={snapshot?.coverage.direction} />
            <CoverageLine label="Payload capture" value={snapshot?.coverage.payload_capture} />
            <CoverageLine label="Per-process bytes" value={snapshot?.coverage.per_process_bytes} />
            {snapshot?.errors.map((item) => <p className="network-inline-warning" key={item}><AlertTriangle size={13} aria-hidden="true" /> {item}</p>)}
          </section>
        </aside>
      </section>

      {selected && (
        <div className="detail-overlay" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setSelected(null); }}>
          <section className="detail-drawer" role="dialog" aria-modal="true" aria-labelledby="connection-detail-title">
            <div className="drawer-heading"><div><div className="eyebrow">CONNECTION DETAIL</div><h2 id="connection-detail-title">{selected.process_name ?? "Unknown process"}</h2></div><button className="icon-button" aria-label="Close details" onClick={() => setSelected(null)} type="button"><X size={17} /></button></div>
            <div className="detail-list"><DetailRow label="Executable" value={selected.executable_path ?? "Unavailable"} /><DetailRow label="PID / identity" value={`${selected.pid ?? "Unknown"}${selected.process_identity ? ` · ${selected.process_identity}` : ""}`} /><DetailRow label="Protocol" value={`${selected.protocol.toUpperCase()} · ${selected.family.toUpperCase()}`} /><DetailRow label="Local endpoint" value={endpoint(selected.local_address, selected.local_port)} /><DetailRow label="Remote endpoint" value={endpoint(selected.remote_address, selected.remote_port)} /><DetailRow label="Direction" value="Unknown from socket snapshot" /><DetailRow label="First observed" value={timestamp(selected.first_seen)} /><DetailRow label="Last observed" value={timestamp(selected.last_seen)} /></div>
            <p className="helper-note">Direction and payload are not collected in this socket snapshot. Review suspicious processes in Windows Security while SVS Cyber firewall rule management is being hardened.</p>
          </section>
        </div>
      )}

      {onionizeOpen && (
        <div className="detail-overlay modal-overlay" role="presentation"><section className="confirmation-modal onionize-modal" role="dialog" aria-modal="true" aria-labelledby="onionize-title"><div className="drawer-heading"><div><div className="eyebrow">PRIVACY ROUTING</div><h2 id="onionize-title">ONIONIZE</h2></div><button className="icon-button" aria-label="Close ONIONIZE panel" onClick={() => setOnionizeOpen(false)} type="button"><X size={17} /></button></div><div className="onionize-state"><span className="state-dot off" /> OFF <span>· Not configured</span></div><p>SVS Cyber is not routing device traffic through Tor. This dashboard does not change Windows proxy or firewall routes. A SOCKS proxy alone would not route every Windows app and could leave direct-connection leaks.</p><div className="onionize-scope"><Shield size={16} /><span><strong>Device-wide Tor routing</strong><small>Unavailable. Requires a separately reviewed Windows traffic-routing component.</small></span></div><div className="onionize-scope"><Globe2 size={16} /><span><strong>Tor Browser mode</strong><small>Can protect traffic opened inside Tor Browser only; it does not protect other applications.</small></span></div><div className="modal-actions"><button className="secondary-button" onClick={() => setOnionizeOpen(false)} type="button">Close</button></div></section></div>
      )}
    </>
  );
}

function NetworkMetric({ icon: Icon, label, value, note }: { icon: typeof Activity; label: string; value: string; note: string }) {
  return <article className="network-metric"><span className="network-metric-icon"><Icon size={16} aria-hidden="true" /></span><span className="network-metric-label">{label}</span><strong>{value}</strong><small>{note}</small></article>;
}

function CoverageLine({ label, value }: { label: string; value: string | undefined }) {
  let display = value ?? "Not reported";
  if (display === "active_socket_snapshot") display = "Current sockets only";
  if (display === "best_effort_pid_and_creation_time") display = "Best effort";
  if (display === "unknown_from_snapshot") display = "Unknown";
  if (display === "not_collected") display = "Not collected";
  if (display === "unavailable") display = "Unavailable";
  return <div className="coverage-line"><span>{label}</span><strong>{display}</strong></div>;
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return <div className="detail-row"><span>{label}</span><strong title={value}>{value}</strong></div>;
}

function RateHistory({ history }: { history: Array<{ at: string; down: number | null; up: number | null }> }) {
  const available = history.filter((point) => point.down !== null || point.up !== null);
  const ceiling = Math.max(1, ...available.flatMap((point) => [point.down ?? 0, point.up ?? 0]));
  const pathFor = (key: "down" | "up") => available
    .filter((point) => point[key] !== null)
    .map((point, index, rows) => `${index === 0 ? "M" : "L"} ${(index / Math.max(1, rows.length - 1)) * 560 + 20} ${100 - ((point[key] ?? 0) / ceiling) * 82}`)
    .join(" ");
  return (
    <section className="panel network-history-panel" aria-label="Network rate history">
      <div className="panel-heading"><div><div className="eyebrow">MEASURED INTERFACE COUNTERS</div><h2>Traffic rate history</h2></div><div className="network-chart-legend"><span><i className="legend-download" /> Download</span><span><i className="legend-upload" /> Upload</span></div></div>
      {available.length < 2 ? <div className="network-chart-empty">Waiting for two valid interface counter samples. Rates are device-wide and cannot be attributed to individual processes.</div> : <svg className="network-rate-chart" viewBox="0 0 600 120" role="img" aria-label="Historical download and upload rates derived from interface counters"><path className="chart-gridline" d="M20 18H580 M20 58H580 M20 100H580" /><path className="chart-download-line" d={pathFor("down")} /><path className="chart-upload-line" d={pathFor("up")} /></svg>}
      <div className="network-chart-foot"><span>{available.length} measured samples · most recent {timestamp(history.at(-1)?.at)}</span><span>Max sample: {formatRate(ceiling)}</span></div>
    </section>
  );
}
