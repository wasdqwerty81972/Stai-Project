import React from "react";
import type { SimulationController } from "../app/hooks";
import type { Packet } from "../models/packet";
import { evaluatePacket } from "../detection/scoring";

export function EventLog({ sim }: { sim: SimulationController }) {
  const [query, setQuery] = React.useState("");
  const events = React.useMemo(() => {
    const raw = sim.metrics;
    return (sim as any)._eventsList ?? [];
  }, [sim]);

  const allEvents = React.useMemo(() => {
    const engine = (sim as any)._engine;
    return engine ? Array.from(engine.store.events.all()) : [];
  }, [sim]);

  const filtered = React.useMemo(() => {
    if (!query) return allEvents;
    const q = query.toLowerCase();
    return allEvents.filter(
      (e: any) =>
        e.type.toLowerCase().includes(q) ||
        e.packetId.toLowerCase().includes(q) ||
        (e.explanation?.toLowerCase().includes(q) ?? false),
    );
  }, [allEvents, query]);

  const clear = () => {
    const engine = (sim as any)._engine;
    if (engine) engine.store.events.clear();
    forceUpdate();
  };

  const [, setTick] = React.useState(0);
  const forceUpdate = () => setTick((n) => n + 1);

  return (
    <div className="panel">
      <div className="flex justify-between items-center">
        <div className="text-xs text-muted" style={{ textTransform: "uppercase", letterSpacing: "0.04em" }}>
          Event Log ({filtered.length})
        </div>
        <div className="flex gap-xs items-center">
          <input
            type="text"
            placeholder="Search events..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="surface"
            style={{ background: "var(--surface-2)", width: "180px" }}
            aria-label="Search events"
          />
          <button className="btn btn-danger" onClick={clear} aria-label="Clear history">
            Clear
          </button>
        </div>
      </div>
      <div className="event-log">
        {filtered.length === 0 ? (
          <div className="text-sm text-muted p-2">No events. Run the simulation.</div>
        ) : (
          filtered.map((e: any) => (
            <div className="event-row" key={e.id}>
              <span className="event-time">t={e.tick}</span>
              <span className="event-type">{e.type}</span>
              <span className="text-secondary">{e.packetId}</span>
              {e.score !== undefined && <span className="text-muted">score={e.score}</span>}
              {e.action && <span className="text-muted">action={e.action}</span>}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export function ThreatPanel({ sim }: { sim: SimulationController }) {
  const p = sim.activePacket;
  if (!p) {
    return (
      <div className="panel">
        <div className="text-xs text-muted" style={{ textTransform: "uppercase", letterSpacing: "0.04em" }}>
          Threat Details
        </div>
        <div className="text-muted text-sm">Select a packet to inspect its threat analysis.</div>
      </div>
    );
  }
  const result = evaluatePacket(p);
  return (
    <div className="panel">
      <div className="text-xs text-muted" style={{ textTransform: "uppercase", letterSpacing: "0.04em" }}>
        Threat Analysis — {p.id}
      </div>
      <div className="flex gap-sm items-center">
        <span className={"status-badge " + badgeClass(p.state)}>
          {p.state}
        </span>
        <span className="text-xs text-muted">Protocol: {p.protocol}</span>
        <span className="text-xs text-muted">Port: {p.destination.port}</span>
      </div>
      <div>
        <div className="text-sm">Score: <b>{result.score}</b>/100 — <span className={severityColor(result.severity)}>{result.severity}</span></div>
        <div className="text-xs text-muted mt-1">{result.explanation}</div>
      </div>
      <div className="text-xs text-muted">Matched rules:</div>
      {result.matchedRules.length === 0 ? (
        <div className="text-xs text-muted">none</div>
      ) : (
        <ul className="text-xs" style={{ paddingLeft: "1rem" }}>
          {result.matchedRules.map((r) => (
            <li key={r.ruleId}>
              {r.name}: +{r.contribution} — {r.reason}
            </li>
          ))}
        </ul>
      )}
      <div className="text-xs text-muted">
        Note: this is a simulation heuristic, not a probability of compromise.
      </div>
      <div className="flex gap-xs mt-2">
        {sim.held.map((h) => h.id).includes(p.id) ? (
          <>
            <button className="btn btn-success" onClick={() => sim.approve(p.id)}>Approve</button>
            <button className="btn btn-danger" onClick={() => sim.drop(p.id)}>Drop</button>
            <button className="btn btn-warning" onClick={() => sim.escalate(p.id)}>Escalate</button>
          </>
        ) : null}
      </div>
    </div>
  );
}

function badgeClass(state: string): string {
  switch (state) {
    case "ALLOWED": return "badge-allowed";
    case "DROPPED": return "badge-dropped";
    case "ESCALATED": return "badge-escalated";
    case "HOLDING_INTERCEPT": return "badge-held";
    default: return "badge-safe";
  }
}

function severityColor(severity: string): string {
  switch (severity) {
    case "SAFE": return "text-allowed";
    case "SUSPICIOUS": return "text-muted";
    case "HIGH": return "text-suspicious";
    case "CRITICAL": return "text-critical";
    default: return "text-secondary";
  }
}
