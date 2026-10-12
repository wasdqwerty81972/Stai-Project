import React from "react";
import type { SimulationController } from "../app/hooks";
import type { Packet } from "../models/packet";

export function formatAddress(addr: { ip: string; hostId: string; port: number }): string {
  return `${addr.hostId} (${addr.ip}:${addr.port})`;
}

export function MetricsPanel({ sim }: { sim: SimulationController }) {
  const m = sim.metrics;
  const cards = [
    ["Generated", m.generated_packets],
    ["Allowed", m.allowed_packets],
    ["Dropped", m.dropped_packets],
    ["Held", m.held_packets],
    ["Escalated", m.escalated_incidents],
    ["Detection Events", m.detection_events],
  ];

  return (
    <div className="panel">
      <div className="text-xs text-muted text-uppercase" style={{ letterSpacing: "0.04em" }}>
        Metrics (tick {m.current_tick})
      </div>
      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: "0.5rem" }}>
        {cards.map(([label, value]) => (
          <div className="metric-card" key={label}>
            <div className="metric-value">{value as number}</div>
            <div className="metric-label">{label}</div>
          </div>
        ))}
      </div>
      <div className="text-xs text-muted">
        Pass rate: {m.pass_percentage}% · Throughput: {m.simulation_throughput} pkt/tick
      </div>
    </div>
  );
}
