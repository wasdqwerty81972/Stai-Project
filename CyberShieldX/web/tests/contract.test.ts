import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, beforeEach } from "vitest";
import { SimulationEngine } from "../src/simulation/engine";
import { evaluatePacket, clampScore, roundScore, severityForScore } from "../src/detection/scoring";
import { SeededPRNG } from "../src/simulation/prng";
import { EventBuffer } from "../src/state/event-buffer";

const FIXTURES = path.resolve(import.meta.dirname, "../../fixtures");

function readFixture(name: string): any {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), "utf-8"));
}

function packetSpecs(fixture: any) {
  return fixture.packets.map((p: any) => ({
    tick: p.tick,
    protocol: p.protocol,
    src: p.src,
    dst: p.dst,
    kind: p.kind,
    size: p.size,
    payload: p.payload,
  }));
}

describe("shared contract: PRNG determinism", () => {
  it("produces identical sequences for the same seed", () => {
    const a = SeededPRNG.sequence(42, 100);
    const b = SeededPRNG.sequence(42, 100);
    expect(a).toEqual(b);
  });

  it("produces different sequences for different seeds", () => {
    const a = SeededPRNG.sequence(42, 100);
    const b = SeededPRNG.sequence(7, 100);
    expect(a).not.toEqual(b);
  });
});

describe("shared contract: safe traffic", () => {
  let engine: SimulationEngine;
  const fixture = readFixture("safe-traffic.json");
  const expected = readFixture("expected-results.json").safe_traffic;

  beforeEach(() => {
    engine = new SimulationEngine(300);
    engine.loadScenario(packetSpecs(fixture));
  });

  it("generates the expected number of packets", () => {
    expect(engine.store.getAllPackets().length).toBe(expected.packetCount);
    expect(engine.store.generated_packets).toBe(expected.generated);
  });

  it("all packets are allowed after running to steady state", () => {
    engine.runUntilSteady();
    const snap = engine.getMetrics();
    expect(snap.allowed_packets).toBe(expected.allowed_after_inspection);
    expect(snap.held_packets).toBe(expected.held_after_inspection);
    expect(snap.dropped_packets).toBe(0);
    expect(snap.escalated_incidents).toBe(0);
  });

  it("pass percentage is 100 for safe traffic", () => {
    engine.runUntilSteady();
    expect(engine.getMetrics().pass_percentage).toBe(expected.pass_percentage);
  });

  it("computes expected per-packet scores", () => {
    const packets = engine.store.getAllPackets();
    const burstMap = new Map<string, number>();
    for (const p of packets) {
      const key = p.source.hostId + "|" + String(p.destination.port);
      burstMap.set(key, (burstMap.get(key) ?? 0) + 1);
    }
    const scores: number[] = [];
    for (const p of packets) {
      const result = evaluatePacket(p, undefined, burstMap.get(p.source.hostId + "|" + String(p.destination.port)) ?? 0, 1);
      scores.push(result.score);
    }
    expect(scores).toEqual(expected.scores);
  });
});

describe("shared contract: suspicious traffic", () => {
  const fixture = readFixture("suspicious-traffic.json");
  const expected = readFixture("expected-results.json").suspicious_traffic;
  let engine: SimulationEngine;

  beforeEach(() => {
    engine = new SimulationEngine(300);
    engine.loadScenario(packetSpecs(fixture));
  });

  it("all packets are flagged and held after inspection", () => {
    engine.runUntilSteady();
    expect(engine.store.detection_events).toBe(expected.flagged);
    expect(engine.store.held_packets).toBe(expected.held_after_inspection);
  });

  it("computes expected per-packet scores", () => {
    const packets = engine.store.getAllPackets();
    const burstMap = new Map<string, number>();
    for (const p of packets) {
      const key = p.source.hostId + "|" + String(p.destination.port);
      burstMap.set(key, (burstMap.get(key) ?? 0) + 1);
    }
    const portScan = new Map<string, number>();
    for (const p of packets) {
      portScan.set(p.source.hostId, 1);
    }
    const scores: number[] = [];
    for (const p of packets) {
      const result = evaluatePacket(p, undefined, burstMap.get(p.source.hostId + "|" + String(p.destination.port)) ?? 0, portScan.get(p.source.hostId) ?? 0);
      scores.push(result.score);
    }
    expect(scores).toEqual(expected.scores);
  });

  it("severity for first packet (score 75) is HIGH", () => {
    expect(severityForScore(75)).toBe("HIGH");
  });
});

describe("shared contract: operator actions", () => {
  const fixture = readFixture("suspicious-traffic.json");
  const expected = readFixture("expected-results.json").operator_actions_suspicious.expected;
  let engine: SimulationEngine;

  beforeEach(() => {
    engine = new SimulationEngine(300);
    engine.loadScenario(packetSpecs(fixture));
    engine.runUntilSteady();
  });

  it("resolves packets with APPROVE/DROP/ESCALATE exactly once", () => {
    for (const a of readFixture("expected-results.json").operator_actions_suspicious.actions) {
      const r = engine.performAction(a.action as any, a.target);
      expect(r.ok).toBe(true);
    }
    const snap = engine.getMetrics();
    expect(snap.allowed_packets).toBe(expected.allowed);
    expect(snap.dropped_packets).toBe(expected.dropped);
    expect(snap.escalated_incidents).toBe(expected.escalated);
    expect(snap.held_packets).toBe(expected.held);
    expect(snap.resolved_packets).toBe(expected.resolved);
    expect(snap.pass_percentage).toBe(expected.pass_percentage);
  });

  it("duplicate operator actions are rejected", () => {
    const r1 = engine.performAction("APPROVE", "pkt_0001");
    expect(r1.ok).toBe(true);
    const r2 = engine.performAction("APPROVE", "pkt_0001");
    expect(r2.ok).toBe(false);
  });

  it("actions on non-held (terminal) packets are rejected", () => {
    const e2 = new SimulationEngine(300);
    e2.loadScenario(packetSpecs(readFixture("safe-traffic.json")));
    e2.runUntilSteady();
    const p = e2.store.getAllPackets()[0] ?? Array.from(e2.store.terminal.values())[0];
    expect(p.state).toBe("ALLOWED");
    const r = e2.performAction("APPROVE", p.id);
    expect(r.ok).toBe(false);
  });
});

describe("shared contract: state machine & transitions", () => {
  it("rejects invalid transition from terminal state", () => {
    const engine = new SimulationEngine();
    const fixture = readFixture("safe-traffic.json");
    engine.loadScenario(packetSpecs({ ...fixture, packets: fixture.packets.slice(0, 1) }));
    engine.runUntilSteady();
    const p = engine.store.getAllPackets()[0];
    expect(p.state).toBe("ALLOWED");
    const r = engine.performAction("APPROVE", p.id);
    expect(r.ok).toBe(false);
  });
});

describe("shared contract: edge cases", () => {
  it("empty input yields zero counters and 0.0 pass percentage", () => {
    const engine = new SimulationEngine();
    engine.runUntilSteady();
    const snap = engine.getMetrics();
    expect(snap.generated_packets).toBe(0);
    expect(snap.resolved_packets).toBe(0);
    expect(snap.pass_percentage).toBe(0);
  });

  it("buffer rollover never exceeds capacity and evicts oldest", () => {
    const small = readFixture("edge-cases.json").cases.find((c: any) => c.name === "buffer_rollover");
    const engine = new SimulationEngine(300);
    const fixture = readFixture("safe-traffic.json");
    let all: any[] = [];
    for (let i = 0; i < 4; i++) {
      all = all.concat(packetSpecs(fixture));
    }
    engine.loadScenario(all);
    const before = engine.store.getAllPackets().length;
    expect(before).toBe(48);
    engine.runUntilSteady();
    const events = engine.store.events.all();
    expect(events.length).toBeLessThanOrEqual(300);
  });

  it("reset clears all packets and counters", () => {
    const engine = new SimulationEngine(300);
    engine.loadScenario(packetSpecs(readFixture("suspicious-traffic.json")));
    engine.runUntilSteady();
    engine.reset();
    expect(engine.store.getAllPackets().length).toBe(0);
    expect(engine.store.getMetricSnapshot().generated_packets).toBe(0);
    expect(engine.store.events.all().length).toBe(0);
  });

  it("deterministic replay produces identical state and metrics", () => {
    const fixture = readFixture("safe-traffic.json");
    const runOne = () => {
      const e = new SimulationEngine(300);
      e.loadScenario(packetSpecs(fixture));
      e.runUntilSteady();
      return { snap: e.getMetrics(), states: e.store.getAllPackets().map((p) => p.state), terminal: Array.from(e.store.terminal.entries()) };
    };
    const a = runOne();
    const b = runOne();
    expect(a.snap).toEqual(b.snap);
    expect(a.states).toEqual(b.states);
    expect(a.terminal).toEqual(b.terminal);
  });

  it("boundary: score 35 auto-allowed, score 40 held", () => {
    const engine = new SimulationEngine(300);
    const caseObj = readFixture("edge-cases.json").cases.find((c: any) => c.name === "score_boundary_safe");
    engine.loadScenario(packetSpecs(caseObj));
    engine.runUntilSteady();
    expect(engine.store.getPacket("pkt_0001")?.state).toBe("ALLOWED");
    expect(engine.store.getPacket("pkt_0002")?.state).toBe("HOLDING_INTERCEPT");
  });
});

describe("shared contract: scoring helpers", () => {
  it("clamps to [0,100]", () => {
    expect(clampScore(-5)).toBe(0);
    expect(clampScore(150)).toBe(100);
    expect(clampScore(42)).toBe(42);
  });

  it("rounds half-to-even to 2 decimals", () => {
    expect(roundScore(2.675)).toBeCloseTo(2.68, 2);
    expect(roundScore(10)).toBe(10);
  });

  it("severity thresholds match contract", () => {
    expect(severityForScore(0)).toBe("SAFE");
    expect(severityForScore(39)).toBe("SAFE");
    expect(severityForScore(40)).toBe("SUSPICIOUS");
    expect(severityForScore(74)).toBe("SUSPICIOUS");
    expect(severityForScore(75)).toBe("HIGH");
    expect(severityForScore(89)).toBe("HIGH");
    expect(severityForScore(90)).toBe("CRITICAL");
    expect(severityForScore(100)).toBe("CRITICAL");
  });
});

describe("shared contract: event buffer limits", () => {
  it("EventBuffer respects capacity and FIFO eviction", () => {
    const buf = new EventBuffer(5);
    for (let i = 0; i < 10; i++) {
      buf.add({ id: "e" + i, tick: i, type: "packet_created", severity: "INFO", packetId: "p" + i });
    }
    expect(buf.all().length).toBe(5);
    expect(buf.all()[0].id).toBe("e5");
    expect(buf.all()[4].id).toBe("e9");
  });
});
