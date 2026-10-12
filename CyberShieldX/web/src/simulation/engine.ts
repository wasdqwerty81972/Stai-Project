import type {
  Packet,
  PacketState,
  MetricSnapshot,
  OperatorActionResult,
  OperatorAction,
  DetectionResult,
} from "../models/packet";
import type { ScenarioPacketSpec } from "./scenarios";
import { evaluatePacket, computeBurstMap, computePortScanMap, DEFAULT_CONFIG } from "../detection/scoring";
import { PacketStore } from "../state/packet-store";
import type { SimulationEvent } from "../state/event-buffer";

export class SimulationEngine {
  readonly store: PacketStore;
  private paused: boolean = true;
  private speed: number = 1;

  constructor(eventsCapacity: number = 300) {
    this.store = new PacketStore(eventsCapacity);
  }

  getConfig() {
    return DEFAULT_CONFIG;
  }

  loadScenario(packets: ScenarioPacketSpec[]): void {
    this.reset();
    for (const spec of packets) {
      this.store.addPacket({
        id: "",
        tick: spec.tick,
        protocol: spec.protocol,
        source: { ...spec.src },
        destination: { ...spec.dst },
        kind: spec.kind,
        size: spec.size,
        payload: spec.payload,
        flags: { isRepeated: false, isPortScan: false },
        state: "CREATED",
      });
    }
  }

  reset(): void {
    this.store.reset();
    this.paused = true;
    this.speed = 1;
  }

  start(): void {
    this.paused = false;
  }

  pause(): void {
    this.paused = true;
  }

  resume(): void {
    this.paused = false;
  }

  setSpeed(multiplier: number): void {
    this.speed = Math.max(1, Math.min(8, Math.floor(multiplier)));
  }

  isRunning(): boolean {
    return !this.paused;
  }

  getSpeed(): number {
    return this.speed;
  }

  private advanceTick(): void {
    this.store.current_tick += 1;
    const tick = this.store.current_tick;
    const packets = this.store.getAllPackets();

    const burstMap = computeBurstMap(packets);
    const portScanMap = computePortScanMap(packets);

    const toInspect = packets.filter((p) => p.state === "CREATED" && p.tick <= tick);
    for (const p of toInspect) {
      this.transition(p, "INSPECTING");
      this.store.inspected_packets += 1;
      this.store.recordLatency(p.id, tick - p.tick);
    }

    const inspecting = packets.filter((p) => p.state === "INSPECTING");
    for (const p of inspecting) {
      const result = evaluatePacket(
        p,
        DEFAULT_CONFIG,
        burstMap.get(p.source.hostId + "|" + String(p.destination.port)) ?? 0,
        portScanMap.get(p.source.hostId) ?? 0,
      );
      if (result.flagged) {
        this.transition(p, "HOLDING_INTERCEPT");
        this.store.held_packets += 1;
        this.store.detection_events += 1;
        this.store.recordEvent({
          tick,
          type: "detection_flagged",
          severity: severityRank(result.severity),
          packetId: p.id,
          score: result.score,
          explanation: result.explanation,
        });
      } else {
        this.transition(p, "ALLOWED");
        this.store.allowed_packets += 1;
      }
    }
  }

  private transition(p: Packet, to: PacketState): void {
    const from = p.state;
    if (from === to) {
      return;
    }
    this.store.recordEvent({
      tick: this.store.current_tick,
      type: "state_transition",
      severity: "INFO",
      packetId: p.id,
      stateFrom: from,
      stateTo: to,
    });
    p.state = to;
  }

  step(): void {
    this.advanceTick();
  }

  run(toTick: number): void {
    while (this.store.current_tick < toTick) {
      this.step();
    }
  }

  runUntilSteady(): void {
    let guard = 0;
    while (guard < 10000) {
      const before = this.store.current_tick;
      this.step();
      guard += 1;
      const maxPkt = this.maxPacketTick();
      const nonHeldActive = this.store
        .getAllPackets()
        .filter((p) => p.state === "CREATED" || p.state === "INSPECTING").length;
      if (this.store.current_tick >= maxPkt && nonHeldActive === 0) {
        break;
      }
      if (this.store.current_tick === before && nonHeldActive === 0) {
        break;
      }
    }
  }

  maxPacketTick(): number {
    const all = this.store.getAllPackets();
    if (all.length === 0) return 0;
    return Math.max(...all.map((p) => p.tick));
  }

  evaluatePacket(packet: Packet): DetectionResult {
    const burstMap = computeBurstMap(this.store.getAllPackets());
    const portScanMap = computePortScanMap(this.store.getAllPackets());
    return evaluatePacket(
      packet,
      DEFAULT_CONFIG,
      burstMap.get(packet.source.hostId + "|" + String(packet.destination.port)) ?? 0,
      portScanMap.get(packet.source.hostId) ?? 0,
    );
  }

  performAction(action: OperatorAction, targetPacket: string): OperatorActionResult {
    const p = this.store.getPacket(targetPacket);
    if (!p) {
      return { ok: false, reason: "pack_not_found" };
    }

    switch (action) {
      case "APPROVE": {
        if (p.state !== "HOLDING_INTERCEPT") {
          return { ok: false, reason: "invalid_state_for_action" };
        }
        const prev = p.state;
        this.transition(p, "ALLOWED");
        this.store.allowed_packets += 1;
        this.store.held_packets -= 1;
        this.store.moveToTerminal(p);
        this.store.recordEvent({
          tick: this.store.current_tick,
          type: "operator_action",
          severity: "INFO",
          packetId: p.id,
          action: "APPROVE",
          stateFrom: prev,
          stateTo: "ALLOWED",
        });
        return { ok: true, packetId: p.id, newState: "ALLOWED", reason: "approved" };
      }
      case "DROP": {
        if (p.state !== "HOLDING_INTERCEPT") {
          return { ok: false, reason: "invalid_state_for_action" };
        }
        const prev = p.state;
        this.transition(p, "DROPPED");
        this.store.dropped_packets += 1;
        this.store.held_packets -= 1;
        this.store.moveToTerminal(p);
        this.store.recordEvent({
          tick: this.store.current_tick,
          type: "operator_action",
          severity: "MEDIUM",
          packetId: p.id,
          action: "DROP",
          stateFrom: prev,
          stateTo: "DROPPED",
        });
        return { ok: true, packetId: p.id, newState: "DROPPED", reason: "dropped" };
      }
      case "ESCALATE": {
        if (p.state !== "HOLDING_INTERCEPT") {
          return { ok: false, reason: "invalid_state_for_action" };
        }
        const prev = p.state;
        this.transition(p, "ESCALATED");
        this.store.escalated_incidents += 1;
        this.store.held_packets -= 1;
        this.store.moveToTerminal(p);
        this.store.recordEvent({
          tick: this.store.current_tick,
          type: "incident_created",
          severity: "HIGH",
          packetId: p.id,
          action: "ESCALATE",
          stateFrom: prev,
          stateTo: "ESCALATED",
        });
        return { ok: true, packetId: p.id, newState: "ESCALATED", reason: "escalated" };
      }
      case "HOLD": {
        if (p.state === "HOLDING_INTERCEPT") {
          return { ok: true, packetId: p.id, newState: "HOLDING_INTERCEPT", reason: "already_held" };
        }
        return { ok: false, reason: "cannot_hold_non_held_packet" };
      }
    }
  }

  getMetrics(): MetricSnapshot {
    return this.store.getMetricSnapshot();
  }
}

function severityRank(s: DetectionResult["severity"]): SimulationEvent["severity"] {
  if (s === "CRITICAL" || s === "HIGH") return "HIGH";
  if (s === "SUSPICIOUS") return "MEDIUM";
  return "INFO";
}
