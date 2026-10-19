import type { Packet, MetricSnapshot } from "../models/packet";
import { EventBuffer, type SimulationEvent } from "./event-buffer";

export class PacketStore {
  private packets: Map<string, Packet> = new Map();
  readonly terminal: Map<string, Packet> = new Map();
  private eventSeq = 0;

  generated_packets = 0;
  inspected_packets = 0;
  allowed_packets = 0;
  dropped_packets = 0;
  held_packets = 0;
  escalated_incidents = 0;
  detection_events = 0;

  current_tick = 0;
  private inspectionLatencies: Map<string, number> = new Map();

  readonly events: EventBuffer;

  constructor(eventsCapacity: number = 300) {
    this.events = new EventBuffer(eventsCapacity);
  }

  makeEventId(): string {
    this.eventSeq += 1;
    return "evt_" + String(this.eventSeq).padStart(6, "0");
  }

  private addEvent(event: SimulationEvent): void {
    this.events.add(event);
  }

  addPacket(packet: Packet): void {
    const id = "pkt_" + String(this.packets.size + 1).padStart(4, "0");
    packet.id = id;
    packet.tick = packet.tick ?? this.current_tick;
    packet.state = "CREATED";
    this.packets.set(id, packet);
    this.generated_packets += 1;
    this.addEvent({
      id: this.makeEventId(),
      tick: packet.tick,
      type: "packet_created",
      severity: "INFO",
      packetId: id,
    });
  }

  getActivePackets(): Packet[] {
    return Array.from(this.packets.values()).filter((p) => p.state === "INSPECTING" || p.state === "HOLDING_INTERCEPT" || p.state === "CREATED");
  }

  getAllPackets(): Packet[] {
    return Array.from(this.packets.values());
  }

  getHeldPackets(): Packet[] {
    return this.getActivePackets().filter((p) => p.state === "HOLDING_INTERCEPT");
  }

  getPacket(id: string): Packet | undefined {
    return this.packets.get(id) ?? this.terminal.get(id);
  }

  recordEvent(event: Omit<SimulationEvent, "id"> & { id?: string }): SimulationEvent {
    const e: SimulationEvent = { id: event.id ?? this.makeEventId(), ...event } as SimulationEvent;
    this.addEvent(e);
    return e;
  }

  recordLatency(packetId: string, latency: number): void {
    this.inspectionLatencies.set(packetId, latency);
  }

  moveToTerminal(packet: Packet): void {
    this.packets.delete(packet.id);
    this.terminal.set(packet.id, packet);
  }

  getMetricSnapshot(): MetricSnapshot {
    const resolved = this.allowed_packets + this.dropped_packets;
    const elapsed = Math.max(1, this.current_tick);
    const latencies = Array.from(this.inspectionLatencies.values());
    const avgLatency = latencies.length === 0 ? 0 : Math.round((latencies.reduce((a, b) => a + b, 0) / latencies.length) * 10000) / 10000;
    const queueDepth = this.getActivePackets().filter((p) => p.state === "INSPECTING" || p.state === "HOLDING_INTERCEPT").length;
    return {
      generated_packets: this.generated_packets,
      inspected_packets: this.inspected_packets,
      allowed_packets: this.allowed_packets,
      dropped_packets: this.dropped_packets,
      held_packets: this.held_packets,
      escalated_incidents: this.escalated_incidents,
      detection_events: this.detection_events,
      resolved_packets: resolved,
      pass_percentage: resolved === 0 ? 0 : Math.round((this.allowed_packets / resolved) * 10000) / 100,
      simulation_throughput: Math.round((resolved / elapsed) * 10000) / 10000,
      simulated_inspection_latency: avgLatency,
      queue_depth: queueDepth,
      current_tick: this.current_tick,
    };
  }

  reset(): void {
    this.packets.clear();
    this.terminal.clear();
    this.events.clear();
    this.eventSeq = 0;
    this.generated_packets = 0;
    this.inspected_packets = 0;
    this.allowed_packets = 0;
    this.dropped_packets = 0;
    this.held_packets = 0;
    this.escalated_incidents = 0;
    this.detection_events = 0;
    this.current_tick = 0;
    this.inspectionLatencies.clear();
  }
}
