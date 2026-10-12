import type { PacketState } from "../models/packet";

export interface SimulationEvent {
  id: string;
  tick: number;
  type:
    | "packet_created"
    | "state_transition"
    | "detection_flagged"
    | "operator_action"
    | "incident_created";
  severity: "INFO" | "MEDIUM" | "HIGH";
  packetId: string;
  stateFrom?: PacketState;
  stateTo?: PacketState;
  action?: string;
  score?: number;
  explanation?: string;
}

export class EventBuffer {
  private capacity: number;
  private events: SimulationEvent[] = [];

  constructor(capacity: number = 300) {
    this.capacity = Math.max(1, capacity);
  }

  getCapacity(): number {
    return this.capacity;
  }

  get length(): number {
    return this.events.length;
  }

  add(event: SimulationEvent): void {
    this.events.push(event);
    if (this.events.length > this.capacity) {
      this.events = this.events.slice(this.events.length - this.capacity);
    }
  }

  all(): SimulationEvent[] {
    return this.events;
  }

  clear(): void {
    this.events = [];
  }

  search(query: string): SimulationEvent[] {
    if (!query) return this.events.slice();
    const q = query.toLowerCase();
    return this.events.filter((e) => e.type.toLowerCase().includes(q) || (e.packetId?.toLowerCase().includes(q) ?? false) || (e.explanation?.toLowerCase().includes(q) ?? false));
  }

  filterByType(type: SimulationEvent["type"]): SimulationEvent[] {
    return this.events.filter((e) => e.type === type);
  }
}
