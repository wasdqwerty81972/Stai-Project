export type Protocol =
  | "TCP" | "UDP" | "ICMP" | "DNS" | "SMB" | "RDP" | "SSH" | "HTTP" | "HTTPS" | "NETBIOS";

export type PacketKind = "SAFE" | "SUSPICIOUS";
export type PacketState =
  | "CREATED"
  | "INSPECTING"
  | "HOLDING_INTERCEPT"
  | "ALLOWED"
  | "DROPPED"
  | "ESCALATED";

export interface Address {
  ip: string;
  hostId: string;
  port: number;
}

export interface PacketFlags {
  isRepeated?: boolean;
  isPortScan?: boolean;
}

export interface Packet {
  id: string;
  tick: number;
  protocol: Protocol;
  source: Address;
  destination: Address;
  kind: PacketKind;
  size: number;
  payload: string;
  flags: PacketFlags;
  state: PacketState;
}

export interface DetectionResult {
  packetId: string;
  score: number;
  severity: "SAFE" | "SUSPICIOUS" | "HIGH" | "CRITICAL";
  flagged: boolean;
  matchedRules: Array<{
    ruleId: string;
    name: string;
    weight: number;
    contribution: number;
    reason: string;
  }>;
  explanation: string;
  recommendedAction: "ALLOW" | "HOLD" | "DROP";
}

export interface MetricSnapshot {
  generated_packets: number;
  inspected_packets: number;
  allowed_packets: number;
  dropped_packets: number;
  held_packets: number;
  escalated_incidents: number;
  detection_events: number;
  resolved_packets: number;
  pass_percentage: number;
  simulation_throughput: number;
  simulated_inspection_latency: number;
  queue_depth: number;
  current_tick: number;
}

export interface OperatorActionResult {
  ok: boolean;
  packetId?: string;
  newState?: PacketState;
  reason: string;
}

export type OperatorAction = "APPROVE" | "DROP" | "ESCALATE" | "HOLD";
