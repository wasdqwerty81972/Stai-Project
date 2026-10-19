import type { DetectionResult, Packet } from "../models/packet";

export interface RuleConfig {
  KNOWN_BAD_SOURCES: string[];
  THRESHOLD_FLAG: number;
  PORT_WEIGHTS: Record<number, number>;
  PORT_22_WEIGHT: number;
  PROTOCOL_ANOMALY_UDP443: number;
  KNOWN_BAD_SOURCE_WEIGHT: number;
  PAYLOAD_INDICATORS: Record<string, number>;
}

export const DEFAULT_CONFIG: RuleConfig = {
  KNOWN_BAD_SOURCES: ["h100", "h200", "h400", "h600"],
  THRESHOLD_FLAG: 40,
  PORT_WEIGHTS: { 445: 25, 139: 25, 135: 25, 3389: 25 },
  PORT_22_WEIGHT: 15,
  PROTOCOL_ANOMALY_UDP443: 20,
  KNOWN_BAD_SOURCE_WEIGHT: 30,
  PAYLOAD_INDICATORS: {
    "brute-force": 25,
    beacon: 10,
    "SMB negotiate": 5,
    "RDP connection": 5,
  },
};

export function clampScore(score: number): number {
  return Math.min(100, Math.max(0, score));
}

export function roundScore(score: number): number {
  const rounded = Math.round(score * 100) / 100;
  return Math.trunc(rounded * 100) / 100;
}

export function severityForScore(score: number): DetectionResult["severity"] {
  if (score >= 90) return "CRITICAL";
  if (score >= 75) return "HIGH";
  if (score >= 40) return "SUSPICIOUS";
  return "SAFE";
}

export function recommendedActionForScore(score: number): DetectionResult["recommendedAction"] {
  return score >= DEFAULT_CONFIG.THRESHOLD_FLAG ? "HOLD" : "ALLOW";
}

interface BurstInfo {
  srcHostId: string;
  dstPort: number;
  count: number;
}

export function computeBurstMap(packets: Packet[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const p of packets) {
    const key = p.source.hostId + "|" + String(p.destination.port);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

export function computePortScanMap(packets: Packet[]): Map<string, number> {
  const distinctPorts = new Map<string, Set<number>>();
  for (const p of packets) {
    const set = distinctPorts.get(p.source.hostId) ?? new Set<number>();
    set.add(p.destination.port);
    distinctPorts.set(p.source.hostId, set);
  }
  const out = new Map<string, number>();
  for (const [host, set] of distinctPorts) out.set(host, set.size);
  return out;
}

export function evaluatePacket(
  packet: Packet,
  config: RuleConfig = DEFAULT_CONFIG,
  burstCount: number = 0,
  distinctPortCount: number = 0,
): DetectionResult {
  const matched: DetectionResult["matchedRules"] = [];
  let sum = 0;

  const add = (ruleId: string, name: string, weight: number, reason: string) => {
    sum += weight;
    matched.push({ ruleId, name, weight, contribution: weight, reason });
  };

  const dstPort = packet.destination.port;
  if (Object.prototype.hasOwnProperty.call(config.PORT_WEIGHTS, dstPort)) {
    const w = config.PORT_WEIGHTS[dstPort]!;
    add("suspicious_destination_port", "Suspicious Destination Port", w, "Destination port " + dstPort + " is a known high-risk service port.");
  }
  if (dstPort === 22) {
    add("suspicious_destination_port_ssh", "Suspicious Destination Port (SSH)", config.PORT_22_WEIGHT, "Destination port 22 (SSH).");
  }

  if (packet.protocol === "UDP" && dstPort === 443) {
    add("protocol_anomaly", "Protocol Anomaly", config.PROTOCOL_ANOMALY_UDP443, "UDP directed at port 443 (normally TCP/TLS).");
  }

  if (config.KNOWN_BAD_SOURCES.includes(packet.source.hostId)) {
    add("known_bad_source", "Threat Indicator (Source)", config.KNOWN_BAD_SOURCE_WEIGHT, "Source host " + packet.source.hostId + " matches a known-bad indicator.");
  }

  const payloadLower = packet.payload.toLowerCase();
  let payloadMatched = false;
  for (const indicator of Object.keys(config.PAYLOAD_INDICATORS)) {
    if (payloadLower.includes(indicator.toLowerCase())) {
      const w = config.PAYLOAD_INDICATORS[indicator]!;
      add(
        "threat_indicator_payload",
        "Threat Indicator (Payload)",
        w,
        "Payload contains indicator \"" + indicator + "\".",
      );
      payloadMatched = true;
    }
  }
  void payloadMatched;

  if (burstCount >= 3) {
    add("connection_burst", "Connection Burst", 15, "Source " + packet.source.hostId + " made " + burstCount + " connections to the same destination port.");
  }

  if (distinctPortCount >= 4) {
    add("port_scan_pattern", "Port Scan Pattern", 20, "Source " + packet.source.hostId + " contacted " + distinctPortCount + " distinct destination ports.");
  }

  const raw = clampScore(sum);
  const score = roundScore(raw);
  const flagged = score >= config.THRESHOLD_FLAG;
  const severity = severityForScore(score);
  const recommendedAction = recommendedActionForScore(score);

  const reasons = matched.length
    ? matched.map((m) => m.name + " (+" + m.contribution + ")").join("; ") + "."
    : "No rules matched.";
  const explanation =
    "score=" +
    score +
    " (" +
    severity +
    "). " +
    reasons +
    " " +
    (flagged
      ? "Packet is flagged as suspicious and will be held for operator review."
      : "Packet is below the detection threshold and will be allowed.");

  return {
    packetId: packet.id,
    score,
    severity,
    flagged,
    matchedRules: matched,
    explanation,
    recommendedAction,
  };
}
