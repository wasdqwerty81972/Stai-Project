import type { Packet, Protocol, Address } from "../models/packet";
import { SeededPRNG } from "./prng";

const PROTOCOLS: Protocol[] = [
  "TCP", "UDP", "ICMP", "DNS", "SMB", "RDP", "SSH", "HTTP", "HTTPS", "NETBIOS",
];

const SAFE_PAYLOADS = [
  "GET /health HTTP/1.1",
  "POST /login HTTP/1.1",
  "example.com",
  "echo",
  "GET /api/v1/status HTTP/1.1",
  "ssh-user-auth",
  "GET /index.html HTTP/1.1",
  "GET /metrics HTTP/1.1",
  "TLSv1.3 handshake",
  "SSH-2.0-connection",
];

export interface ScenarioPacketSpec {
  tick: number;
  protocol: Protocol;
  src: Address;
  dst: Address;
  kind: "SAFE" | "SUSPICIOUS";
  size: number;
  payload: string;
}

export interface Scenario {
  seed: number;
  maxTick: number;
  packetCount: number;
  packets: ScenarioPacketSpec[];
}

export function loadScenario(input: unknown): Scenario {
  const s = input as {
    seed: number;
    maxTick: number;
    packetCount: number;
    packets: ScenarioPacketSpec[];
  };
  return {
    seed: s.seed,
    maxTick: s.maxTick,
    packetCount: s.packetCount,
    packets: s.packets.map((p) => ({
      tick: p.tick,
      protocol: p.protocol,
      src: { ...p.src },
      dst: { ...p.dst },
      kind: p.kind,
      size: p.size,
      payload: p.payload,
    })),
  };
}

export function generateSafeScenario(
  rng: SeededPRNG,
  count: number,
  baseTick: number,
): ScenarioPacketSpec[] {
  const out: ScenarioPacketSpec[] = [];
  for (let i = 0; i < count; i++) {
    const proto = PROTOCOLS[rng.nextInt(PROTOCOLS.length)] as Protocol;
    const payload = SAFE_PAYLOADS[rng.nextInt(SAFE_PAYLOADS.length)];
    out.push({
      tick: baseTick + i,
      protocol: proto,
      src: { ip: "10.0.0." + (i + 2), hostId: "h" + String(i + 1).padStart(3, "0"), port: 1024 + rng.nextInt(60000) },
      dst: { ip: "10.0.0.10", hostId: "h00a", port: proto === "DNS" ? 53 : proto === "SSH" ? 22 : proto === "HTTPS" ? 443 : proto === "HTTP" ? 80 : 8080 },
      kind: "SAFE",
      size: 64 + rng.nextInt(1400),
      payload,
    });
  }
  return out;
}

export function materializePackets(spec: Scenario): Packet[] {
  return spec.packets.map((p, idx) => {
    const id = "pkt_" + String(idx + 1).padStart(4, "0");
    return {
      id,
      tick: p.tick,
      protocol: p.protocol,
      source: { ...p.src },
      destination: { ...p.dst },
      kind: p.kind,
      size: p.size,
      payload: p.payload,
      flags: { isRepeated: false, isPortScan: false },
      state: "CREATED",
    };
  });
}
