import { useEffect, useRef, useState, useCallback } from "react";
import { SimulationEngine } from "../simulation/engine";
import type { Packet, MetricSnapshot, OperatorAction } from "../models/packet";
import type { SimulationEvent } from "../state/event-buffer";
import { loadScenario } from "../simulation/scenarios";
import type { ScenarioPacketSpec } from "../simulation/scenarios";
import safeFixture from "../../fixtures/safe-traffic.json";
import suspiciousFixture from "../../fixtures/suspicious-traffic.json";

export type Mode = "beginner" | "advanced";
export type ScenarioName = "safe" | "suspicious" | "combined";

export interface SimulationController {
  mode: Mode;
  setMode: (m: Mode) => void;
  scenario: ScenarioName;
  setScenario: (s: ScenarioName) => void;
  tick: number;
  packets: Packet[];
  held: Packet[];
  metrics: MetricSnapshot;
  running: boolean;
  speed: number;
  start: () => void;
  pause: () => void;
  resume: () => void;
  reset: () => void;
  step: () => void;
  replay: () => void;
  setSpeed: (n: number) => void;
  approve: (id: string) => void;
  drop: (id: string) => void;
  escalate: (id: string) => void;
  activePacket: Packet | undefined;
  setActivePacket: (p: Packet | undefined) => void;
}

function normalizeSpec(p: any): ScenarioPacketSpec {
  return { tick: p.tick, protocol: p.protocol, src: p.src, dst: p.dst, kind: p.kind, size: p.size, payload: p.payload };
}

function specsFor(s: ScenarioName): ScenarioPacketSpec[] {
  if (s === "safe") return (safeFixture as any).packets.map(normalizeSpec);
  if (s === "suspicious") return (suspiciousFixture as any).packets.map(normalizeSpec);
  return [
    ...(safeFixture as any).packets,
    ...(suspiciousFixture as any).packets,
  ]
    .map(normalizeSpec)
    .sort((a, b) => a.tick - b.tick);
}

export function useSimulation(): SimulationController {
  const engineRef = useRef<SimulationEngine | null>(null);
  if (!engineRef.current) engineRef.current = new SimulationEngine(300);
  const engine = engineRef.current;

  const [mode, setMode] = useState<Mode>("beginner");
  const [scenario, setScenarioState] = useState<ScenarioName>("safe");
  const [tick, setTick] = useState(0);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [held, setHeld] = useState<Packet[]>([]);
  const [metrics, setMetrics] = useState<MetricSnapshot>(engine.getMetrics());
  const [events, setEvents] = useState<SimulationEvent[]>(engine.store.events.all());
  const [running, setRunning] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [activePacket, setActivePacket] = useState<Packet | undefined>();

  const snapshot = useCallback(() => {
    setTick(engine.store.current_tick);
    setPackets(engine.store.getAllPackets());
    setHeld(engine.store.getHeldPackets());
    setMetrics(engine.getMetrics());
    setEvents(engine.store.events.all());
  }, [engine]);

  const load = useCallback(() => {
    engine.reset();
    engine.loadScenario(specsFor(scenario));
    snapshot();
  }, [engine, scenario, snapshot]);

  useEffect(() => {
    load();
  }, []);

  const start = () => { engine.start(); setRunning(true); snapshot(); };
  const pause = () => { engine.pause(); setRunning(false); snapshot(); };
  const resume = () => { engine.resume(); setRunning(true); snapshot(); };
  const reset = () => { setRunning(false); load(); };
  const step = () => { engine.step(); snapshot(); };
  const replay = () => { engine.reset(); engine.loadScenario(specsFor(scenario)); engine.runUntilSteady(); setRunning(false); snapshot(); };
  const setSpeedVal = (n: number) => { engine.setSpeed(n); setSpeed(n); };

  const doAction = (action: OperatorAction, id: string) => {
    engine.performAction(action, id);
    snapshot();
  };

  const clearEvents = () => {
    engine.store.events.clear();
    setEvents([]);
  };

  return {
    mode,
    setMode: (m: Mode) => {
      setMode(m);
    },
    scenario,
    setScenario: (s: ScenarioName) => { setScenarioState(s); setTimeout(load, 0); },
    tick,
    packets,
    held,
    events,
    metrics,
    running,
    speed,
    start,
    pause,
    resume,
    reset,
    step,
    replay,
    setSpeed: setSpeedVal,
    approve: (id: string) => doAction("APPROVE", id),
    drop: (id: string) => doAction("DROP", id),
    escalate: (id: string) => doAction("ESCALATE", id),
    clearEvents,
    activePacket,
    setActivePacket,
  };
}
