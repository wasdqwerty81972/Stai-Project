import React, { useEffect } from "react";
import { useSimulation, type SimulationController } from "./hooks";
import { MetricsPanel } from "../views/MetricsPanel";
import { EventLog } from "../views/EventLog";
import { PacketGate } from "../views/PacketGate";
import { ThreatPanel } from "../views/ThreatPanel";
import { BeginnerMode } from "./BeginnerMode";
import { AdvancedMode } from "./AdvancedMode";

export default function App() {
  const sim = useSimulation();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = document.activeElement?.tagName;
      if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
      if (document.activeElement?.hasAttribute("contenteditable")) return;
      if (e.code === "Space") { e.preventDefault(); sim.running ? sim.pause() : sim.start(); }
      if (e.code === "ArrowRight") { e.preventDefault(); sim.step(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [sim]);

  return (
    <div className="layout">
      <header className="header">
        <div className="flex justify-between items-center flex-wrap gap-sm">
          <div>
            <h1 className="text-xl font-bold"><span className="text-accent">CYBER</span> SHIELD <span className="text-accent">X</span></h1>
            <div className="text-sm text-muted">Offline Simulation Training Console — Tick {sim.tick} · Mode: {sim.mode} · Scenario: {sim.scenario}</div>
          </div>
          <div className="flex gap-sm items-center">
            <button className="btn" onClick={() => sim.setMode(sim.mode === "beginner" ? "advanced" : "beginner")}>
              Switch to {sim.mode === "beginner" ? "Advanced" : "Beginner"}
            </button>
            <button className="btn" onClick={sim.replay}>Replay</button>
            <button className="btn" onClick={sim.reset}>Reset</button>
            <label className="speed-control">
              Speed
              <input type="range" min={1} max={8} value={sim.speed} onChange={(e) => sim.setSpeed(Number(e.target.value))} aria-label="Simulation speed" />
            </label>
          </div>
        </div>
      </header>

      <aside className="sidebar surface p-3 panel">
        <MetricsPanel sim={sim} />
        <div className="controls-row">
          {sim.running ? (
            <button className="btn" onClick={sim.pause}>Pause</button>
          ) : (
            <button className="btn btn-primary" onClick={sim.start}>Start</button>
          )}
          <button className="btn" onClick={sim.step} disabled={sim.running}>Step</button>
        </div>
        <div className="panel">
          <label className="text-xs text-muted">Scenario</label>
          <select onChange={(e) => sim.setScenario(e.target.value as any)} value={sim.scenario} className="surface" style={{background:"var(--surface-2)"}}>
            <option value="safe">Safe Traffic</option>
            <option value="suspicious">Suspicious Traffic</option>
            <option value="combined">Combined</option>
          </select>
        </div>
        <label className="toggle-switch">
          <input type="checkbox" checked={sim.metrics.current_tick > 0} readOnly />
          <span className="toggle-slider"></span>
          <span className="text-sm text-muted">Events active</span>
        </label>
      </aside>

      <main className="main-content panel">
        <PacketGate sim={sim} />
        <ThreatPanel sim={sim} />
      </main>

      <footer className="surface p-3 panel">
        <EventLog sim={sim} />
      </footer>

      {sim.mode === "beginner" ? <BeginnerMode sim={sim} /> : <AdvancedMode sim={sim} />}
    </div>
  );
}
