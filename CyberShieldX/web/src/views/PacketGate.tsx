import React, { useRef, useState, useEffect } from "react";
import type { SimulationController } from "../app/hooks";

export function PacketGate({ sim }: { sim: SimulationController }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>(0);
  const [time, setTime] = useState(0);

  const held = sim.held;
  const active = sim.packets;

  useEffect(() => {
    let frame = 0;
    const loop = () => {
      frame = requestAnimationFrame(() => {
        setTime((t) => t + (sim.running ? 1 : 0));
        animationRef.current = loop();
      });
    };
    animationRef.current = loop();
    return () => cancelAnimationFrame(animationRef.current);
  }, [sim.running]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d")!;
    const resize = () => {
      canvas.width = canvas.offsetWidth * window.devicePixelRatio;
      canvas.height = canvas.offsetHeight * window.devicePixelRatio;
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    };
    resize();
    window.addEventListener("resize", resize);
    return () => window.removeEventListener("resize", resize);
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d")!;
    const dpr = window.devicePixelRatio || 1;

    const draw = () => {
      const w = canvas.width / dpr;
      const h = canvas.height / dpr;
      ctx.clearRect(0, 0, w, h);

      const gateX = w / 2;

      const leftEdge = 80;
      const rightEdge = w - 80;

      ctx.strokeStyle = "rgba(51, 65, 85, 0.5)";
      ctx.setLineDash([4, 6]);
      ctx.beginPath();
      ctx.moveTo(leftEdge, h / 2);
      ctx.lineTo(gateX - 40, h / 2);
      ctx.moveTo(gateX + 40, h / 2);
      ctx.lineTo(rightEdge, h / 2);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.fillStyle = "#334155";
      ctx.fillRect(gateX - 2, 20, 4, h - 40);
      ctx.shadowColor = "#3b82f6";
      ctx.shadowBlur = 8;
      ctx.fillStyle = "#3b82f6";
      ctx.fillRect(gateX - 2, 0, 4, h);
      ctx.shadowBlur = 0;

      ctx.fillStyle = "#94a3b8";
      ctx.font = "11px monospace";
      ctx.textAlign = "center";
      ctx.fillText("INSPECTION GATE", gateX, 14);

      const speed = 0.6 + sim.speed * 0.2;

      const renderPacket = (p: typeof active[number], index: number) => {
        const laneY = 70 + (index % 6) * 26;
        let x: number;
        if (p.state === "CREATED" || p.state === "INSPECTING") {
          x = leftEdge + ((time * speed + (p.id.charCodeAt(3) * 7 % 120)) % (rightEdge - leftEdge - 80));
        } else if (p.state === "HOLDING_INTERCEPT") {
          x = gateX;
        } else if (p.state === "ALLOWED") {
          x = gateX + 40 + (time * speed * 1.5) % (rightEdge - gateX - 40);
        } else if (p.state === "DROPPED" || p.state === "ESCALATED") {
          x = gateX - 40 - (time * speed * 1.2) % (gateX - leftEdge - 40);
        } else {
          x = gateX;
        }

        const color =
          p.state === "DROPPED" || p.state === "ESCALATED"
            ? "#ef4444"
            : p.state === "HOLDING_INTERCEPT"
              ? "#f59e0b"
              : p.state === "ALLOWED"
                ? "#22c55e"
                : p.kind === "SUSPICIOUS"
                  ? "#f59e0b"
                  : "#22c55e";

        const alpha = p.state === "HOLDING_INTERCEPT" ? 1 : 0.9;
        ctx.globalAlpha = alpha;

        ctx.save();
        ctx.translate(x, laneY);
        ctx.fillStyle = color;
        ctx.shadowColor = color;
        ctx.shadowBlur = p.state === "HOLDING_INTERCEPT" ? 14 : 6;
        ctx.beginPath();
        ctx.moveTo(-10, 0);
        ctx.lineTo(10, -7);
        ctx.lineTo(10, 7);
        ctx.closePath();
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.globalAlpha = 1;
        ctx.fillStyle = "#cbd5e1";
        ctx.font = "9px monospace";
        ctx.textAlign = "left";
        ctx.fillText(p.protocol, 12, 2);
        ctx.restore();
      };

      active.forEach(renderPacket);

      if (held.length > 0) {
        ctx.fillStyle = "rgba(245, 158, 11, 0.12)";
        ctx.fillRect(gateX - 50, h / 2 - 18, 100, 16);
        ctx.strokeStyle = "#f59e0b";
        ctx.strokeRect(gateX - 50, h / 2 - 18, 100, 16);
        ctx.fillStyle = "#f59e0b";
        ctx.font = "11px monospace";
        ctx.textAlign = "center";
        ctx.fillText(held.length + " HELD", gateX, h / 2 - 6);
      }
    };

    draw();
    return () => {};
  }, [time, active, held, sim.speed, sim.running]);

  return (
    <div className="gate-column surface" aria-label="Packet inspection gate visualization">
      <canvas ref={canvasRef} className="flex-1 w-full h-[420px]" aria-hidden="true" />
      <div className="operator-actions">
        {held.length > 0 && (
          <>
            <button className="btn btn-success operator-btn" onClick={() => sim.approve(held[0].id)}>Approve</button>
            <button className="btn btn-danger operator-btn" onClick={() => sim.drop(held[0].id)}>Drop</button>
            <button className="btn btn-warning operator-btn" onClick={() => sim.escalate(held[0].id)}>Escalate</button>
          </>
        )}
        {held.length > 1 && (
          <button className="btn operator-btn" onClick={() => held.forEach((p) => sim.drop(p.id))}>Drop All</button>
        )}
      </div>
    </div>
  );
}
