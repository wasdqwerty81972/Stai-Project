"use client";

import { PanelLeft, Shield } from "lucide-react";

interface SvsWorkspaceHeaderProps {
  title: string;
  connection: "idle" | "connecting" | "connected" | "disconnected";
  running: boolean;
  onOpenNavigation: () => void;
}

const connectionStyles = {
  idle: {
    label: "Local-first workspace",
    compactLabel: "Local-first",
    dot: "",
  },
  connecting: {
    label: "Connecting to local agent",
    compactLabel: "Connecting...",
    dot: "bg-amber-400",
  },
  connected: {
    label: "Agent connected",
    compactLabel: "Live",
    dot: "bg-emerald-400",
  },
  disconnected: {
    label: "Agent disconnected",
    compactLabel: "Offline",
    dot: "bg-destructive",
  },
} as const;

export function SvsWorkspaceHeader({
  title,
  connection,
  running,
  onOpenNavigation,
}: SvsWorkspaceHeaderProps) {
  const status = connectionStyles[connection];

  return (
    <header className="relative flex min-h-[68px] shrink-0 items-center justify-between gap-3 border-b border-border/70 bg-background/95 px-3 backdrop-blur-sm sm:px-5">
      <span
        className="pointer-events-none absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-cyan-500/35 via-cyan-500/10 to-transparent"
        aria-hidden="true"
      />
      <div className="flex min-w-0 items-center gap-2.5">
        <button
          type="button"
          aria-label="Open navigation"
          onClick={onOpenNavigation}
          className="flex size-10 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring md:hidden"
        >
          <PanelLeft className="size-5" aria-hidden="true" />
        </button>
        <span
          className="hidden size-8 shrink-0 items-center justify-center rounded-lg border border-cyan-500/20 bg-cyan-500/5 text-cyan-600 sm:flex dark:text-cyan-300"
          aria-hidden="true"
        >
          <Shield className="size-4" />
        </span>
        <div className="min-w-0">
          <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            <span
              className="size-1 rounded-full bg-cyan-500"
              aria-hidden="true"
            />
            <span className="sm:hidden">SVS-Cyber</span>
            <span className="hidden sm:inline">
              SVS-Cyber / investigation workspace
            </span>
          </p>
          <h1 className="truncate text-sm font-semibold tracking-tight text-foreground sm:text-[15px]">
            {title || "SVS-Cyber"}
          </h1>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground sm:gap-3">
        {running && (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-card px-2 py-1 font-medium text-foreground sm:px-2.5">
            <span
              className="size-1.5 rounded-full bg-amber-400 motion-safe:animate-pulse"
              aria-hidden="true"
            />
            <span className="hidden sm:inline">Agent running</span>
            <span className="sm:hidden">Running</span>
          </span>
        )}
        <span
          role="status"
          aria-live="polite"
          className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 ${connection === "idle" ? "border-cyan-500/20 bg-cyan-500/5 text-cyan-700 dark:text-cyan-300" : "border-border bg-card"}`}
        >
          {connection === "idle" ? (
            <Shield className="size-3.5 shrink-0" aria-hidden="true" />
          ) : (
            <span
              className={`size-1.5 shrink-0 rounded-full ${status.dot}`}
              aria-hidden="true"
            />
          )}
          <span className="hidden sm:inline">{status.label}</span>
          <span className="sm:hidden" aria-hidden="true">
            {status.compactLabel}
          </span>
          <span className="sr-only sm:hidden">{status.label}</span>
        </span>
      </div>
    </header>
  );
}
