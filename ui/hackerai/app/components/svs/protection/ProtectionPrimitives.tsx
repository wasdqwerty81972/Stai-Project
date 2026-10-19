"use client";

import type { ReactNode } from "react";
import { CircleAlert, Inbox, Loader2 } from "lucide-react";

/** Format an ISO timestamp for display; "Never" for null/empty, raw for unparseable. */
export function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

/** Short, readable form of a SHA-256 (first 10 + last 6). */
export function shortHash(sha256: string | null | undefined): string {
  if (!sha256) return "—";
  if (sha256.length <= 20) return sha256;
  return `${sha256.slice(0, 10)}…${sha256.slice(-6)}`;
}

type StatTone = "default" | "detect" | "block" | "quarantine";

const STAT_TONE: Record<StatTone, string> = {
  default: "text-foreground",
  detect: "text-cyan-200",
  block: "text-rose-300",
  quarantine: "text-amber-300",
};

/**
 * A single labelled metric. Exposed as an accessible group so a label and its
 * value stay bound together — used for the distinct detection / blocked /
 * quarantined counts that must never be conflated.
 */
export function StatTile({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: StatTone;
}) {
  return (
    <div
      role="group"
      aria-label={label}
      className="flex flex-col gap-1 rounded-lg border border-border bg-card/50 px-4 py-3"
    >
      <span className={`text-2xl font-semibold tabular-nums ${STAT_TONE[tone]}`}>
        {value}
      </span>
      <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      {hint ? (
        <span className="text-[11px] text-muted-foreground/80">{hint}</span>
      ) : null}
    </div>
  );
}

/**
 * Explicit loading / empty / error placeholder. Errors use role="alert" so the
 * real failure reason is announced; loading/empty use a polite status region.
 */
export function AsyncState({
  kind,
  title,
  detail,
}: {
  kind: "loading" | "empty" | "error";
  title: string;
  detail?: string | null;
}) {
  const Icon = kind === "loading" ? Loader2 : kind === "error" ? CircleAlert : Inbox;
  const iconClass =
    kind === "loading"
      ? "text-muted-foreground motion-safe:animate-spin"
      : kind === "error"
        ? "text-destructive"
        : "text-muted-foreground";
  return (
    <div
      role={kind === "error" ? "alert" : "status"}
      aria-live="polite"
      className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-card/30 px-6 py-10 text-center"
    >
      <Icon className={`size-5 ${iconClass}`} aria-hidden="true" />
      <p className="text-sm font-medium text-foreground">{title}</p>
      {detail ? (
        <p className="max-w-md text-xs text-muted-foreground">{detail}</p>
      ) : null}
    </div>
  );
}

type ActionKind = "blocked" | "quarantined" | "observed" | "other";

/** Classify a detection action into a distinct outcome (never conflated). */
export function classifyAction(action: string): ActionKind {
  const a = action.toLowerCase();
  if (a.includes("block") || a.includes("deny") || a.includes("denied"))
    return "blocked";
  if (a.includes("quarantine")) return "quarantined";
  if (a.includes("observe") || a.includes("allow") || a.includes("audit"))
    return "observed";
  return "other";
}

const ACTION_LABEL: Record<ActionKind, string> = {
  blocked: "Blocked",
  quarantined: "Quarantined",
  observed: "Observed",
  other: "Recorded",
};

const ACTION_CLASS: Record<ActionKind, string> = {
  blocked: "border-rose-500/40 bg-rose-500/10 text-rose-200",
  quarantined: "border-amber-500/40 bg-amber-500/10 text-amber-200",
  observed: "border-border bg-card text-muted-foreground",
  other: "border-border bg-card text-muted-foreground",
};

/** A small coloured badge for a detection's confirmed action/outcome. */
export function ActionBadge({ action }: { action: string }) {
  const kind = classifyAction(action);
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${ACTION_CLASS[kind]}`}
      title={action}
    >
      {ACTION_LABEL[kind]}
    </span>
  );
}
