"use client";

import { ShieldAlert, Bot } from "lucide-react";
import type { ProtectionStatus, ThreatRecord } from "@/lib/stai-protection-api";
import {
  ActionBadge,
  AsyncState,
  StatTile,
  formatTimestamp,
  shortHash,
} from "./ProtectionPrimitives";

interface Props {
  threats: ThreatRecord[];
  status: ProtectionStatus | null;
  loading: boolean;
  error: string | null;
  /** Dashboard preview: hide headline totals (shown on the banner) and cap rows. */
  compact?: boolean;
  limit?: number;
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: "text-rose-300",
  high: "text-rose-200",
  medium: "text-amber-200",
  low: "text-muted-foreground",
};

export function ProtectionThreatActivity({
  threats,
  status,
  loading,
  error,
  compact = false,
  limit,
}: Props) {
  const rows = typeof limit === "number" ? threats.slice(0, limit) : threats;

  return (
    <section
      aria-label="Threat activity"
      className="rounded-xl border border-border bg-card/40 p-5"
    >
      <div className="flex items-center gap-2">
        <ShieldAlert className="size-4 text-rose-300" aria-hidden="true" />
        <h3 className="text-sm font-semibold text-foreground">Threat activity</h3>
      </div>

      {!compact ? (
        <>
          <p className="mt-1 text-xs text-muted-foreground">
            Detection, confirmed block, quarantine, and agent escalation are
            tracked distinctly. Totals below reflect only confirmed outcomes.
          </p>
          <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatTile
              label="Detections"
              value={status ? (status.counts.detected ?? 0) : "—"}
              tone="detect"
            />
            <StatTile
              label="Confirmed blocked"
              value={status ? (status.counts.blocked ?? 0) : "—"}
              tone="block"
            />
            <StatTile
              label="Quarantined"
              value={status ? (status.counts.quarantined ?? 0) : "—"}
              tone="quarantine"
            />
            <StatTile
              label="Escalated to AI"
              value={threats.filter((t) => t.triage_enqueued).length}
            />
          </div>
        </>
      ) : null}

      <div className="mt-4">
        {loading ? (
          <AsyncState kind="loading" title="Loading detections…" />
        ) : error ? (
          <AsyncState
            kind="error"
            title="Threat activity unavailable"
            detail={error}
          />
        ) : rows.length === 0 ? (
          <AsyncState
            kind="empty"
            title="No detections recorded"
            detail="Detections appear here once the protection service records on-access or scan matches."
          />
        ) : (
          <ul className="divide-y divide-border/60 overflow-hidden rounded-lg border border-border/60">
            {rows.map((threat) => (
              <li key={threat.detection_id} className="bg-background/40 px-3 py-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <ActionBadge action={threat.action} />
                    <span
                      className={`text-xs font-semibold uppercase ${SEVERITY_CLASS[threat.severity?.toLowerCase()] ?? "text-muted-foreground"}`}
                    >
                      {threat.severity || "unknown"}
                    </span>
                    <span className="text-sm font-medium text-foreground">
                      {threat.rule_id}
                    </span>
                    <span className="text-[11px] text-muted-foreground">
                      v{threat.rule_version}
                    </span>
                  </div>
                  <time
                    dateTime={threat.created_at}
                    className="text-[11px] text-muted-foreground"
                  >
                    {formatTimestamp(threat.created_at)}
                  </time>
                </div>
                <p className="mt-1 break-all text-xs text-muted-foreground">
                  {threat.file_path || threat.file_type || "path withheld"}
                </p>
                <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                  <span>sha256 {shortHash(threat.sha256)}</span>
                  <span>confidence {threat.confidence}</span>
                  {threat.triage_enqueued ? (
                    <span className="inline-flex items-center gap-1 text-cyan-300">
                      <Bot className="size-3" aria-hidden="true" />
                      Escalated to AI triage
                    </span>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
