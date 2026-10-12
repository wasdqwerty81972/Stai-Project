"use client";

import {
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  ShieldQuestion,
  type LucideIcon,
} from "lucide-react";
import type { ProtectionStatus } from "@/lib/stai-protection-api";
import { StatTile, formatTimestamp } from "./ProtectionPrimitives";

interface Props {
  status: ProtectionStatus | null;
  loading: boolean;
  /** Transport/service error reaching the status endpoint (service unreachable). */
  error: string | null;
}

type Tone = "active" | "degraded" | "unavailable" | "unknown";

const TONE_STYLE: Record<
  Tone,
  { wrap: string; chip: string; icon: string; Icon: LucideIcon }
> = {
  active: {
    wrap: "border-emerald-500/40 bg-emerald-500/5",
    chip: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
    icon: "text-emerald-300",
    Icon: ShieldCheck,
  },
  degraded: {
    wrap: "border-amber-500/40 bg-amber-500/5",
    chip: "border-amber-500/40 bg-amber-500/10 text-amber-200",
    icon: "text-amber-300",
    Icon: ShieldAlert,
  },
  unavailable: {
    wrap: "border-destructive/50 bg-destructive/5",
    chip: "border-destructive/50 bg-destructive/10 text-destructive",
    icon: "text-destructive",
    Icon: ShieldOff,
  },
  unknown: {
    wrap: "border-border bg-card/40",
    chip: "border-border bg-card text-muted-foreground",
    icon: "text-muted-foreground",
    Icon: ShieldQuestion,
  },
};

function resolve(
  status: ProtectionStatus | null,
  loading: boolean,
  error: string | null,
): { tone: Tone; label: string; description: string } {
  if (error) {
    return {
      tone: "unavailable",
      label: "Unavailable",
      description: `The local protection service could not be reached: ${error}`,
    };
  }
  if (!status) {
    return loading
      ? {
          tone: "unknown",
          label: "Checking…",
          description: "Querying the local protection service.",
        }
      : {
          tone: "unknown",
          label: "Unknown",
          description: "No protection status is available yet.",
        };
  }
  const state = String(status.state).toLowerCase();
  if (state === "active") {
    return {
      tone: "active",
      label: "Active",
      description:
        "Level 1 file protection is enforcing the verified rule package.",
    };
  }
  if (state === "degraded") {
    return {
      tone: "degraded",
      label: "Degraded",
      description:
        status.last_error ||
        "Protection is running with reduced coverage; unresolved operations follow the pass-through policy.",
    };
  }
  if (state === "unavailable") {
    return {
      tone: "unavailable",
      label: "Unavailable",
      description:
        status.last_error ||
        "The protection driver or service is not healthy. SVS Cyber is not currently protecting this device.",
    };
  }
  return {
    tone: "unknown",
    label: status.state || "Unknown",
    description: status.last_error || "Reported an unrecognized protection state.",
  };
}

export function ProtectionStatusBanner({ status, loading, error }: Props) {
  const { tone, label, description } = resolve(status, loading, error);
  const style = TONE_STYLE[tone];
  const { Icon } = style;

  // Values shown as "—" when there is no live status, so an error/offline state
  // never displays a fabricated "0 threats" that could read as reassurance.
  const detected = status ? (status.counts.detected ?? 0) : "—";
  const blocked = status ? (status.counts.blocked ?? 0) : "—";
  const quarantined = status ? (status.counts.quarantined ?? 0) : "—";

  return (
    <section
      aria-label="Protection status"
      role="status"
      aria-live="polite"
      className={`rounded-xl border p-5 ${style.wrap}`}
    >
      <div className="flex items-start gap-4">
        <span
          className={`mt-0.5 flex size-11 shrink-0 items-center justify-center rounded-lg border border-border/60 bg-background/40 ${style.icon}`}
          aria-hidden="true"
        >
          <Icon className="size-6" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            SVS Cyber protection status
          </p>
          <h2 className="mt-0.5 text-2xl font-semibold tracking-tight text-foreground">
            {label}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{description}</p>

          <dl className="mt-4 flex flex-wrap gap-x-6 gap-y-2 text-xs">
            <div className="flex flex-col">
              <dt className="text-muted-foreground">Rule pack</dt>
              <dd className="font-medium text-foreground">
                {status?.rules_version || "Unknown"}
              </dd>
            </div>
            <div className="flex flex-col">
              <dt className="text-muted-foreground">Last scan</dt>
              <dd className="font-medium text-foreground">
                {formatTimestamp(status?.last_scan)}
              </dd>
            </div>
            <div className="flex flex-col">
              <dt className="text-muted-foreground">Driver</dt>
              <dd className="font-medium text-foreground">
                {status?.driver_state || "unknown"}
              </dd>
            </div>
            <div className="flex flex-col">
              <dt className="text-muted-foreground">Service</dt>
              <dd className="font-medium text-foreground">
                {status?.service_state || "unknown"}
              </dd>
            </div>
          </dl>
        </div>
      </div>

      <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <StatTile
          label="Detections"
          value={detected}
          tone="detect"
          hint="Recorded detections (all actions)"
        />
        <StatTile
          label="Confirmed blocked"
          value={blocked}
          tone="block"
          hint="Operations actually denied"
        />
        <StatTile
          label="Quarantined"
          value={quarantined}
          tone="quarantine"
          hint="Verified moves to quarantine"
        />
      </div>
    </section>
  );
}
