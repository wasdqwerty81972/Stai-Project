"use client";

import { Shield, Info } from "lucide-react";
import type { ProtectionStatus } from "@/lib/stai-protection-api";
import { AsyncState, formatTimestamp } from "./ProtectionPrimitives";

interface Props {
  status: ProtectionStatus | null;
  loading: boolean;
  error: string | null;
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border/50 py-2 last:border-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-right text-sm font-medium text-foreground">{value}</dd>
    </div>
  );
}

/** Render primitive key/value pairs from the free-form sensor_coverage map. */
function coverageRows(coverage: Record<string, unknown>): [string, string][] {
  return Object.entries(coverage)
    .filter(([, v]) => ["string", "number", "boolean"].includes(typeof v))
    .map(([k, v]) => [k.replaceAll("_", " "), String(v)]);
}

export function ProtectionSystemStatus({ status, loading, error }: Props) {
  if (loading && !status && !error) {
    return <AsyncState kind="loading" title="Loading system status…" />;
  }
  if (error) {
    return (
      <AsyncState
        kind="error"
        title="System status unavailable"
        detail={`The local protection service could not be reached: ${error}`}
      />
    );
  }
  if (!status) {
    return <AsyncState kind="empty" title="No system status reported" />;
  }

  const av = status.windows_security?.registered_av_provider;
  const defenderMode = status.windows_security?.defender_mode;
  const coverage = coverageRows(status.sensor_coverage ?? {});

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <section className="rounded-xl border border-border bg-card/40 p-5">
        <div className="flex items-center gap-2">
          <Shield className="size-4 text-cyan-300" aria-hidden="true" />
          <h3 className="text-sm font-semibold text-foreground">
            Driver & service health
          </h3>
        </div>
        <dl className="mt-3">
          <Row label="Overall state" value={status.state} />
          <Row label="Minifilter driver" value={status.driver_state} />
          <Row label="Protection service" value={status.service_state} />
          <Row label="Rule pack version" value={status.rules_version || "Unknown"} />
          <Row label="Last scan" value={formatTimestamp(status.last_scan)} />
        </dl>
        {status.last_error ? (
          <p
            role="alert"
            className="mt-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
          >
            {status.last_error}
          </p>
        ) : null}
      </section>

      <section className="rounded-xl border border-border bg-card/40 p-5">
        <div className="flex items-center gap-2">
          <Shield className="size-4 text-cyan-300" aria-hidden="true" />
          <h3 className="text-sm font-semibold text-foreground">Windows security</h3>
        </div>
        <dl className="mt-3">
          <Row
            label="Registered AV provider"
            value={av ?? "Not reported by OS"}
          />
          <Row
            label="Defender mode"
            value={defenderMode ?? "Not reported by OS"}
          />
        </dl>
        <p className="mt-3 flex items-start gap-2 text-[11px] text-muted-foreground">
          <Info className="mt-0.5 size-3.5 shrink-0 text-cyan-300" aria-hidden="true" />
          <span>
            These are read-only observations. STAI never changes Defender
            settings or services.
          </span>
        </p>
      </section>

      <section className="rounded-xl border border-border bg-card/40 p-5 md:col-span-2">
        <h3 className="text-sm font-semibold text-foreground">Sensor coverage</h3>
        {coverage.length > 0 ? (
          <dl className="mt-3 grid gap-x-6 sm:grid-cols-2">
            {coverage.map(([label, value]) => (
              <Row key={label} label={label} value={value} />
            ))}
          </dl>
        ) : (
          <p className="mt-2 text-xs text-muted-foreground">
            No evidence-backed sensor coverage reported by the service.
          </p>
        )}
      </section>
    </div>
  );
}
