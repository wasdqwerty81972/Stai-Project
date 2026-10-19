"use client";

import { useCallback, useEffect, useState } from "react";
import {
  LayoutDashboard,
  Bot,
  Shield,
  ShieldAlert,
  ScanLine,
  Archive,
  Settings as SettingsIcon,
  Cpu,
  ArrowRight,
  Lock,
  type LucideIcon,
} from "lucide-react";
import {
  getProtectionStatus,
  listThreats,
  startScan as apiStartScan,
  getScan,
  cancelScan as apiCancelScan,
  type ProtectionStatus,
  type ThreatRecord,
  type ScanJob,
  type ScanScope,
} from "@/lib/stai-protection-api";
import { ProtectionStatusBanner } from "./protection/ProtectionStatusBanner";
import { ProtectionScans } from "./protection/ProtectionScans";
import { ProtectionThreatActivity } from "./protection/ProtectionThreatActivity";
import { ProtectionQuarantine } from "./protection/ProtectionQuarantine";
import { ProtectionAgent } from "./protection/ProtectionAgent";
import { ProtectionSystemStatus } from "./protection/ProtectionSystemStatus";
import { ProcessMonitorView } from "./protection/ProcessMonitorView";
import { formatTimestamp } from "./protection/ProtectionPrimitives";

type View =
  | "dashboard"
  | "agent"
  | "system"
  | "threats"
  | "scans"
  | "processes"
  | "quarantine"
  | "settings";

const NAV: { id: View; label: string; Icon: LucideIcon }[] = [
  { id: "dashboard", label: "Dashboard", Icon: LayoutDashboard },
  { id: "agent", label: "AI Agent", Icon: Bot },
  { id: "system", label: "System Status", Icon: Shield },
  { id: "threats", label: "Threat Activity", Icon: ShieldAlert },
  { id: "scans", label: "Scans", Icon: ScanLine },
  { id: "processes", label: "Processes", Icon: Cpu },
  { id: "quarantine", label: "Quarantine", Icon: Archive },
  { id: "settings", label: "Settings", Icon: SettingsIcon },
];

const STATUS_REFRESH_MS = 15_000;
const SCAN_POLL_MS = 1_500;

function isScanActive(job: ScanJob | null): boolean {
  return !!job && (job.state === "running" || job.state === "queued");
}

export function SvsProtectionDashboard() {
  const [view, setView] = useState<View>("dashboard");

  const [status, setStatus] = useState<ProtectionStatus | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);

  const [threats, setThreats] = useState<ThreatRecord[]>([]);
  const [threatsLoading, setThreatsLoading] = useState(true);
  const [threatsError, setThreatsError] = useState<string | null>(null);

  const [scanJob, setScanJob] = useState<ScanJob | null>(null);
  const [scanStarting, setScanStarting] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await getProtectionStatus());
      setStatusError(null);
    } catch (err) {
      setStatus(null);
      setStatusError(
        err instanceof Error ? err.message : "Protection status unavailable",
      );
    } finally {
      setStatusLoading(false);
    }
  }, []);

  const refreshThreats = useCallback(async () => {
    try {
      setThreats(await listThreats(50));
      setThreatsError(null);
    } catch (err) {
      setThreatsError(
        err instanceof Error ? err.message : "Threat activity unavailable",
      );
    } finally {
      setThreatsLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
    void refreshThreats();
    const timer = window.setInterval(() => void refreshStatus(), STATUS_REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [refreshStatus, refreshThreats]);

  // Poll an active scan job until it reaches a terminal state.
  useEffect(() => {
    if (!isScanActive(scanJob) || !scanJob) return;
    const jobId = scanJob.job_id;
    let cancelled = false;
    const timer = window.setInterval(async () => {
      try {
        const next = await getScan(jobId);
        if (!cancelled) setScanJob(next);
      } catch {
        // Stop polling and surface the last known state; a vanished job or
        // service error must not masquerade as continued progress.
        if (!cancelled) {
          window.clearInterval(timer);
          setScanError("Lost contact with the scan job.");
        }
      }
    }, SCAN_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [scanJob]);

  const handleStartScan = useCallback(
    async (scope: ScanScope) => {
      if (scanStarting || isScanActive(scanJob)) return;
      setScanStarting(true);
      setScanError(null);
      try {
        setScanJob(await apiStartScan(scope));
      } catch (err) {
        setScanError(err instanceof Error ? err.message : "Could not start scan");
      } finally {
        setScanStarting(false);
      }
    },
    [scanStarting, scanJob],
  );

  const handleCancelScan = useCallback(async () => {
    if (!scanJob) return;
    const jobId = scanJob.job_id;
    try {
      await apiCancelScan(jobId);
      setScanJob((prev) =>
        prev && prev.job_id === jobId ? { ...prev, state: "cancelled" } : prev,
      );
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Could not cancel scan");
    }
  }, [scanJob]);

  const escalations = threats.filter((t) => t.triage_enqueued).length;
  const recommendation = buildRecommendation(status, statusError, escalations);

  return (
    <div className="flex h-full min-h-0 w-full flex-col overflow-hidden bg-background text-foreground md:flex-row">
      {/* Persistent navigation */}
      <nav
        aria-label="Protection navigation"
        className="flex shrink-0 gap-1 overflow-x-auto border-b border-border/70 bg-card/30 p-2 md:w-56 md:flex-col md:overflow-y-auto md:border-b-0 md:border-r"
      >
        <div className="hidden items-center gap-2 px-2 py-3 md:flex">
          <span className="flex size-7 items-center justify-center rounded-lg border border-cyan-500/20 bg-cyan-500/5 text-cyan-300">
            <Shield className="size-4" aria-hidden="true" />
          </span>
          <div className="leading-tight">
            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
              STAI
            </p>
            <p className="text-sm font-semibold text-foreground">Protection</p>
          </div>
        </div>
        {NAV.map((item) => {
          const active = view === item.id;
          return (
            <button
              key={item.id}
              type="button"
              aria-current={active ? "page" : undefined}
              onClick={() => setView(item.id)}
              className={`inline-flex shrink-0 items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-ring ${
                active
                  ? "bg-cyan-500/10 text-cyan-100"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground"
              }`}
            >
              <item.Icon className="size-4 shrink-0" aria-hidden="true" />
              {item.label}
            </button>
          );
        })}
      </nav>

      {/* Main content */}
      <main className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-5xl space-y-5 px-4 py-6 sm:px-6">
          <header className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-foreground">
                {NAV.find((n) => n.id === view)?.label}
              </h1>
              <p className="text-xs text-muted-foreground">
                STAI local Windows protection
              </p>
            </div>
          </header>

          {view === "dashboard" ? (
            <>
              <ProtectionStatusBanner
                status={status}
                loading={statusLoading}
                error={statusError}
              />

              <section
                aria-label="Recommended action"
                className={`flex flex-wrap items-center justify-between gap-3 rounded-xl border p-4 ${recommendation.cls}`}
              >
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Recommended action
                  </p>
                  <p className="mt-0.5 text-sm font-medium text-foreground">
                    {recommendation.text}
                  </p>
                </div>
                {recommendation.target ? (
                  <button
                    type="button"
                    onClick={() => setView(recommendation.target!)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-3 py-1.5 text-sm font-medium text-foreground transition-colors hover:bg-accent focus-visible:outline-2 focus-visible:outline-ring"
                  >
                    {recommendation.cta}
                    <ArrowRight className="size-4" aria-hidden="true" />
                  </button>
                ) : null}
              </section>

              <ProtectionScans
                job={scanJob}
                starting={scanStarting}
                error={scanError}
                onStart={handleStartScan}
                onCancel={handleCancelScan}
                variant="compact"
              />

              <ProtectionThreatActivity
                threats={threats}
                status={status}
                loading={threatsLoading}
                error={threatsError}
                compact
                limit={5}
              />
            </>
          ) : null}

          {view === "agent" ? (
            <ProtectionAgent
              threats={threats}
              loading={threatsLoading}
              error={threatsError}
            />
          ) : null}

          {view === "system" ? (
            <ProtectionSystemStatus
              status={status}
              loading={statusLoading}
              error={statusError}
            />
          ) : null}

          {view === "threats" ? (
            <ProtectionThreatActivity
              threats={threats}
              status={status}
              loading={threatsLoading}
              error={threatsError}
            />
          ) : null}

          {view === "scans" ? (
            <ProtectionScans
              job={scanJob}
              starting={scanStarting}
              error={scanError}
              onStart={handleStartScan}
              onCancel={handleCancelScan}
            />
          ) : null}

          {view === "processes" ? <ProcessMonitorView /> : null}

          {view === "quarantine" ? <ProtectionQuarantine /> : null}

          {view === "settings" ? (
            <ProtectionSettingsView status={status} error={statusError} />
          ) : null}
        </div>
      </main>
    </div>
  );
}

function buildRecommendation(
  status: ProtectionStatus | null,
  statusError: string | null,
  escalations: number,
): { text: string; cta: string; target: View | null; cls: string } {
  if (statusError) {
    return {
      text: "Protection status is unreachable. STAI is not confirmed active on this device.",
      cta: "Open System Status",
      target: "system",
      cls: "border-destructive/40 bg-destructive/5",
    };
  }
  const state = status ? String(status.state).toLowerCase() : "";
  if (state === "unavailable") {
    return {
      text: "Protection is unavailable. Review driver, service, and rule health.",
      cta: "Open System Status",
      target: "system",
      cls: "border-destructive/40 bg-destructive/5",
    };
  }
  if (state === "degraded") {
    return {
      text: "Protection is degraded. Review driver, service, and rule health.",
      cta: "Open System Status",
      target: "system",
      cls: "border-amber-500/40 bg-amber-500/5",
    };
  }
  if (escalations > 0) {
    return {
      text: `${escalations} detection${escalations === 1 ? "" : "s"} awaiting AI triage.`,
      cta: "Open AI Agent",
      target: "agent",
      cls: "border-cyan-500/40 bg-cyan-500/5",
    };
  }
  if (state === "active") {
    return {
      text: "Protection is active. No action required.",
      cta: "Run a quick scan",
      target: "scans",
      cls: "border-border bg-card/40",
    };
  }
  return {
    text: "Waiting on the local protection service for current status.",
    cta: "Open System Status",
    target: "system",
    cls: "border-border bg-card/40",
  };
}

function ProtectionSettingsView({
  status,
  error,
}: {
  status: ProtectionStatus | null;
  error: string | null;
}) {
  return (
    <section
      aria-label="Protection settings"
      className="space-y-4 rounded-xl border border-border bg-card/40 p-5"
    >
      <div className="flex items-center gap-2">
        <SettingsIcon className="size-4 text-cyan-300" aria-hidden="true" />
        <h3 className="text-sm font-semibold text-foreground">
          Protection settings
        </h3>
      </div>

      <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
        <div className="flex items-center justify-between gap-3 border-b border-border/50 py-2">
          <dt className="text-xs text-muted-foreground">Current state</dt>
          <dd className="text-sm font-medium text-foreground">
            {error ? "unavailable" : status?.state || "unknown"}
          </dd>
        </div>
        <div className="flex items-center justify-between gap-3 border-b border-border/50 py-2">
          <dt className="text-xs text-muted-foreground">Rule pack version</dt>
          <dd className="text-sm font-medium text-foreground">
            {status?.rules_version || "unknown"}
          </dd>
        </div>
        <div className="flex items-center justify-between gap-3 border-b border-border/50 py-2">
          <dt className="text-xs text-muted-foreground">Last scan</dt>
          <dd className="text-sm font-medium text-foreground">
            {formatTimestamp(status?.last_scan)}
          </dd>
        </div>
        <div className="flex items-center justify-between gap-3 border-b border-border/50 py-2">
          <dt className="text-xs text-muted-foreground">AV provider</dt>
          <dd className="text-sm font-medium text-foreground">
            {status?.windows_security?.registered_av_provider ?? "Not reported by OS"}
          </dd>
        </div>
      </dl>

      <p className="flex items-start gap-2 rounded-lg border border-border bg-background/40 px-3 py-2 text-[11px] text-muted-foreground">
        <Lock className="mt-0.5 size-3.5 shrink-0 text-cyan-300" aria-hidden="true" />
        <span>
          Protection lifecycle — driver and service installation, rule-pack
          updates, and quarantine policy — is owned by the elevated local STAI
          installer and service. It cannot be changed from this page, and the
          hosted web app is never granted privileged protection controls.
        </span>
      </p>
    </section>
  );
}
