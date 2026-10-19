import {
  Activity,
  ArrowRight,
  Bot,
  Check,
  Clock3,
  FileSearch,
  HardDrive,
  LockKeyhole,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import type {
  DetectionRecord,
  ProtectionStatus,
  ScanJob,
} from "../protection-api";
import { isDemoRuleVersion, summarizeProtection } from "../protection-status";
import { EmptyState } from "./EmptyState";
import { DetectionRow } from "./DetectionRow";
import { MetricCard } from "./MetricCard";
import { PageHeading } from "./PageHeading";
import type { DashboardPage } from "./Navigation";
import { StatusPill } from "./StatusPill";

const count = (value: number | null | undefined) => value ?? "—";

function RulePackageValue({ status }: { status: ProtectionStatus | null }) {
  const version = status?.rules_version;
  if (!version || version === "unknown") return <>Not reported</>;
  if (status?.rules_trusted === false) return <>{version} · not verified</>;
  if (isDemoRuleVersion(version)) return <>{version} · demo only</>;
  return <>{version}</>;
}

function formatTime(value: string | null | undefined) {
  if (!value) return "No completed scan recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function ScanAction({
  icon: Icon,
  title,
  detail,
  onClick,
  disabled,
  busy,
}: {
  icon: LucideIcon;
  title: string;
  detail: string;
  onClick: () => void;
  disabled: boolean;
  busy: boolean;
}) {
  return (
    <button
      aria-label={title}
      className="scan-action-card"
      disabled={disabled || busy}
      onClick={onClick}
      type="button"
    >
      <span className="scan-action-icon" aria-hidden="true">
        {busy ? <RefreshCw size={20} className="spin" /> : <Icon size={20} />}
      </span>
      <span className="scan-action-copy">
        <strong>{busy ? "Starting scan…" : title}</strong>
        <span>{detail}</span>
      </span>
      <ArrowRight size={17} aria-hidden="true" className="scan-action-arrow" />
    </button>
  );
}

export function ProtectionOverview({
  status,
  statusError,
  threats,
  threatsError,
  scan,
  scanError,
  scanBusy,
  onStartScan,
  onNavigate,
  onOpenDetection,
  onRetry,
}: {
  status: ProtectionStatus | null;
  statusError: string | null;
  threats: DetectionRecord[] | null;
  threatsError: string | null;
  scan: ScanJob | null;
  scanError: string | null;
  scanBusy: "quick" | "system" | null;
  onStartScan: (scope: "quick" | "system") => void;
  onNavigate: (page: DashboardPage) => void;
  onOpenDetection: (detection: DetectionRecord) => void;
  onRetry: () => void;
}) {
  const state = status?.state ?? "unavailable";
  const unavailable = Boolean(statusError) || !status || state === "unavailable";
  const verdict = summarizeProtection(status, statusError);
  const filterDriverDisconnected =
    !statusError &&
    state === "degraded" &&
    status?.service_state === "running" &&
    status?.driver_state === "stopped";
  const detail = statusError || (filterDriverDisconnected
    ? "The protection service is running, but the Windows file filter driver is not connected. Real-time protection is unavailable."
    : status?.last_error) || verdict.detail;
  // Counts and queue depth are only evidence when the service reported a status.
  const evidenceAvailable = Boolean(status) && state !== "unavailable" && !statusError;
  const counts = evidenceAvailable ? status?.counts : null;
  const escalatedCount = evidenceAvailable && threats
    ? threats.filter((threat) => threat.triage_enqueued).length
    : undefined;
  const canScan = !unavailable;
  // A success banner requires a connected kernel filter AND real rule coverage.
  const bannerTone = unavailable
    ? "unavailable"
    : verdict.verifiedProtection
      ? "active"
      : "degraded";

  return (
    <>
      <PageHeading
        eyebrow="DEVICE OVERVIEW"
        title="Security at a glance"
        description="Local protection status and recent activity for this device."
        action={status ? <StatusPill state={state} /> : undefined}
      />

      <section className={`protection-banner banner-${bannerTone}`} aria-labelledby="protection-state-title">
        <div className="banner-emblem" aria-hidden="true">
          {unavailable ? <ShieldAlert size={26} /> : verdict.verifiedProtection ? <ShieldCheck size={26} /> : <Activity size={26} />}
        </div>
        <div className="banner-copy">
          <div className="banner-kicker">LOCAL PROTECTION</div>
          <h2 id="protection-state-title">{verdict.title}</h2>
          <p>{detail}</p>
        </div>
        {unavailable && (
          <button className="button button-secondary banner-retry" onClick={onRetry} type="button">
            <RefreshCw size={15} aria-hidden="true" /> Retry connection
          </button>
        )}
        {verdict.verifiedProtection && (
          <div className="banner-confirmed"><Check size={15} aria-hidden="true" /> Service confirmed</div>
        )}
      </section>

      {verdict.limits.length > 0 && (
        <div className="inline-alert coverage-gap coverage-limits" role="status">
          <TriangleAlert size={16} aria-hidden="true" />
          <div>
            <strong>Protection coverage is limited</strong>
            <ul>
              {verdict.limits.map((limit) => <li key={limit}>{limit}</li>)}
            </ul>
            <button className="text-button" onClick={() => onNavigate("Driver Diagnostics")} type="button">
              Open driver diagnostics <ArrowRight size={14} aria-hidden="true" />
            </button>
          </div>
        </div>
      )}

      {scanError && <div role="alert" className="inline-alert error-alert">{scanError}</div>}

      <section className="section-block" aria-label="Protection totals">
        <div className="section-heading">
          <div>
            <h2>Protection totals</h2>
            <p>Verified outcomes recorded by the local service</p>
          </div>
          <span className="evidence-label"><LockKeyhole size={13} aria-hidden="true" /> Evidence backed</span>
        </div>
        {!status?.last_scan && !scan && (
          <p className="panel-description" role="status">
            No completed scan is recorded yet. These totals count outcomes saved by the protection service; zero does not mean the device has been scanned or found clean.
          </p>
        )}
        <div className="metric-grid">
          <MetricCard
            label="Detected"
            value={count(counts?.detected)}
            detail="Recorded detections"
            icon={<FileSearch size={17} />}
            tone="blue"
          />
          <MetricCard
            label="Blocked"
            value={count(counts?.blocked)}
            detail="Confirmed denied operations"
            icon={<ShieldAlert size={17} />}
            tone="amber"
          />
          <MetricCard
            label="Quarantined"
            value={count(counts?.quarantined)}
            detail="Verified moves to quarantine"
            icon={<LockKeyhole size={17} />}
            tone="green"
          />
          <MetricCard
            label="AI review queue"
            value={escalatedCount ?? "—"}
            detail={escalatedCount === undefined ? "Threat activity not loaded" : "Queued for AI review"}
            icon={<Bot size={17} />}
            tone="blue"
          />
        </div>
      </section>

      <div className="overview-columns">
        <section className="panel scan-panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">ON-DEMAND SCANS</div>
              <h2>Check your device</h2>
            </div>
            <span className="panel-icon"><FileSearch size={18} aria-hidden="true" /></span>
          </div>
          <p className="panel-description">Choose a local scan scope. Progress and any access errors are saved by the service.</p>
          <div className="scan-actions">
            <ScanAction
              icon={Clock3}
              title="Quick Scan"
              detail="Common user and startup locations"
              onClick={() => onStartScan("quick")}
              disabled={!canScan || Boolean(scan && (scan.state === "queued" || scan.state === "running"))}
              busy={scanBusy === "quick"}
            />
            <ScanAction
              icon={HardDrive}
              title="System Scan"
              detail="Accessible fixed local volumes"
              onClick={() => onStartScan("system")}
              disabled={!canScan || Boolean(scan && (scan.state === "queued" || scan.state === "running"))}
              busy={scanBusy === "system"}
            />
          </div>
          {scan && (
            <div className={`scan-status-row scan-${scan.state}`}>
              <span className="scan-state-dot" aria-hidden="true" />
              <div>
                <strong>{scan.scope === "quick" ? "Quick scan" : "System scan"} · {scan.state}</strong>
                <span>{scan.files_scanned} of {scan.files_total ?? "—"} files scanned</span>
              </div>
              <button className="text-button" onClick={() => onNavigate("Scans")} type="button">
                Details <ArrowRight size={14} aria-hidden="true" />
              </button>
            </div>
          )}
          <button className="quiet-link" onClick={() => onNavigate("Scans")} type="button">
            Open scan history <ArrowRight size={14} aria-hidden="true" />
          </button>
        </section>

        <section className="panel health-panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">ENGINE HEALTH</div>
              <h2>System status</h2>
            </div>
            <span className="panel-icon"><Activity size={18} aria-hidden="true" /></span>
          </div>
          <div className="health-list">
            <div><span>Filter driver</span><strong>{status?.driver_state ?? "Not reported"}</strong></div>
            <div><span>Protection service</span><strong>{status?.service_state ?? "Not reported"}</strong></div>
            <div><span>Rule package</span><strong><RulePackageValue status={status} /></strong></div>
            <div><span>Network telemetry</span><strong>{status?.network_telemetry?.state?.replaceAll("_", " ") ?? "Not reported"}</strong></div>
            <div><span>Registered antivirus</span><strong>{status?.windows_security?.registered_av_provider ?? "Not reported"}</strong></div>
          </div>
          <button className="quiet-link" onClick={() => onNavigate("System Status")} type="button">
            View system details <ArrowRight size={14} aria-hidden="true" />
          </button>
        </section>
      </div>

      <section className="panel recent-panel">
        <div className="panel-heading panel-heading-wide">
          <div>
            <div className="eyebrow">RECENT ACTIVITY</div>
            <h2>Threat activity</h2>
          </div>
          <button className="text-button" onClick={() => onNavigate("Threat Activity")} type="button">
            View all <ArrowRight size={14} aria-hidden="true" />
          </button>
        </div>
        {threatsError ? (
          <div role="alert" className="inline-alert error-alert">{threatsError}</div>
        ) : threats === null ? (
          <div className="loading-row"><span className="spinner" /> Loading activity…</div>
        ) : threats.length === 0 ? (
          <EmptyState title="No detections recorded" description="The local service has not recorded any detections yet." />
        ) : (
          <div className="detection-list">
            {threats.slice(0, 3).map((detection) => (
              <DetectionRow key={detection.detection_id} detection={detection} onOpen={onOpenDetection} />
            ))}
          </div>
        )}
        <div className="panel-footnote">
          <Clock3 size={14} aria-hidden="true" /> Last completed scan: <time dateTime={status?.last_scan ?? undefined}>{formatTime(status?.last_scan)}</time>
        </div>
      </section>
    </>
  );
}
