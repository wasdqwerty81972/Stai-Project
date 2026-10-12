import {
  ArrowRight,
  Bot,
  CircleCheck,
  Clock3,
  RefreshCw,
  ScanLine,
  Shield,
  ShieldAlert,
  TriangleAlert,
} from "lucide-react";
import type { DetectionRecord, ProtectionStatus } from "../protection-api";
import type { DashboardPage } from "./Navigation";
import { StatusPill } from "./StatusPill";

export function HomeView({
  status,
  statusError,
  statusLoading,
  scanError,
  threats,
  onNavigate,
  onRetry,
  onStartQuickScan,
  scanBusy,
}: {
  status: ProtectionStatus | null;
  statusError: string | null;
  statusLoading: boolean;
  scanError: string | null;
  threats: DetectionRecord[] | null;
  onNavigate: (page: DashboardPage) => void;
  onRetry: () => void;
  onStartQuickScan: () => void;
  scanBusy: boolean;
}) {
  const state = status?.state ?? "unavailable";
  const unavailable = !status || Boolean(statusError) || state === "unavailable";
  const headline = statusLoading && !status && !statusError
    ? "Checking device protection"
    : unavailable
      ? statusError ? "Protection service unavailable" : "Protection status is unavailable"
      : state === "degraded"
        ? "Protection needs attention"
        : "Protection service is active";
  const detail = statusLoading && !status && !statusError
    ? "Connecting to the local Windows protection service…"
    : statusError || status?.last_error || (state === "active"
      ? "The local service reports that its protection components are healthy."
      : state === "degraded"
        ? "Review system status to see which components need attention."
        : "Start the local protection service to check this device." );
  const StatusIcon = unavailable ? ShieldAlert : state === "degraded" ? TriangleAlert : CircleCheck;
  const blockedCount = status?.counts?.blocked ?? "—";
  const detectionCount = threats ? threats.length : "—";

  return (
    <div className="home-view">
      <header className="home-welcome">
        <div>
          <h1>Welcome to STAI</h1>
          <p>Your security tools and AI assistant, together in one place.</p>
        </div>
        {status && <StatusPill state={state} />}
      </header>

      {scanError && <div role="alert" className="inline-alert error-alert">{scanError}</div>}

      <section className={`home-status home-status-${unavailable ? "unavailable" : state}`} aria-live="polite">
        <span className="home-status-icon" aria-hidden="true">
          {statusLoading && !status && !statusError
            ? <RefreshCw className="spin" size={22} />
            : <StatusIcon size={23} />}
        </span>
        <div className="home-status-copy">
          <h2>{headline}</h2>
          <p>{detail}</p>
        </div>
        <button
          className="home-status-link"
          onClick={unavailable ? onRetry : () => onNavigate("System Status")}
          type="button"
        >
          {unavailable ? "Retry connection" : "System status"}
          {unavailable ? <RefreshCw size={14} aria-hidden="true" /> : <ArrowRight size={15} aria-hidden="true" />}
        </button>
      </section>

      <section className="home-modules" aria-label="Choose a STAI tool">
        <article className="home-module home-module-antivirus">
          <div className="home-module-top">
            <span className="home-module-icon" aria-hidden="true"><Shield size={23} /></span>
            <span className="home-module-label">DEVICE PROTECTION</span>
          </div>
          <h2>Antivirus</h2>
          <p>Scan files, review threats, and manage quarantined items from your device.</p>
          <div className="home-module-metrics" aria-label="Protection activity">
            <div><strong>{blockedCount}</strong><span>Threats blocked</span></div>
            <div><strong>{detectionCount}</strong><span>Recorded detections</span></div>
          </div>
          <div className="home-module-actions">
            <button className="button button-primary" onClick={() => onNavigate("Antivirus")} type="button">
              Open antivirus <ArrowRight size={15} aria-hidden="true" />
            </button>
            <button
              className="button button-secondary"
              disabled={unavailable || statusLoading || scanBusy}
              onClick={onStartQuickScan}
              type="button"
            >
              <ScanLine size={15} aria-hidden="true" />
              {scanBusy ? "Starting scan…" : "Quick Scan"}
            </button>
          </div>
        </article>

        <article className="home-module home-module-agent">
          <div className="home-module-top">
            <span className="home-module-icon agent-module-icon" aria-hidden="true"><Bot size={23} /></span>
            <span className="home-module-label">AI ASSISTANT</span>
          </div>
          <h2>AI Agent</h2>
          <p>Get a plain-language review of security detections and ask follow-up questions.</p>
          <div className="home-agent-context">
            <Clock3 size={16} aria-hidden="true" />
            <span>{threats ? `${threats.length} detection${threats.length === 1 ? "" : "s"} available to review` : "Detection activity is loading"}</span>
          </div>
          <button className="button button-secondary home-agent-button" onClick={() => onNavigate("AI Agent")} type="button">
            Open AI Agent <ArrowRight size={15} aria-hidden="true" />
          </button>
        </article>
      </section>

      <section className="home-shortcuts" aria-label="More security tools">
        <div className="home-shortcuts-heading">
          <h2>More security tools</h2>
          <p>Open a specific area of device protection.</p>
        </div>
        <div className="home-shortcut-list">
          <button onClick={() => onNavigate("Threat Activity")} type="button"><ShieldAlert size={17} /><span>Threat activity</span><ArrowRight size={14} /></button>
          <button onClick={() => onNavigate("System Status")} type="button"><CircleCheck size={17} /><span>System status</span><ArrowRight size={14} /></button>
          <button onClick={() => onNavigate("Scans")} type="button"><ScanLine size={17} /><span>Scan center</span><ArrowRight size={14} /></button>
        </div>
      </section>
    </div>
  );
}
