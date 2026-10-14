import { AlertCircle, CircleHelp, Cpu, HardDriveDownload, Network, ShieldCheck } from "lucide-react";
import type { ProtectionStatus } from "../protection-api";
import { isDemoRuleVersion, summarizeProtection } from "../protection-status";
import { PageHeading } from "./PageHeading";
import { StatusPill } from "./StatusPill";

/**
 * Driver and capability diagnostics.
 *
 * Every row is either a field the protection service actually reported or an
 * explicit "not reported" row. Nothing here is inferred from a default: a
 * missing field must read as unknown, never as healthy.
 */

type RowTone = "healthy" | "attention" | "unknown";

function DiagnosticRow({
  label,
  value,
  tone,
  detail,
}: {
  label: string;
  value: string;
  tone: RowTone;
  detail: string;
}) {
  return (
    <div className="diagnostic-row">
      <div className="diagnostic-row-copy">
        <strong>{label}</strong>
        <span>{detail}</span>
      </div>
      <span className={`health-value ${tone}`}>
        {tone === "healthy" ? <ShieldCheck size={14} aria-hidden="true" />
          : tone === "attention" ? <AlertCircle size={14} aria-hidden="true" />
          : <CircleHelp size={14} aria-hidden="true" />}
        {value}
      </span>
    </div>
  );
}

function loadState(status: ProtectionStatus): { value: string; tone: RowTone; detail: string } {
  switch (status.driver_state) {
    case "running":
      return {
        value: "Connected",
        tone: "healthy",
        detail: "The service holds an open communication port to the Windows minifilter driver.",
      };
    case "stopped":
      return {
        value: "Not connected",
        tone: "attention",
        detail: "The minifilter communication port is not open. File operations are not inspected or blocked in the kernel.",
      };
    case "error":
      return {
        value: "Error",
        tone: "attention",
        detail: "The service reported a driver error. Kernel-level blocking is not in effect.",
      };
    default:
      return {
        value: status.driver_state ? status.driver_state.replaceAll("_", " ") : "Not reported",
        tone: "unknown",
        detail: "The service did not report a driver load state, so kernel protection cannot be confirmed.",
      };
  }
}

function rulePackageRow(status: ProtectionStatus): { value: string; tone: RowTone; detail: string } {
  if (status.rules_trusted === false) {
    return {
      value: "Not verified",
      tone: "attention",
      detail: "The service could not validate a signed rule package, so no rule-based detection is in effect.",
    };
  }
  if (!status.rules_version || status.rules_version === "unknown") {
    return {
      value: "Not reported",
      tone: "unknown",
      detail: "The service did not report a rule package version.",
    };
  }
  if (isDemoRuleVersion(status.rules_version)) {
    return {
      value: `${status.rules_version} · demo only`,
      tone: "attention",
      detail: "This is the EICAR demonstration package. It matches the EICAR test file only and provides no real malware coverage.",
    };
  }
  const total = status.rule_count;
  return {
    value: total == null ? status.rules_version : `${status.rules_version} · ${total} rules`,
    tone: "healthy",
    detail: status.sha256_rule_count == null && status.yara_rule_count == null
      ? "A signed rule package is loaded and verified by the service."
      : `Verified signed package: ${status.sha256_rule_count ?? 0} hash rules and ${status.yara_rule_count ?? 0} YARA rules.`,
  };
}

function networkRow(status: ProtectionStatus): { value: string; tone: RowTone; detail: string } {
  const telemetry = status.network_telemetry;
  if (!telemetry || !telemetry.state) {
    return {
      value: "Not reported",
      tone: "unknown",
      detail: "The service did not report network telemetry status.",
    };
  }
  if (telemetry.state === "running") {
    return { value: "Running", tone: "healthy", detail: "The service reports active network telemetry." };
  }
  if (telemetry.state === "not_configured") {
    return {
      value: "Not configured",
      tone: "attention",
      detail: "This build of the protection service runs without a network filter. Connections shown under Network Activity come from user-mode polling and are not filtered or blocked.",
    };
  }
  return {
    value: telemetry.state.replaceAll("_", " "),
    tone: "attention",
    detail: telemetry.startup_error || telemetry.error || "The service reported that network telemetry is not active.",
  };
}

export function DriverDiagnostics({
  status,
  error,
}: {
  status: ProtectionStatus | null;
  error: string | null;
}) {
  const verdict = summarizeProtection(status, error);
  const capabilities = status?.sensors?.capabilities ?? [];
  const coverage = status?.sensor_coverage ? Object.entries(status.sensor_coverage) : [];

  return (
    <>
      <PageHeading
        eyebrow="KERNEL COMPONENTS"
        title="Driver diagnostics"
        description="Installed driver state, rule package trust, and reported capabilities. Fields the service does not report are shown as not reported."
        action={status ? <StatusPill state={status.state} /> : undefined}
      />

      {error && <div role="alert" className="inline-alert error-alert">{error}</div>}

      {!status ? (
        <section className="panel">
          <div className="loading-row" role="status">
            <span className="spinner" /> Waiting for the local protection service…
          </div>
        </section>
      ) : (
        <>
          <section className={`inline-alert ${verdict.verifiedProtection ? "success-alert" : "coverage-gap"}`} role="status">
            <div>
              <strong>{verdict.title}</strong>
              <p className="diagnostic-verdict-detail">{verdict.detail}</p>
            </div>
          </section>

          <section className="panel health-detail-panel" aria-label="Driver state">
            <div className="panel-heading">
              <div><div className="eyebrow">MINIFILTER DRIVER</div><h2>Installed driver</h2></div>
              <span className="panel-icon"><HardDriveDownload size={18} aria-hidden="true" /></span>
            </div>
            <div className="diagnostic-list">
              <DiagnosticRow label="Load state" {...loadState(status)} />
              <DiagnosticRow
                label="Driver version"
                value="Not reported"
                tone="unknown"
                detail="The protection service does not report an installed driver version yet."
              />
              <DiagnosticRow
                label="Signing state"
                value="Not reported"
                tone="unknown"
                detail="The protection service does not report the driver's Authenticode signing state yet."
              />
              <DiagnosticRow
                label="OS compatibility"
                value="Not reported"
                tone="unknown"
                detail="The protection service does not report a supported Windows build range for the installed driver yet."
              />
              <DiagnosticRow
                label="Last error"
                value={status.last_error ? "Reported" : "None reported"}
                tone={status.last_error ? "attention" : "unknown"}
                detail={status.last_error || "The service did not report a driver error. This is not a confirmation that the driver loaded."}
              />
              <DiagnosticRow
                label="Error code"
                value="Not reported"
                tone="unknown"
                detail="The protection service reports error text only, without a Windows status or NTSTATUS code."
              />
            </div>
            <p className="helper-note">
              Driver version, signing state, compatibility, and numeric error codes are not part of the service status response. They are shown as not reported rather than assumed.
            </p>
          </section>

          <section className="panel health-detail-panel" aria-label="Protection capabilities">
            <div className="panel-heading">
              <div><div className="eyebrow">CAPABILITIES</div><h2>Supported capabilities</h2></div>
              <span className="panel-icon"><ShieldCheck size={18} aria-hidden="true" /></span>
            </div>
            <div className="diagnostic-list">
              <DiagnosticRow label="Rule package" {...rulePackageRow(status)} />
              <DiagnosticRow label="Network telemetry" {...networkRow(status)} />
              <DiagnosticRow
                label="Real-time file blocking"
                value={status.driver_state === "running" ? "Available" : "Unavailable"}
                tone={status.driver_state === "running" ? "healthy" : "attention"}
                detail={status.driver_state === "running"
                  ? "The connected minifilter driver can deny file operations."
                  : "Without a connected minifilter driver the service cannot deny a file operation; detections are recorded only."}
              />
              <DiagnosticRow
                label="Drop-folder watch"
                value={status.sensors?.drop_folder_watch?.state
                  ? status.sensors.drop_folder_watch.state.replaceAll("_", " ")
                  : "Not reported"}
                tone={status.sensors?.drop_folder_watch?.state === "running" ? "healthy"
                  : status.sensors?.drop_folder_watch?.state ? "attention" : "unknown"}
                detail={status.sensors?.drop_folder_watch
                  ? `Watching ${status.sensors.drop_folder_watch.active_roots} of ${status.sensors.drop_folder_watch.roots.length} enrolled folders. User-mode watching cannot block a write.`
                  : "The service did not report a drop-folder watcher."}
              />
            </div>
          </section>

          <section className="panel health-detail-panel" aria-label="Reported sensor capabilities">
            <div className="panel-heading">
              <div><div className="eyebrow">SENSOR RUNTIME</div><h2>Reported capability states</h2></div>
              <span className="panel-icon"><Cpu size={18} aria-hidden="true" /></span>
            </div>
            {capabilities.length === 0 ? (
              <p className="helper-note">The service did not report any sensor capability states.</p>
            ) : (
              <div className="health-list">
                {capabilities.map((capability) => (
                  <div key={`${capability.id}-${capability.key}`}>
                    <span>{capability.name || capability.key}</span>
                    <strong title={capability.error || undefined}>
                      {capability.state ? capability.state.replaceAll("_", " ") : "not reported"}
                    </strong>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="panel health-detail-panel" aria-label="Reported sensor coverage">
            <div className="panel-heading">
              <div><div className="eyebrow">COVERAGE</div><h2>Service-reported coverage</h2></div>
              <span className="panel-icon"><Network size={18} aria-hidden="true" /></span>
            </div>
            {coverage.length === 0 ? (
              <p className="helper-note">The service has not reported sensor coverage details.</p>
            ) : (
              <div className="health-list">
                {coverage.map(([name, value]) => (
                  <div key={name}>
                    <span>{name.replaceAll("_", " ")}</span>
                    <strong>{value === null || value === "" ? "Not reported" : String(value)}</strong>
                  </div>
                ))}
              </div>
            )}
          </section>
        </>
      )}
    </>
  );
}
