import { Activity, AlertCircle, CheckCircle2, CircleHelp, Cpu, Network, Shield, ShieldCheck } from "lucide-react";
import type { ProtectionStatus } from "../protection-api";
import { isDemoRuleVersion } from "../protection-status";
import { PageHeading } from "./PageHeading";
import { StatusPill } from "./StatusPill";

function HealthValue({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="health-value unknown"><CircleHelp size={14} aria-hidden="true" /> Not reported</span>;
  const healthy = ["running", "active", "enabled", "covered", "healthy"].includes(value.toLowerCase());
  return (
    <span className={`health-value ${healthy ? "healthy" : "attention"}`}>
      {healthy ? <CheckCircle2 size={14} aria-hidden="true" /> : <AlertCircle size={14} aria-hidden="true" />}
      {value}
    </span>
  );
}

/** Rule packages carry the real coverage, so trust and demo state lead here. */
function RulePackageValue({ status }: { status: ProtectionStatus }) {
  if (status.rules_trusted === false) {
    return <span className="health-value attention"><AlertCircle size={14} aria-hidden="true" /> Not verified</span>;
  }
  if (!status.rules_version || status.rules_version === "unknown") {
    return <span className="health-value unknown"><CircleHelp size={14} aria-hidden="true" /> Not reported</span>;
  }
  if (isDemoRuleVersion(status.rules_version)) {
    return (
      <span className="health-value attention">
        <AlertCircle size={14} aria-hidden="true" /> {status.rules_version} · demo only
      </span>
    );
  }
  return (
    <span className="health-value healthy">
      <CheckCircle2 size={14} aria-hidden="true" /> {status.rules_version}
      {status.rule_count == null ? "" : ` · ${status.rule_count} rules`}
    </span>
  );
}

export function SystemStatus({
  status,
  error,
}: {
  status: ProtectionStatus | null;
  error: string | null;
}) {
  const coverage = status?.sensor_coverage ? Object.entries(status.sensor_coverage) : [];
  const sensorRegistry = status?.sensors?.registry ?? [];
  const sensorsByCategory = sensorRegistry.reduce<Record<string, typeof sensorRegistry>>((groups, sensor) => {
    (groups[sensor.category] ??= []).push(sensor);
    return groups;
  }, {});
  return (
    <>
      <PageHeading
        eyebrow="DEVICE HEALTH"
        title="System status"
        description="Read-only health observations from the local protection service and Windows."
        action={status && <StatusPill state={status.state} />}
      />
      {error && <div role="alert" className="inline-alert error-alert">{error}</div>}
      {!status ? (
        <section className="panel"><div className="loading-row"><span className="spinner" /> Loading system status…</div></section>
      ) : (
        <>
          {status.last_error && <div className="inline-alert error-alert"><AlertCircle size={16} aria-hidden="true" /> {status.last_error}</div>}
          {status.sensor_error && <div className="inline-alert error-alert"><AlertCircle size={16} aria-hidden="true" /> {status.sensor_error}</div>}
          <section className="panel health-detail-panel">
            <div className="panel-heading">
              <div><div className="eyebrow">PROTECTION ENGINE</div><h2>Core components</h2></div>
              <span className="panel-icon"><Cpu size={18} aria-hidden="true" /></span>
            </div>
            <div className="health-detail-grid">
              <HealthCard icon={Shield} label="Filter driver" value={status.driver_state} />
              <HealthCard icon={Activity} label="Local service" value={status.service_state} />
              <HealthCard
                icon={ShieldCheck}
                label="Hash intelligence"
                value={status.threat_intel?.state === "advisory"
                  ? `Advisory · ${status.threat_intel.block_eligible_records} eligible; inactive`
                  : status.threat_intel?.state ?? "Not reported"}
              />
              <article className="health-card">
                <span className="health-card-icon"><ShieldCheck size={17} aria-hidden="true" /></span>
                <span>Rule package</span>
                <RulePackageValue status={status} />
              </article>
            </div>
            {isDemoRuleVersion(status.rules_version) && status.rules_trusted !== false && (
              <div className="inline-alert coverage-gap" role="status">
                <AlertCircle size={16} aria-hidden="true" />
                The active rule package is the EICAR demonstration package. It detects the EICAR test file only and provides no real malware coverage.
              </div>
            )}
            {status.threat_intel?.state === "advisory" && (
              <p className="helper-note">
                Exact SHA-256 matches are stored as evidence. Feed-based blocking stays inactive until signed feed activation is implemented and verified.
              </p>
            )}
          </section>

          <section className="panel health-detail-panel">
            <div className="panel-heading">
              <div><div className="eyebrow">NETWORK</div><h2>Network telemetry</h2></div>
              <span className="panel-icon"><Network size={18} aria-hidden="true" /></span>
            </div>
            <div className="health-list">
              <div>
                <span>Reported state</span>
                <strong>
                  <HealthValue value={status.network_telemetry?.state?.replaceAll("_", " ") ?? null} />
                </strong>
              </div>
              {status.network_telemetry?.startup_error && (
                <div><span>Startup error</span><strong>{status.network_telemetry.startup_error}</strong></div>
              )}
            </div>
            <p className="helper-note">
              {status.network_telemetry?.state === "running"
                ? "The service reports active network telemetry."
                : "Network Activity lists connections read from user-mode polling. Without active network telemetry those connections are not filtered or blocked."}
            </p>
          </section>

          <section className="panel health-detail-panel">
            <div className="panel-heading">
              <div><div className="eyebrow">WINDOWS SECURITY</div><h2>Registered antivirus</h2></div>
              <span className="panel-icon"><ShieldCheck size={18} aria-hidden="true" /></span>
            </div>
            <div className="health-list">
              <div><span>Antivirus provider</span><strong>{status.windows_security?.registered_av_provider ?? "Not reported by Windows"}</strong></div>
              <div><span>Defender mode</span><strong>{status.windows_security?.defender_mode ?? "Not reported by Windows"}</strong></div>
              <div><span>Windows query</span><strong>{status.windows_security?.query_available ? "Available" : "Unavailable"}</strong></div>
            </div>
            <p className="helper-note">STAI reports the Windows security provider and does not change Defender settings.</p>
          </section>

          <section className="panel health-detail-panel">
            <div className="panel-heading">
              <div><div className="eyebrow">SENSOR COVERAGE</div><h2>Reported coverage</h2></div>
              <span className="panel-icon"><Activity size={18} aria-hidden="true" /></span>
            </div>
            {coverage.length === 0 ? (
              <p className="helper-note">The service has not reported sensor coverage details.</p>
            ) : (
              <div className="health-list">
                {coverage.map(([name, value]) => (
                  <div key={name}><span>{name.replaceAll("_", " ")}</span><strong><HealthValue value={value === null ? null : String(value)} /></strong></div>
                ))}
              </div>
            )}
          </section>

          <section className="panel health-detail-panel">
            <div className="panel-heading">
              <div><div className="eyebrow">ENDPOINT SENSORS</div><h2>Sensor runtime</h2></div>
              <span className="panel-icon"><Activity size={18} aria-hidden="true" /></span>
            </div>
            {!status.sensors ? (
              <p className="helper-note">Sensor runtime status is not available from the protection service.</p>
            ) : (
              <>
                <div className="health-list">
                  <div><span>Collector service</span><strong>{status.sensors.running ? "Running" : "Stopped or unavailable"}</strong></div>
                  <div><span>Catalog entries</span><strong>{sensorRegistry.length}</strong></div>
                  <div><span>Queued events</span><strong>{status.sensors.queue?.depth ?? 0} / {status.sensors.queue?.capacity ?? 0}</strong></div>
                  <div><span>Last event</span><strong>{status.sensors.last_event_time ?? "Not reported"}</strong></div>
                  <div><span>Backpressure</span><strong>{status.sensors.queue?.backpressure ?? 0}</strong></div>
                  <div><span>Drop-folder watcher</span><strong>{status.sensors.drop_folder_watch?.state ?? "Unavailable"}</strong></div>
                  <div><span>Watched folders</span><strong>{status.sensors.drop_folder_watch?.active_roots ?? 0} / {status.sensors.drop_folder_watch?.roots.length ?? 0}</strong></div>
                </div>
                {status.sensors.drop_folder_watch && (
                  <p className="helper-note">
                    Drop-folder scans run after writes settle. Coverage is limited to the enrolled user’s Downloads, Desktop, and Temp folders; kernel-level blocking requires an installed minifilter driver.
                  </p>
                )}
                <div className="sensor-category-list">
                  {Object.entries(sensorsByCategory).map(([category, sensors]) => (
                    <details key={category} className="sensor-category">
                      <summary>{category.replaceAll("_", " ")} <span>{sensors.length}</span></summary>
                      <div className="health-list">
                        {sensors.map((sensor) => (
                          <div key={sensor.id}>
                            <span>{sensor.name}</span>
                            <strong title={sensor.runtime_error ?? sensor.host_support}>{sensor.runtime_state.replaceAll("_", " ")}</strong>
                          </div>
                        ))}
                      </div>
                    </details>
                  ))}
                </div>
              </>
            )}
          </section>
        </>
      )}
    </>
  );
}

function HealthCard({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Cpu;
  label: string;
  value: string | null;
}) {
  return (
    <article className="health-card">
      <span className="health-card-icon"><Icon size={17} aria-hidden="true" /></span>
      <span>{label}</span>
      <HealthValue value={value} />
    </article>
  );
}
