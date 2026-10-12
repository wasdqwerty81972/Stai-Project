import { Activity, AlertCircle, CheckCircle2, CircleHelp, Cpu, Shield, ShieldCheck } from "lucide-react";
import type { ProtectionStatus } from "../protection-api";
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

export function SystemStatus({
  status,
  error,
}: {
  status: ProtectionStatus | null;
  error: string | null;
}) {
  const coverage = status?.sensor_coverage ? Object.entries(status.sensor_coverage) : [];
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
          <section className="panel health-detail-panel">
            <div className="panel-heading">
              <div><div className="eyebrow">PROTECTION ENGINE</div><h2>Core components</h2></div>
              <span className="panel-icon"><Cpu size={18} aria-hidden="true" /></span>
            </div>
            <div className="health-detail-grid">
              <HealthCard icon={Shield} label="Filter driver" value={status.driver_state} />
              <HealthCard icon={Activity} label="Local service" value={status.service_state} />
              <HealthCard icon={ShieldCheck} label="Rule package" value={status.rules_version} />
            </div>
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
            <p className="helper-note">SVS Cyber reports the Windows security provider and does not change Defender settings.</p>
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
