import { FileCheck2, Info, LockKeyhole, ShieldCheck } from "lucide-react";
import type { ProtectionStatus } from "../protection-api";
import { isDemoRuleVersion } from "../protection-status";
import { PageHeading } from "./PageHeading";

function rulePackageValue(status: ProtectionStatus | null): string {
  if (!status) return "Not reported";
  if (status.rules_trusted === false) return "Not verified";
  if (!status.rules_version || status.rules_version === "unknown") return "Not reported";
  if (isDemoRuleVersion(status.rules_version)) return `${status.rules_version} · demo only`;
  return status.rules_version;
}

export function SettingsView({ status }: { status: ProtectionStatus | null }) {
  const demoRules = isDemoRuleVersion(status?.rules_version) && status?.rules_trusted !== false;
  return (
    <>
      <PageHeading
        eyebrow="POLICY & PRIVACY"
        title="Settings"
        description="Protection policy is controlled by the signed local service. This dashboard exposes read-only settings."
      />
      <section className="panel settings-panel">
        <div className="panel-heading">
          <div><div className="eyebrow">ACTIVE POLICY</div><h2>Local protection configuration</h2></div>
          <span className="panel-icon"><FileCheck2 size={18} aria-hidden="true" /></span>
        </div>
        {demoRules && (
          <div className="inline-alert coverage-gap" role="status">
            The active rule package is the EICAR demonstration package and provides no real malware coverage.
          </div>
        )}
        <div className="settings-list">
          <SettingRow icon={ShieldCheck} title="Rule package" value={rulePackageValue(status)} detail="Rules are supplied and verified by the local protection service." />
          <SettingRow icon={LockKeyhole} title="Quarantine" value="User initiated restore" detail="Restore requests rescan the file before returning it to its original location." />
          <SettingRow icon={Info} title="Agent permissions" value="Investigation only" detail="The agent can explain detections and answer questions. It cannot run commands or change protection verdicts." />
        </div>
      </section>
      <div className="settings-note"><Info size={16} aria-hidden="true" /><p>Driver, service, and rule updates are managed by the signed installer and local policy. STAI does not change Microsoft Defender settings.</p></div>
    </>
  );
}

function SettingRow({
  icon: Icon,
  title,
  value,
  detail,
}: {
  icon: typeof Info;
  title: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="setting-row">
      <span className="setting-icon"><Icon size={17} aria-hidden="true" /></span>
      <div><strong>{title}</strong><span>{detail}</span></div>
      <b>{value}</b>
    </div>
  );
}
