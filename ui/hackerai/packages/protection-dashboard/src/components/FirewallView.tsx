import { AlertTriangle, CheckCircle2, LockKeyhole, RefreshCw, Shield } from "lucide-react";
import type { FirewallSnapshot } from "../protection-api";
import { PageHeading } from "./PageHeading";

export function FirewallView({
  snapshot,
  error,
  loading,
  onRefresh,
}: {
  snapshot: FirewallSnapshot | null;
  error: string | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  const enabledProfiles = snapshot?.profiles?.filter((profile) => profile.enabled).length ?? null;
  return (
    <>
      <PageHeading
        eyebrow="WINDOWS NETWORK SECURITY"
        title="Firewall"
        description="Inspect effective Windows Firewall profiles and review SVS Cyber rule telemetry."
        action={<button className="secondary-button compact-button" onClick={onRefresh} type="button" disabled={loading}><RefreshCw size={14} aria-hidden="true" /> Refresh</button>}
      />
      {error && <div className="inline-alert error-alert" role="alert">{error}</div>}
      {snapshot?.state === "unavailable" && <div className="inline-alert warning-alert" role="status"><AlertTriangle size={16} aria-hidden="true" /> Windows Firewall status is unavailable. SVS Cyber will not infer that the device is protected.</div>}
      <section className="firewall-summary-grid" aria-label="Firewall summary">
        <article className="firewall-summary-card"><span className="panel-icon"><Shield size={18} aria-hidden="true" /></span><div><small>WINDOWS FIREWALL</small><strong>{snapshot?.protection === "enabled" ? "Enabled" : snapshot?.protection === "partial" ? "Partially enabled" : snapshot?.protection === "disabled" ? "Disabled" : "Unavailable"}</strong><span>{snapshot?.source ?? "Waiting for local service"}</span></div></article>
        <article className="firewall-summary-card"><span className="panel-icon"><CheckCircle2 size={18} aria-hidden="true" /></span><div><small>ACTIVE PROFILES</small><strong>{enabledProfiles == null ? "—" : `${enabledProfiles} of ${snapshot?.profiles?.length ?? 0}`}</strong><span>Effective profile state</span></div></article>
        <article className="firewall-summary-card"><span className="panel-icon"><LockKeyhole size={18} aria-hidden="true" /></span><div><small>SVS CYBER RULES</small><strong>{snapshot?.managed_rules?.length ?? "—"}</strong><span>Only rules owned by this app</span></div></article>
      </section>
      <section className="firewall-profile-grid" aria-label="Windows Firewall profiles">
        {snapshot?.profiles?.map((profile) => <article className={`firewall-profile ${profile.enabled ? "enabled" : "disabled"}`} key={profile.name}><div><strong>{profile.name}</strong><span className={`interface-state ${profile.enabled ? "up" : "down"}`}>{profile.enabled ? "Enabled" : "Disabled"}</span></div><p>Inbound default <b>{profile.default_inbound_action}</b> · Outbound default <b>{profile.default_outbound_action}</b></p></article>)}
        {!snapshot?.profiles && <div className="panel network-muted">Profile details have not been reported.</div>}
      </section>
      <section className="panel firewall-rules-panel">
        <div className="panel-heading"><div><div className="eyebrow">MANAGED RULES</div><h2>SVS Cyber rules</h2></div><span className="panel-icon"><LockKeyhole size={17} aria-hidden="true" /></span></div>
        <p className="panel-description">SVS Cyber displays only rules carrying its ownership marker. The current build is read-only; rule changes require a separate Windows elevation and confirmation flow.</p>
        {!snapshot?.managed_rules ? <p className="network-muted">SVS Cyber rule inventory is unavailable.</p> : snapshot.managed_rules.length === 0 ? <div className="empty-rule-state"><Shield size={21} /><strong>No SVS Cyber rules</strong><span>There are no rules created by SVS Cyber to display.</span></div> : <div className="network-table-scroll"><table className="network-table firewall-table"><thead><tr><th>Rule</th><th>Remote address</th><th>Direction</th><th>Action</th><th>Profiles</th><th>State</th></tr></thead><tbody>{snapshot.managed_rules.map((rule) => <tr key={rule.rule_id}><td><strong>{rule.name}</strong><small>{rule.owner}</small></td><td className="mono-cell">{rule.remote_addresses}</td><td>{rule.direction}</td><td><span className="protocol-tag tcp">{rule.action.toUpperCase()}</span></td><td>{rule.profiles}</td><td>{rule.enabled ? "Enabled" : "Disabled"}</td></tr>)}</tbody></table></div>}
      </section>
      <p className="helper-note firewall-note">SVS Cyber uses the existing Windows Firewall. This COM view reads local profile settings; Group Policy can override local values. It does not disable Defender Firewall or change rules owned by Windows, Group Policy, or other software.</p>
    </>
  );
}
