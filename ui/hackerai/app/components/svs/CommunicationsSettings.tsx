"use client";

import { useCallback, useEffect, useState } from "react";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import {
  approveCommunicationsPairing,
  deleteCommunicationsCredential,
  disableAllCommunications,
  getCommunicationsDeliveries,
  getCommunicationsPairingRequests,
  getCommunicationsPairings,
  getCommunicationsStatus,
  revokeCommunicationsPairing,
  sendCommunicationsTest,
  setCommunicationsCredential,
  setCommunicationsEnabled,
  setCommunicationsNotifications,
  type CommunicationsStatus,
} from "@/lib/stai-api";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const eventChoices = [
  ["incident_created", "Security incidents"],
  ["finding_created", "New findings"],
  ["approval_requested", "Actions awaiting local review"],
  ["agent_error", "Agent errors"],
  ["investigation_completed", "Completed investigations"],
] as const;

export function CommunicationsSettings({ open, onOpenChange }: Props) {
  const [status, setStatus] = useState<CommunicationsStatus | null>(null);
  const [requests, setRequests] = useState<Array<Record<string, string>>>([]);
  const [pairings, setPairings] = useState<Array<{ key: string; channel: string; account_id: string; sender_id: string; role: string }>>([]);
  const [deliveries, setDeliveries] = useState<Array<{ event_id: string; platform: string; event_type: string; status: string; timestamp: number }>>([]);
  const [tokens, setTokens] = useState<Record<string, string>>({});
  const [roles, setRoles] = useState<Record<string, string>>({});
  const [testDestination, setTestDestination] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");

  const refresh = useCallback(async () => {
    const [nextStatus, nextRequests, nextPairings, nextDeliveries] = await Promise.all([
      getCommunicationsStatus(),
      getCommunicationsPairingRequests(),
      getCommunicationsPairings(),
      getCommunicationsDeliveries(),
    ]);
    setStatus(nextStatus);
    setRequests(nextRequests);
    setPairings(nextPairings);
    setDeliveries(nextDeliveries);
    setTestDestination((current) => current || nextPairings[0]?.key || "");
  }, []);

  useEffect(() => {
    if (!open) return;
    let active = true;
    const load = () => refresh().catch((error) => {
      if (active) setNotice(error instanceof Error ? error.message : "Could not load communications settings");
    });
    void load();
    const timer = window.setInterval(() => void load(), 10000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [open, refresh]);

  async function run(action: () => Promise<unknown>, success: string) {
    setBusy(true);
    setNotice("");
    try {
      await action();
      await refresh();
      setNotice(success);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "The request failed");
    } finally {
      setBusy(false);
    }
  }

  const enabled = status?.settings.enabled ?? {};
  const notifications = status?.settings.notifications ?? { enabled: false, event_types: [], destinations: [] };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90dvh] w-[min(760px,96vw)] overflow-y-auto rounded-2xl p-0">
        <div className="sticky top-0 z-10 border-b bg-background/95 px-6 py-5 backdrop-blur">
          <DialogTitle className="text-lg font-semibold">Communications</DialogTitle>
          <p className="mt-1 text-sm text-muted-foreground">Connect private Discord and Telegram conversations to this SVS-Cyber agent.</p>
        </div>
        <div className="space-y-7 px-6 py-5">
          {notice && <p role="status" className="rounded-lg border border-border bg-muted/40 px-3 py-2 text-sm">{notice}</p>}

          <section className="space-y-4" aria-labelledby="connectors-heading">
            <h2 id="connectors-heading" className="text-sm font-semibold">Connectors</h2>
            {(["discord", "telegram"] as const).map((platform) => {
              const connection = status?.platforms[platform];
              return (
                <div key={platform} className="rounded-xl border border-border p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h3 className="font-medium capitalize">{platform}</h3>
                      <p className="text-xs text-muted-foreground">Status: {connection?.status ?? "Loading"}{connection?.error ? ` · ${connection.error}` : ""}</p>
                    </div>
                    <label className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={Boolean(enabled[platform])}
                        disabled={busy}
                        onChange={(event) => void run(
                          () => setCommunicationsEnabled({ ...enabled, [platform]: event.target.checked }),
                          `${platform} setting updated`,
                        )}
                      />
                      Enable
                    </label>
                  </div>
                  <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                    <input
                      type="password"
                      autoComplete="new-password"
                      value={tokens[platform] ?? ""}
                      onChange={(event) => setTokens((current) => ({ ...current, [platform]: event.target.value }))}
                      placeholder={`${platform === "discord" ? "Bot" : "Bot"} token (stored in OS credential vault)`}
                      aria-label={`${platform} bot token`}
                      className="min-w-0 flex-1 rounded-lg border border-input bg-background px-3 py-2 text-sm"
                    />
                    <button
                      type="button"
                      disabled={busy || !tokens[platform]?.trim()}
                      onClick={() => void run(async () => {
                        await setCommunicationsCredential(platform, tokens[platform]);
                        setTokens((current) => ({ ...current, [platform]: "" }));
                      }, "Credential submitted; connection status will update after authentication")}
                      className="rounded-lg bg-primary px-3 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50"
                    >Save credential</button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void run(() => deleteCommunicationsCredential(platform), "Credential removed")}
                      className="rounded-lg border border-border px-3 py-2 text-sm disabled:opacity-50"
                    >Remove</button>
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">Messages are accepted in private chats only. Group conversations are disabled to prevent findings from being broadcast.</p>
                </div>
              );
            })}
          </section>

          <section className="space-y-3" aria-labelledby="pairing-heading">
            <div>
              <h2 id="pairing-heading" className="text-sm font-semibold">Pairing requests</h2>
              <p className="text-xs text-muted-foreground">Approve only accounts you recognize. Analyst access can send requests to CyberAgent.</p>
            </div>
            {requests.length === 0 ? <p className="text-sm text-muted-foreground">No pending requests.</p> : requests.map((item) => (
              <div key={item.request_id} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border p-3 text-sm">
                <span className="min-w-0"><b className="capitalize">{item.channel}</b> · {item.sender_id} · account {item.account_id}</span>
                <div className="flex items-center gap-2">
                  <select value={roles[item.request_id] ?? "viewer"} onChange={(event) => setRoles((current) => ({ ...current, [item.request_id]: event.target.value }))} className="rounded-md border border-input bg-background px-2 py-1.5">
                    <option value="viewer">Viewer</option><option value="analyst">Analyst</option>
                  </select>
                  <button type="button" disabled={busy} onClick={() => void run(() => approveCommunicationsPairing(item.request_id, roles[item.request_id] ?? "viewer"), "Account paired")} className="rounded-md bg-primary px-3 py-1.5 text-primary-foreground disabled:opacity-50">Approve</button>
                </div>
              </div>
            ))}
          </section>

          <section className="space-y-3" aria-labelledby="paired-heading">
            <h2 id="paired-heading" className="text-sm font-semibold">Paired accounts</h2>
            {pairings.length === 0 ? <p className="text-sm text-muted-foreground">No accounts are paired.</p> : pairings.map((item) => (
              <div key={item.key} className="flex items-center justify-between gap-3 rounded-lg border border-border p-3 text-sm">
                <span><b className="capitalize">{item.channel}</b> · {item.sender_id} · {item.role}</span>
                <button type="button" disabled={busy} onClick={() => void run(() => revokeCommunicationsPairing(item.channel, item.account_id, item.sender_id), "Pairing revoked")} className="rounded-md border border-border px-3 py-1.5 text-destructive disabled:opacity-50">Revoke</button>
              </div>
            ))}
          </section>

          <section className="space-y-3" aria-labelledby="notifications-heading">
            <div>
              <h2 id="notifications-heading" className="text-sm font-semibold">Security notifications</h2>
              <p className="text-xs text-muted-foreground">Alerts contain event summaries only. Open the local application for investigation details or approvals.</p>
            </div>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={notifications.enabled} disabled={busy} onChange={(event) => void run(() => setCommunicationsNotifications({ ...notifications, enabled: event.target.checked }), "Notification setting updated")} />Enable selected alerts</label>
            <div className="grid gap-2 sm:grid-cols-2">
              {eventChoices.map(([key, label]) => <label key={key} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={notifications.event_types.includes(key)} disabled={busy} onChange={(event) => {
                const selected = event.target.checked ? [...notifications.event_types, key] : notifications.event_types.filter((item) => item !== key);
                void run(() => setCommunicationsNotifications({ ...notifications, event_types: selected }), "Notification events updated");
              }} />{label}</label>)}
            </div>
            <div className="space-y-2">
              <p className="text-xs font-medium text-muted-foreground">Send alerts to paired accounts</p>
              {pairings.map((item) => <label key={item.key} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={notifications.destinations.includes(item.key)} disabled={busy} onChange={(event) => {
                const selected = event.target.checked ? [...notifications.destinations, item.key] : notifications.destinations.filter((key) => key !== item.key);
                void run(() => setCommunicationsNotifications({ ...notifications, destinations: selected }), "Notification destinations updated");
              }} /><span className="capitalize">{item.channel}</span> · {item.sender_id}</label>)}
            </div>
            {pairings.length > 0 && <div className="flex flex-wrap gap-2">
              <select value={testDestination} onChange={(event) => setTestDestination(event.target.value)} className="rounded-md border border-input bg-background px-2 py-1.5 text-sm">
                {pairings.map((item) => <option key={item.key} value={item.key}>{item.channel} · {item.sender_id}</option>)}
              </select>
              <button type="button" disabled={busy || !testDestination} onClick={() => void run(() => sendCommunicationsTest(testDestination), "Test notification delivered")} className="rounded-md border border-border px-3 py-1.5 text-sm disabled:opacity-50">Send test</button>
            </div>}
          </section>

          <section className="space-y-2" aria-labelledby="delivery-heading">
            <h2 id="delivery-heading" className="text-sm font-semibold">Recent delivery history</h2>
            {deliveries.length === 0 ? <p className="text-sm text-muted-foreground">No notifications delivered yet.</p> : <ul className="space-y-1 text-xs text-muted-foreground">{deliveries.slice(-8).reverse().map((item) => <li key={`${item.event_id}-${item.platform}`} className="flex justify-between gap-2"><span>{item.platform} · {item.event_type}</span><span>{item.status} · {new Date(item.timestamp * 1000).toLocaleTimeString()}</span></li>)}</ul>}
          </section>

          <div className="flex items-center justify-between gap-4 border-t border-border pt-4">
            <p className="text-xs text-muted-foreground">This gateway is available only while the SVS-Cyber host is awake and online.</p>
            <button type="button" disabled={busy} onClick={() => void run(disableAllCommunications, "All remote connectors disabled")} className="shrink-0 rounded-lg border border-destructive/40 px-3 py-2 text-sm font-medium text-destructive disabled:opacity-50">Disable all remote access</button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
