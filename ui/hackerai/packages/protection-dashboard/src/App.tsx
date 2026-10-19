import { useCallback, useEffect, useRef, useState } from "react";
import { RefreshCw } from "lucide-react";
import {
  cancelScan,
  getAgentHistory,
  getActiveScan,
  getProtectionStatus,
  getProtectionTriage,
  getScan,
  getScanSchedule,
  listQuarantine,
  listThreats,
  requestProtectionTriage,
  restoreQuarantine,
  sendAgentMessage,
  startScan,
  setScanSchedule,
  type AgentHistory,
  type AgentReply,
  type DetectionRecord,
  type ProtectionStatus,
  type QuarantineItem,
  type ScanJob,
  type ScanSchedule,
  type ScanScope,
  type TriageRecord,
} from "./protection-api";
import { AgentView } from "./components/AgentView";
import { DriverDiagnostics } from "./components/DriverDiagnostics";
import { Navigation, type DashboardPage } from "./components/Navigation";
import { ProtectionOverview } from "./components/ProtectionOverview";
import { QuarantineView } from "./components/QuarantineView";
import { ScanView } from "./components/ScanView";
import { SettingsView } from "./components/SettingsView";
import { SystemStatus } from "./components/SystemStatus";
import { ThreatActivity } from "./components/ThreatActivity";
import { DeviceActivityView } from "./components/DeviceActivityView";

function messageFor(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === "string" && error.trim()) return error;
  if (error && typeof error === "object" && "message" in error) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string" && message.trim()) return message;
  }
  return fallback;
}

function pageSubtitle(page: DashboardPage) {
  return page === "Dashboard" ? "Windows endpoint protection" : "Local Windows protection";
}

export default function App() {
  const [page, setPage] = useState<DashboardPage>(() =>
    new URLSearchParams(window.location.search).get("view") === "agent"
      ? "AI Agent"
      : "Dashboard",
  );
  const [status, setStatus] = useState<ProtectionStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [threats, setThreats] = useState<DetectionRecord[] | null>(null);
  const [threatsError, setThreatsError] = useState<string | null>(null);
  const [quarantine, setQuarantine] = useState<QuarantineItem[] | null>(null);
  const [quarantineError, setQuarantineError] = useState<string | null>(null);
  const [scan, setScan] = useState<ScanJob | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanBusy, setScanBusy] = useState<ScanScope | null>(null);
  const [scanSchedule, setScanScheduleState] = useState<ScanSchedule | null>(null);
  const [scanScheduleError, setScanScheduleError] = useState<string | null>(null);
  const [selectedDetectionId, setSelectedDetectionId] = useState<string | null>(null);
  const [triage, setTriage] = useState<TriageRecord | null>(null);
  const [triageLoading, setTriageLoading] = useState(false);
  const [triageError, setTriageError] = useState<string | null>(null);
  const [history, setHistory] = useState<AgentHistory | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const refreshing = useRef(false);

  const refresh = useCallback(async () => {
    if (refreshing.current) return;
    refreshing.current = true;
    setStatusLoading(true);
    setThreatsError(null);
    setQuarantineError(null);
    setScanScheduleError(null);
    const [statusResult, threatsResult, quarantineResult, scheduleResult, activeScanResult] = await Promise.allSettled([
      getProtectionStatus(),
      listThreats(),
      listQuarantine(),
      getScanSchedule(),
      getActiveScan(),
    ]);
    if (statusResult.status === "fulfilled") {
      setStatus(statusResult.value);
      setStatusError(null);
    } else {
      setStatusError(messageFor(statusResult.reason, "Protection service unavailable"));
    }
    if (threatsResult.status === "fulfilled") {
      setThreats(threatsResult.value);
    } else {
      setThreats(null);
      setThreatsError(messageFor(threatsResult.reason, "Threat activity unavailable"));
    }
    if (quarantineResult.status === "fulfilled") {
      setQuarantine(quarantineResult.value);
    } else {
      setQuarantine(null);
      setQuarantineError(messageFor(quarantineResult.reason, "Quarantine is unavailable"));
    }
    if (scheduleResult.status === "fulfilled") {
      setScanScheduleState(scheduleResult.value);
      setScanScheduleError(null);
    } else {
      setScanScheduleState(null);
      setScanScheduleError(messageFor(scheduleResult.reason, "Scan schedule unavailable"));
    }
    if (activeScanResult.status === "fulfilled") {
      setScan(activeScanResult.value.active_scan);
      setScanError(null);
    }
    setStatusLoading(false);
    refreshing.current = false;
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!["Dashboard", "AI Agent", "System Status", "Driver Diagnostics"].includes(page) && !statusError) return;
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(timer);
  }, [page, refresh, statusError]);

  useEffect(() => {
    if (page !== "Scans") return;
    let stale = false;
    const poll = async () => {
      try {
        const current = await getScanSchedule();
        if (!stale) {
          setScanScheduleState(current);
          setScanScheduleError(null);
        }
      } catch (error) {
        if (!stale) setScanScheduleError(messageFor(error, "Scan schedule unavailable"));
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 15000);
    return () => {
      stale = true;
      window.clearInterval(timer);
    };
  }, [page]);

  const activeScan = scan?.state === "running" || scan?.state === "queued";
  const activeScanJobId = activeScan ? scan?.job_id : undefined;
  useEffect(() => {
    // Key the interval on the job id so a progress update does not tear down
    // and rebuild the timer on every poll.
    if (!activeScanJobId) return;
    const timer = window.setInterval(() => {
      void getScan(activeScanJobId)
        .then(setScan)
        .catch((error: unknown) => setScanError(messageFor(error, "Scan progress unavailable")));
    }, 1500);
    return () => window.clearInterval(timer);
  }, [activeScanJobId]);

  useEffect(() => {
    if (page !== "AI Agent" || selectedDetectionId || !threats?.length) return;
    const first = threats.find((detection) => detection.triage_enqueued) ?? threats[0];
    setSelectedDetectionId(first.detection_id);
  }, [page, selectedDetectionId, threats]);

  useEffect(() => {
    if (page !== "AI Agent" || !selectedDetectionId) return;
    let stale = false;
    setTriage(null);
    setHistory(null);
    setTriageError(null);
    setHistoryError(null);
    setTriageLoading(true);
    void getProtectionTriage(selectedDetectionId)
      .then(async (record) => {
        if (stale) return;
        setTriage(record);
        try {
          const conversation = await getAgentHistory(record.triage_id);
          if (!stale) setHistory(conversation);
        } catch (error) {
          if (!stale) setHistoryError(messageFor(error, "Conversation history unavailable"));
        }
      })
      .catch((error: unknown) => {
        if (!stale) setTriageError(messageFor(error, "Stored analysis unavailable"));
      })
      .finally(() => {
        if (!stale) setTriageLoading(false);
      });
    return () => {
      stale = true;
    };
  }, [page, selectedDetectionId]);

  useEffect(() => {
    if (page !== "AI Agent" || !selectedDetectionId || !triage || !["queued", "running"].includes(triage.state)) return;
    let stale = false;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const current = await getProtectionTriage(selectedDetectionId);
        if (stale) return;
        setTriage(current);
        if (current.state === "queued" || current.state === "running") {
          timer = window.setTimeout(() => void poll(), 1200);
        }
      } catch (error) {
        if (!stale) setTriageError(messageFor(error, "Unable to refresh analysis status"));
      }
    };
    timer = window.setTimeout(() => void poll(), 1200);
    return () => {
      stale = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [page, selectedDetectionId, triage?.state]);

  const handleStartScan = useCallback(
    async (scope: ScanScope) => {
      if (activeScan) {
        setPage("Scans");
        return;
      }
      if (!status || statusError || status.state === "unavailable") {
        const error = new Error("Scans are unavailable until the local protection service is active.");
        setScanError(error.message);
        throw error;
      }
      setScanError(null);
      setScanBusy(scope);
      try {
        const created = await startScan(scope);
        setScan(created);
        setPage("Scans");
        if (created.state === "running" || created.state === "queued") {
          const current = await getScan(created.job_id);
          setScan(current);
        }
      } catch (error) {
        const message = messageFor(error, "Unable to start scan");
        setScanError(message);
        throw new Error(message);
      } finally {
        setScanBusy(null);
      }
    },
    [activeScan, status, statusError],
  );

  const handleCancelScan = useCallback(async () => {
    if (!scan) return;
    setScanError(null);
    try {
      const result = await cancelScan(scan.job_id);
      setScan(result ?? (await getScan(scan.job_id)));
    } catch (error) {
      setScanError(messageFor(error, "Unable to cancel scan"));
    }
  }, [scan]);

  const handleSaveScanSchedule = useCallback(async (config: Pick<ScanSchedule, "enabled" | "frequency" | "scope" | "local_time" | "weekday">) => {
    setScanScheduleError(null);
    try {
      const saved = await setScanSchedule(config);
      setScanScheduleState(saved);
      return saved;
    } catch (error) {
      const message = messageFor(error, "Unable to save the scan schedule");
      setScanScheduleError(message);
      throw new Error(message);
    }
  }, []);

  const handleRestore = useCallback(async (itemId: string) => {
    const result = await restoreQuarantine(itemId);
    if (!result.success || !result.item) {
      throw new Error(result.error || "The service did not confirm a successful restore.");
    }
    setQuarantine((items) =>
      items?.map((item) => item.item_id === itemId ? result.item! : item) ?? items,
    );
  }, []);

  const handleRetryTriage = useCallback(async () => {
    if (!selectedDetectionId) return;
    setTriageLoading(true);
    setTriageError(null);
    try {
      const result = await requestProtectionTriage(selectedDetectionId);
      setTriage(result);
      try {
        setHistory(await getAgentHistory(result.triage_id));
        setHistoryError(null);
      } catch (error) {
        setHistory(null);
        setHistoryError(messageFor(error, "Conversation history unavailable"));
      }
    } catch (error) {
      setTriageError(messageFor(error, "Unable to request analysis"));
    } finally {
      setTriageLoading(false);
    }
  }, [selectedDetectionId]);

  const selectedDetection = threats?.find((item) => item.detection_id === selectedDetectionId) ?? null;
  const handleSendAgentMessage = useCallback(
    async (message: string): Promise<AgentReply> => {
      if (!selectedDetection) throw new Error("Select a detection before asking a question.");
      const sessionId = history?.session_id ?? triage?.triage_id ?? selectedDetection.detection_id;
      const beforeMessageCount = history?.session_id === sessionId ? history.messages.length : 0;
      const result = await sendAgentMessage(sessionId, message, selectedDetection.detection_id);
      if (result.status !== "queued") return result;

      for (let attempt = 0; attempt < 30; attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 1000));
        const current = await getAgentHistory(sessionId);
        const messages = current.messages;
        const latest = messages[messages.length - 1];
        if (messages.length >= beforeMessageCount + 2 && latest?.role === "assistant") {
          setHistory(current);
          return { ...result, message: "", status: "completed" };
        }
      }
      throw new Error("The protection agent is still processing this question. Reopen the detection to refresh its history.");
    },
    [history, selectedDetection, triage?.triage_id],
  );

  const openDetection = (detection: DetectionRecord) => {
    setSelectedDetectionId(detection.detection_id);
    setPage("AI Agent");
  };

  return (
    <div className="app-shell">
      <Navigation
        page={page}
        onNavigate={setPage}
      />
      <main className="main-area">
        <header className="topbar">
          <div className="topbar-context">
            <span className="device-dot" aria-hidden="true" />
            <span>MY DEVICE</span>
            <span className="topbar-divider">/</span>
            <strong>{pageSubtitle(page)}</strong>
          </div>
          <button className="topbar-refresh" onClick={() => void refresh()} type="button" aria-label="Refresh protection data" title="Refresh protection data">
            <RefreshCw size={16} aria-hidden="true" />
          </button>
        </header>

        <div className="page-scroll" key={page}>
          <div className="page-content">
            {(page === "Processes" || page === "Network Activity") && (
              <DeviceActivityView mode={page === "Processes" ? "processes" : "network"} />
            )}
            {page === "Dashboard" && (
              statusLoading && !status && !statusError ? (
                <div className="page-loading" role="status"><span className="spinner" /> Connecting to local protection service…</div>
              ) : (
                <ProtectionOverview
                  status={status}
                  statusError={statusError}
                  threats={threats}
                  threatsError={threatsError}
                  scan={scan}
                  scanError={scanError}
                  scanBusy={scanBusy}
                    onStartScan={(scope) => void handleStartScan(scope).catch(() => undefined)}
                  onNavigate={setPage}
                  onOpenDetection={openDetection}
                  onRetry={() => void refresh()}
                />
              )
            )}
            {page === "AI Agent" && (
              <AgentView
                threats={threats}
                threatsError={threatsError}
                selectedDetection={selectedDetection}
                onSelectDetection={openDetection}
                triage={triage}
                triageLoading={triageLoading}
                triageError={triageError}
                onRetryTriage={handleRetryTriage}
                history={history}
                historyError={historyError}
                onSend={handleSendAgentMessage}
                sensorWarnings={status?.sensors?.warnings ?? []}
              />
            )}
            {page === "System Status" && <SystemStatus status={status} error={statusError} />}
            {page === "Driver Diagnostics" && <DriverDiagnostics status={status} error={statusError} />}
            {page === "Threat Activity" && <ThreatActivity threats={threats} error={threatsError} />}
            {page === "Scans" && (
              <ScanView
                scan={scan}
                scanError={scanError}
                schedule={scanSchedule}
                scheduleError={scanScheduleError}
                onStart={handleStartScan}
                onCancel={handleCancelScan}
                onSaveSchedule={handleSaveScanSchedule}
                unavailable={!status || Boolean(statusError) || status.state === "unavailable"}
              />
            )}
            {page === "Quarantine" && (
              <QuarantineView items={quarantine} error={quarantineError} onRestore={handleRestore} />
            )}
            {page === "Settings" && <SettingsView status={status} />}
          </div>
          <footer className="page-footer">SVS Cyber · Local Windows dashboard · Status reflects service-reported evidence</footer>
        </div>
      </main>
    </div>
  );
}
