import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import {
  getProtectionStatus,
  getProcessConnections,
  getProcessDetails,
  scanProcessExecutable,
  setProcessMonitorProfile,
  listThreats,
  startScan,
  getScan,
  cancelScan,
  listQuarantine,
  restoreQuarantine,
  getTriage,
  getAgentHistory,
  sendAgentMessage,
  subscribeToProcessMonitor,
  type ProtectionStatus,
  type ThreatRecord,
  type ScanJob,
  type QuarantineItem,
} from "@/lib/stai-protection-api";
import { SvsProtectionDashboard } from "./SvsProtectionDashboard";

jest.mock("@/lib/stai-protection-api", () => ({
  getProtectionStatus: jest.fn(),
  getProcessConnections: jest.fn(),
  getProcessDetails: jest.fn(),
  scanProcessExecutable: jest.fn(),
  setProcessMonitorProfile: jest.fn(),
  listThreats: jest.fn(),
  startScan: jest.fn(),
  getScan: jest.fn(),
  cancelScan: jest.fn(),
  listQuarantine: jest.fn(),
  restoreQuarantine: jest.fn(),
  getTriage: jest.fn(),
  getAgentHistory: jest.fn(),
  sendAgentMessage: jest.fn(),
  subscribeToProcessMonitor: jest.fn(),
}));

const activeStatus: ProtectionStatus = {
  state: "active",
  driver_state: "running",
  service_state: "running",
  rules_version: "2026.10.12-1",
  last_scan: "2026-10-12T08:00:00.000Z",
  // The three counts MUST stay distinct — never summed or conflated.
  counts: { detected: 4, blocked: 2, quarantined: 1 },
  windows_security: {
    registered_av_provider: "STAI Protection",
    defender_mode: "passive",
  },
  sensor_coverage: { phase1_mappings: 7, sources_readable: 3 },
  last_error: null,
};

const threatFixtures: ThreatRecord[] = [
  {
    detection_id: "det-1",
    sha256: "a".repeat(64),
    rule_id: "STAI-EICAR-TEST",
    rule_version: "1",
    action: "block",
    confidence: "high",
    severity: "high",
    file_type: "exe",
    size_bytes: 68,
    file_path: "C:/Users/u/Downloads/sample.exe",
    created_at: "2026-10-12T08:10:00.000Z",
    triage_enqueued: true,
  },
  {
    detection_id: "det-2",
    sha256: "b".repeat(64),
    rule_id: "STAI-YARA-OBS",
    rule_version: "3",
    action: "observe",
    confidence: "medium",
    severity: "low",
    file_type: "dll",
    size_bytes: 1024,
    file_path: "C:/temp/x.dll",
    created_at: "2026-10-12T07:50:00.000Z",
    triage_enqueued: false,
  },
];

const quarantineFixtures: QuarantineItem[] = [
  {
    item_id: "q-1",
    original_path: "C:/Users/u/Downloads/sample.exe",
    quarantined_path: "C:/ProgramData/STAI/Quarantine/q-1",
    sha256: "a".repeat(64),
    rule_id: "STAI-EICAR-TEST",
    rule_version: "1",
    action_result: "quarantined",
    detection_id: "det-1",
    created_at: "2026-10-12T08:10:05.000Z",
    restored_at: null,
    restore_result: null,
  },
];

const runningJob: ScanJob = {
  job_id: "scan-1",
  scope: "quick",
  state: "running",
  files_scanned: 12,
  files_total: 100,
  detections: 0,
  errors: 0,
  files_skipped: 0,
  unknown_verdicts: 0,
  started_at: "2026-10-12T09:00:00.000Z",
  completed_at: null,
  error_message: null,
};

const completedJob: ScanJob = {
  ...runningJob,
  state: "completed",
  files_scanned: 100,
  detections: 1,
  completed_at: "2026-10-12T09:01:00.000Z",
};

beforeEach(() => {
  // Defaults are overridden per test. getTriage / getAgentHistory reject to
  // mirror the backend's current 501 responses so the UI degrades honestly.
  jest.mocked(getProtectionStatus).mockResolvedValue(activeStatus);
  jest
    .mocked(getProcessConnections)
    .mockResolvedValue({ instance_id: "", available: true, connections: [] });
  jest.mocked(getProcessDetails).mockResolvedValue({
    pid: 0,
    instance_id: "",
    identity_verified: false,
    name: "unknown",
    status: "running",
    cpu_percent: null,
    memory_bytes: null,
  });
  jest
    .mocked(scanProcessExecutable)
    .mockRejectedValue(new Error("unavailable"));
  jest.mocked(setProcessMonitorProfile).mockResolvedValue({
    state: "running",
    event_source: "degraded",
    dropped_events: 0,
    sample_interval_seconds: 5,
    reconcile_interval_seconds: 5,
    sampling_profile: "normal",
  });
  jest.mocked(listThreats).mockResolvedValue([]);
  jest.mocked(listQuarantine).mockResolvedValue([]);
  jest.mocked(startScan).mockResolvedValue(runningJob);
  jest.mocked(getScan).mockResolvedValue(completedJob);
  jest
    .mocked(cancelScan)
    .mockResolvedValue({ status: "cancelled", job_id: "scan-1" });
  jest
    .mocked(restoreQuarantine)
    .mockResolvedValue({ success: true, item: null });
  jest
    .mocked(getTriage)
    .mockRejectedValue(new Error("triage endpoint not yet implemented"));
  jest
    .mocked(getAgentHistory)
    .mockRejectedValue(new Error("agent history endpoint not yet implemented"));
  jest.mocked(sendAgentMessage).mockResolvedValue({
    session_id: "protection-triage-det-1",
    message: "Protection agent analysis not yet implemented",
    tool_calls: [],
    response_action: null,
  });
  jest
    .mocked(subscribeToProcessMonitor)
    .mockImplementation((onEvent, onState) => {
      onState("connected");
      onEvent({
        type: "snapshot",
        sequence: 1,
        processes: [
          {
            pid: 9024,
            instance_id: "9024:0x1",
            identity_verified: true,
            name: "sample-app.exe",
            status: "running",
            cpu_percent: 12.5,
            memory_bytes: 1048576,
          },
        ],
        health: {
          state: "running",
          event_source: "degraded",
          dropped_events: 0,
          sample_interval_seconds: 1,
          reconcile_interval_seconds: 5,
        },
      });
      return jest.fn();
    });
});

describe("SvsProtectionDashboard", () => {
  it("opens the live Processes tab and renders real monitor snapshots", async () => {
    render(<SvsProtectionDashboard />);
    fireEvent.click(await screen.findByRole("button", { name: "Processes" }));

    expect(await screen.findByText("sample-app.exe")).toBeInTheDocument();
    expect(screen.getByText("12.5%")).toBeInTheDocument();
    expect(screen.getByText("1.0 MB")).toBeInTheDocument();
    expect(screen.getByText("Snapshot reconciliation")).toBeInTheDocument();
    expect(subscribeToProcessMonitor).toHaveBeenCalled();
  });

  it("renders the active state with distinct detection/blocked/quarantine counts", async () => {
    render(<SvsProtectionDashboard />);

    expect(
      await screen.findByRole("heading", { name: "Active" }),
    ).toBeInTheDocument();

    // Each count is read from its own labelled tile — proving they are not conflated.
    expect(
      within(screen.getByRole("group", { name: "Detections" })).getByText("4"),
    ).toBeInTheDocument();
    expect(
      within(
        screen.getByRole("group", { name: "Confirmed blocked" }),
      ).getByText("2"),
    ).toBeInTheDocument();
    expect(
      within(screen.getByRole("group", { name: "Quarantined" })).getByText("1"),
    ).toBeInTheDocument();

    expect(screen.getByText("2026.10.12-1")).toBeInTheDocument();
  });

  it("renders the degraded state from the API, not a success state", async () => {
    jest.mocked(getProtectionStatus).mockResolvedValue({
      ...activeStatus,
      state: "degraded",
      last_error: "rule pack stale",
    });
    render(<SvsProtectionDashboard />);

    expect(
      await screen.findByRole("heading", { name: "Degraded" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Active" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("rule pack stale")).toBeInTheDocument();
  });

  it("explains the limited user-mode fallback when the kernel filter is stopped", async () => {
    jest.mocked(getProtectionStatus).mockResolvedValue({
      ...activeStatus,
      state: "degraded",
      driver_state: "stopped",
      protection_mode: "user_mode_limited",
      fallback_coverage: {
        state: "running",
        coverage: "post_write_selected_user_folders",
        active_roots: 1,
        roots: ["C:/Users/demo/Downloads"],
        limitations: [
          "Cannot prevent a file from executing before it is scanned.",
        ],
      },
    });
    render(<SvsProtectionDashboard />);

    expect(
      await screen.findByRole("heading", { name: "Degraded" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/kernel filter is disconnected/i),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "System Status" }));
    expect(await screen.findByText("user mode limited")).toBeInTheDocument();
    expect(
      screen.getByText(/cannot prevent a file from executing/i),
    ).toBeInTheDocument();
  });

  it("renders the unavailable state and never a success badge", async () => {
    jest.mocked(getProtectionStatus).mockResolvedValue({
      ...activeStatus,
      state: "unavailable",
      last_error: "driver not loaded",
    });
    render(<SvsProtectionDashboard />);

    expect(
      await screen.findByRole("heading", { name: "Unavailable" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Active" }),
    ).not.toBeInTheDocument();
    expect(
      within(screen.getByRole("group", { name: "Detections" })).getByText("—"),
    ).toBeInTheDocument();
    expect(screen.getByText("driver not loaded")).toBeInTheDocument();
  });

  it("shows an honest unavailable state (no fabricated zero counts) when the service is unreachable", async () => {
    jest
      .mocked(getProtectionStatus)
      .mockRejectedValue(new Error("Failed to fetch"));
    render(<SvsProtectionDashboard />);

    expect(
      await screen.findByRole("heading", { name: "Unavailable" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Active" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Failed to fetch/)).toBeInTheDocument();

    // Counts render as "—", never as a reassuring "0".
    expect(
      within(screen.getByRole("group", { name: "Detections" })).getByText("—"),
    ).toBeInTheDocument();
    expect(
      within(
        screen.getByRole("group", { name: "Confirmed blocked" }),
      ).getByText("—"),
    ).toBeInTheDocument();
  });

  it("summarizes rule pack and pending AI escalations on the dashboard", async () => {
    jest.mocked(listThreats).mockResolvedValue(threatFixtures);
    render(<SvsProtectionDashboard />);

    await screen.findByRole("heading", { name: "Active" });
    expect(screen.getByText("2026.10.12-1")).toBeInTheDocument();
    expect(
      await screen.findByText(/1 detection awaiting AI triage/i),
    ).toBeInTheDocument();
  });

  it("exposes all seven navigation labels as keyboard-reachable controls", async () => {
    render(<SvsProtectionDashboard />);
    await screen.findByRole("heading", { name: "Active" });

    const nav = screen.getByRole("navigation", {
      name: "Protection navigation",
    });
    for (const label of [
      "Dashboard",
      "AI Agent",
      "System Status",
      "Threat Activity",
      "Scans",
      "Quarantine",
      "Settings",
    ]) {
      const button = within(nav).getByRole("button", { name: label });
      expect(button).toBeEnabled();
      button.focus();
      expect(button).toHaveFocus();
    }
  });

  it("starts a quick scan and shows live progress", async () => {
    render(<SvsProtectionDashboard />);

    fireEvent.click(await screen.findByRole("button", { name: "Quick scan" }));

    await waitFor(() => expect(startScan).toHaveBeenCalledWith("quick"));
    expect(await screen.findByText(/files scanned/)).toBeInTheDocument();
  });

  it("shows incomplete coverage when any files were skipped or verdicts were unknown", async () => {
    jest.mocked(startScan).mockResolvedValue({
      ...runningJob,
      state: "partial",
      files_scanned: 97,
      files_total: 100,
      files_skipped: 2,
      unknown_verdicts: 1,
      completed_at: "2026-10-12T09:01:00.000Z",
    });
    render(<SvsProtectionDashboard />);

    fireEvent.click(await screen.findByRole("button", { name: "Scans" }));
    fireEvent.click(await screen.findByRole("button", { name: "Quick scan" }));

    expect(
      await screen.findByText(/This scan did not verify every file/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Incomplete coverage/)).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("1")).toBeInTheDocument();
  });

  it("lists quarantined items and renders the restore outcome", async () => {
    jest.mocked(listQuarantine).mockResolvedValue(quarantineFixtures);
    jest.mocked(restoreQuarantine).mockResolvedValue({
      success: true,
      item: {
        ...quarantineFixtures[0],
        restored_at: "2026-10-12T10:00:00.000Z",
        restore_result: "restored and rescanned clean",
      },
    });
    render(<SvsProtectionDashboard />);

    fireEvent.click(await screen.findByRole("button", { name: "Quarantine" }));
    expect(
      await screen.findByText("C:/Users/u/Downloads/sample.exe"),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Restore" }));
    await waitFor(() => expect(restoreQuarantine).toHaveBeenCalledWith("q-1"));
    expect(
      await screen.findByText(/restored and rescanned clean/),
    ).toBeInTheDocument();
  });

  it("sends a typed detection follow-up to the agent and renders the reply, with no command control", async () => {
    jest.mocked(listThreats).mockResolvedValue(threatFixtures);
    jest.mocked(sendAgentMessage).mockResolvedValue({
      session_id: "protection-triage-det-1",
      message:
        "This matches the STAI EICAR test rule; it was blocked before execution.",
      tool_calls: [],
      response_action: null,
    });
    render(<SvsProtectionDashboard />);

    fireEvent.click(await screen.findByRole("button", { name: "AI Agent" }));
    // Detection det-1 (escalated) is auto-selected; its triage header confirms it.
    await screen.findByRole("heading", { name: "STAI-EICAR-TEST" });

    const input = screen.getByRole("textbox", { name: /follow-up question/i });
    fireEvent.change(input, { target: { value: "Is this malware?" } });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));

    await waitFor(() =>
      expect(sendAgentMessage).toHaveBeenCalledWith(
        "protection-triage-det-1",
        "Is this malware?",
        "det-1",
      ),
    );
    expect(
      await screen.findByText(/blocked before execution/),
    ).toBeInTheDocument();

    // The investigation-scoped agent exposes no shell / privileged command control.
    expect(
      screen.queryByRole("button", {
        name: /run|execute|terminal|shell|command/i,
      }),
    ).toBeNull();
    expect(screen.queryByText(/terminal|shell/i)).toBeNull();
  });
});
