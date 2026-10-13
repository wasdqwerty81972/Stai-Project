import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "../App";
import {
  cancelScan,
  getAgentHistory,
  getProtectionStatus,
  getScanSchedule,
  getProtectionTriage,
  getScan,
  listQuarantine,
  listThreats,
  requestProtectionTriage,
  restoreQuarantine,
  refreshScanProfile,
  sendAgentMessage,
  setScanSchedule,
  startScan,
} from "../protection-api";

jest.mock("../protection-api", () => ({
  cancelScan: jest.fn(),
  getAgentHistory: jest.fn(),
  getProtectionStatus: jest.fn(),
  getScanSchedule: jest.fn(),
  getProtectionTriage: jest.fn(),
  getScan: jest.fn(),
  listQuarantine: jest.fn(),
  listThreats: jest.fn(),
  requestProtectionTriage: jest.fn(),
  restoreQuarantine: jest.fn(),
  refreshScanProfile: jest.fn(),
  sendAgentMessage: jest.fn(),
  setScanSchedule: jest.fn(),
  startScan: jest.fn(),
}));

const status = {
  state: "active",
  driver_state: "running",
  service_state: "running",
  rules_version: "rules-2026.10",
  last_scan: "2026-10-11T15:30:00Z",
  counts: { detected: 4, blocked: 2, quarantined: 1 },
  windows_security: {
    registered_av_provider: "Microsoft Defender Antivirus",
    defender_mode: "enabled",
    query_available: true,
  },
  sensor_coverage: { file_filter: "covered" },
  last_error: null,
};

const threats = [
  {
    detection_id: "det-1",
    action: "block",
    confidence: "high",
    severity: "critical",
    file_type: ".exe",
    size_bytes: 1024,
    file_path: "C:\\Users\\Public\\invoice.exe",
    created_at: "2026-10-11T15:00:00Z",
    triage_enqueued: true,
    summary: "A verified test rule matched this file.",
  },
  {
    detection_id: "det-2",
    action: "allow",
    confidence: "low",
    severity: "medium",
    file_type: ".dll",
    size_bytes: 2048,
    file_path: "C:\\Temp\\sample.dll",
    created_at: "2026-10-11T14:00:00Z",
    triage_enqueued: false,
    summary: "Observed by a review-only rule.",
  },
];

const quarantine = [
  {
    item_id: "q-1",
    original_path: "C:\\Users\\Public\\invoice.exe",
    sha256: "a".repeat(64),
    rule_id: "hash-1",
    rule_version: "rules-2026.10",
    action_result: "moved",
    detection_id: "det-1",
    created_at: "2026-10-11T15:00:00Z",
    restored_at: null,
    restore_result: null,
  },
];

const triage = {
  triage_id: "session-det-1",
  detection_id: "det-1",
  summary: "The file matched a high-confidence local hash rule.",
  recommendations: ["Keep the item quarantined while you verify its source."],
  state: "complete",
  created_at: "2026-10-11T15:05:00Z",
  updated_at: "2026-10-11T15:05:00Z",
};

const scan = {
  job_id: "job-1",
  scope: "quick",
  state: "running",
  files_scanned: 12,
  files_total: 48,
  detections: 1,
  errors: 0,
  started_at: "2026-10-12T09:00:00Z",
  completed_at: null,
  error_message: null,
};

function setupDefaults() {
  jest.mocked(getProtectionStatus).mockResolvedValue(status as never);
  jest.mocked(getScanSchedule).mockResolvedValue({ configured: false, enabled: false } as never);
  jest.mocked(listThreats).mockResolvedValue(threats as never);
  jest.mocked(listQuarantine).mockResolvedValue(quarantine as never);
  jest.mocked(getProtectionTriage).mockResolvedValue(triage as never);
  jest.mocked(getAgentHistory).mockResolvedValue({
    session_id: "session-det-1",
    messages: [],
  } as never);
  jest.mocked(sendAgentMessage).mockResolvedValue({
    session_id: "session-det-1",
    message: "The stored evidence shows a local hash match.",
    tool_calls: [],
    response_action: null,
  } as never);
  jest.mocked(startScan).mockResolvedValue(scan as never);
  jest.mocked(refreshScanProfile).mockResolvedValue({
    ready: true,
    refreshed_at: "2026-10-13T09:00:00",
    folders: ["desktop", "downloads", "startup"],
  } as never);
  jest.mocked(setScanSchedule).mockResolvedValue({
    configured: true,
    enabled: true,
    cadence: "weekly",
    local_time: "10:30",
    days_of_week: ["mon"],
    last_run_date: null,
    last_job_id: null,
    last_result: null,
    next_run_local: "2026-10-19T10:30:00",
  } as never);
  jest.mocked(getScan).mockResolvedValue(scan as never);
  jest.mocked(cancelScan).mockResolvedValue(undefined as never);
  jest.mocked(requestProtectionTriage).mockResolvedValue(triage as never);
  jest.mocked(restoreQuarantine).mockResolvedValue({
    success: true,
    item: {
      ...quarantine[0],
      restored_at: "2026-10-12T09:00:00Z",
      restore_result: "restored",
    },
    error: null,
  } as never);
}

beforeEach(() => {
  jest.clearAllMocks();
  setupDefaults();
});

test("renders_degraded_state_without_fake_counts", async () => {
  jest.mocked(getProtectionStatus).mockResolvedValue({
    ...status,
    state: "degraded",
    counts: null,
    last_error: "Rule package is unavailable.",
  } as never);

  render(<App />);

  expect(await screen.findByText("Protection needs attention")).toBeInTheDocument();
  expect(screen.getByText("Rule package is unavailable.")).toBeInTheDocument();
  await userEvent.setup().click(await screen.findByRole("button", { name: "Antivirus" }));
  expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(3);
  expect(screen.queryByText("0 blocked")).not.toBeInTheDocument();
  expect(screen.queryByText("Protected and up to date")).not.toBeInTheDocument();
});

test("shows_last_scan_rule_version_and_agent_escalations", async () => {
  const user = userEvent.setup();
  render(<App />);

  await user.click(await screen.findByRole("button", { name: "Antivirus" }));
  expect(await screen.findByText("rules-2026.10")).toBeInTheDocument();
  expect(screen.getByText(new Date(status.last_scan).toLocaleString())).toBeInTheDocument();
  const reviewQueue = screen.getByText("AI review queue").closest("article");
  expect(reviewQueue).not.toBeNull();
  expect(within(reviewQueue as HTMLElement).getByText("1")).toBeInTheDocument();
  expect(within(reviewQueue as HTMLElement).getByText("Queued for AI review")).toBeInTheDocument();
});

test("starts_and_tracks_quick_scan", async () => {
  const user = userEvent.setup();
  jest.mocked(getScan).mockResolvedValue({
    ...scan,
    state: "completed",
    files_scanned: 48,
  } as never);
  render(<App />);

  await user.click(await screen.findByRole("button", { name: "Quick Scan" }));

  expect(startScan).toHaveBeenCalledWith("quick");
  await waitFor(() => expect(getScan).toHaveBeenCalledWith("job-1"));
  expect(await screen.findByText(/48 of 48 files scanned/i)).toBeInTheDocument();
});

test("saves_a_weekly_schedule_after_refreshing_the_enrolled_user_profile", async () => {
  const user = userEvent.setup();
  render(<App />);

  await user.click(await screen.findByRole("button", { name: "Scans" }));
  expect(await screen.findByRole("heading", { name: "Scheduled Quick Scan" })).toBeInTheDocument();
  expect(getScanSchedule).toHaveBeenCalledTimes(1);

  await user.selectOptions(screen.getByRole("combobox", { name: "Frequency" }), "weekly");
  await user.click(screen.getByRole("checkbox", { name: "Monday" }));
  fireEvent.change(screen.getByLabelText("Local time"), { target: { value: "10:30" } });
  await user.click(screen.getByRole("checkbox", { name: "Enable scheduled Quick Scan" }));
  await user.click(screen.getByRole("button", { name: "Save schedule" }));

  await waitFor(() => expect(setScanSchedule).toHaveBeenCalledWith({
    enabled: true,
    cadence: "weekly",
    localTime: "10:30",
    daysOfWeek: ["mon"],
  }));
  expect(refreshScanProfile).toHaveBeenCalledTimes(1);
  expect(refreshScanProfile.mock.invocationCallOrder[0]).toBeLessThan(
    setScanSchedule.mock.invocationCallOrder[0],
  );
  expect(await screen.findByText(/Next run/i)).toBeInTheDocument();
});

test("reports_schedule_unavailable_without_marking_it_enabled", async () => {
  const user = userEvent.setup();
  jest.mocked(getScanSchedule).mockRejectedValue(new Error("enrolled dashboard user required"));
  render(<App />);

  await user.click(await screen.findByRole("button", { name: "Scans" }));

  expect(await screen.findByRole("alert")).toHaveTextContent("enrolled dashboard user required");
  expect(screen.getByRole("button", { name: "Save schedule" })).toBeDisabled();
});

test("shows_distinct_detection_block_and_quarantine_totals", async () => {
  const user = userEvent.setup();
  render(<App />);

  await user.click(await screen.findByRole("button", { name: "Antivirus" }));
  const totals = await screen.findByRole("region", { name: "Protection totals" });
  expect(within(totals).getByRole("article", { name: /^Detected:/ })).toHaveTextContent("4");
  expect(within(totals).getByRole("article", { name: /^Blocked:/ })).toHaveTextContent("2");
  expect(within(totals).getByRole("article", { name: /^Quarantined:/ })).toHaveTextContent("1");
});

test("renders_quarantine_restore_result", async () => {
  const user = userEvent.setup();
  render(<App />);

  await user.click(await screen.findByRole("button", { name: "Quarantine" }));
  expect(await screen.findByText("C:\\Users\\Public\\invoice.exe")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Restore item" }));

  expect(restoreQuarantine).toHaveBeenCalledWith("q-1");
  expect(await screen.findByText("Restore completed. The item was rescanned before it was returned.")).toBeInTheDocument();
});

test("sends_typed_detection_follow_up_and_renders_agent_reply", async () => {
  const user = userEvent.setup();
  render(<App />);

  await user.click(await screen.findByRole("button", { name: "AI Agent" }));
  expect(await screen.findByText(triage.summary)).toBeInTheDocument();
  expect(screen.getByText("Keep the item quarantined while you verify its source.")).toBeInTheDocument();

  await user.type(screen.getByRole("textbox", { name: "Ask about this detection" }), "Why was this blocked?");
  await user.click(screen.getByRole("button", { name: "Send question" }));

  expect(sendAgentMessage).toHaveBeenCalledWith(
    "session-det-1",
    "Why was this blocked?",
    "det-1",
  );
  expect(await screen.findByText("The stored evidence shows a local hash match.")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /shell|terminal|run command/i })).not.toBeInTheDocument();
});

test("renders_service_unavailable_on_bridge_error", async () => {
  jest.mocked(getProtectionStatus).mockRejectedValue(new Error("protection service unavailable"));
  jest.mocked(listThreats).mockRejectedValue(new Error("protection service unavailable"));
  jest.mocked(listQuarantine).mockRejectedValue(new Error("protection service unavailable"));
  render(<App />);

  expect(await screen.findByText("Protection service unavailable")).toBeInTheDocument();
  expect(screen.queryByText("Protected and up to date")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Retry connection" })).toBeInTheDocument();
});

test("keeps_navigation_and_scan_action_keyboard_reachable", async () => {
  const user = userEvent.setup();
  render(<App />);

  const home = await screen.findByRole("button", { name: "Home" });
  home.focus();
  await user.keyboard("{Enter}");
  expect(home).toHaveAttribute("aria-current", "page");

  const scan = screen.getByRole("button", { name: "Quick Scan" });
  scan.focus();
  await user.keyboard("{Enter}");
  expect(startScan).toHaveBeenCalledWith("quick");
});
