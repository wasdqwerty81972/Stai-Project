import { act, fireEvent, render, screen } from "@testing-library/react";
import { getProcessConnections, getProcessDetails, scanProcessExecutable, setProcessMonitorProfile, subscribeToProcessMonitor, type ProcessMonitorEvent } from "@/lib/stai-protection-api";
import { ProcessMonitorView } from "./ProcessMonitorView";

jest.mock("@/lib/stai-protection-api", () => ({
  getProcessConnections: jest.fn(),
  getProcessDetails: jest.fn(),
  scanProcessExecutable: jest.fn(),
  setProcessMonitorProfile: jest.fn(),
  subscribeToProcessMonitor: jest.fn(),
}));

const processFixture = {
  pid: 4120,
  instance_id: "4120:0x1",
  identity_verified: true,
  name: "worker.exe",
  status: "running",
  cpu_percent: 7.2,
  memory_bytes: 2048,
};

let emit: (event: ProcessMonitorEvent) => void;

beforeEach(() => {
  jest.mocked(getProcessDetails).mockResolvedValue({ ...processFixture, exe: "C:/worker.exe" });
  jest.mocked(scanProcessExecutable).mockResolvedValue({
    instance_id: processFixture.instance_id, pid: processFixture.pid, executable: "C:/worker.exe",
    status: "clean", action: "allow", rule_id: null, rule_version: "demo-1",
    sha256: "a".repeat(64), reason: "No rule matched", reason_code: "no_match",
    detection_id: null, quarantine: null,
  });
  jest.mocked(getProcessConnections).mockResolvedValue({ instance_id: processFixture.instance_id, available: true, connections: [] });
  jest.mocked(setProcessMonitorProfile).mockResolvedValue({
    state: "running", event_source: "degraded", dropped_events: 0,
    sample_interval_seconds: 1, reconcile_interval_seconds: 2, sampling_profile: "high",
  });
  jest.mocked(subscribeToProcessMonitor).mockImplementation((onEvent, onState) => {
    emit = onEvent;
    onState("connected");
    onEvent({
      type: "snapshot",
      sequence: 1,
      observed_at: "2026-10-14T12:00:00Z",
      processes: [processFixture],
      health: {
        state: "running",
        event_source: "degraded",
        event_source_name: "Win32_ProcessTrace",
        event_source_error: "Access denied",
        dropped_events: 0,
        sample_interval_seconds: 1,
        reconcile_interval_seconds: 5,
      },
    });
    return jest.fn();
  });
});

afterEach(() => jest.clearAllMocks());

describe("ProcessMonitorView", () => {
  it("adds and removes processes from stream events without refreshing", async () => {
    render(<ProcessMonitorView />);
    expect(await screen.findByText("worker.exe")).toBeInTheDocument();
    await act(async () => emit({
      type: "process_added", sequence: 2,
      process: { ...processFixture, pid: 99, instance_id: "99:0x2", name: "new-app.exe" },
      instance_id: "99:0x2",
    }));
    expect(screen.getByText("new-app.exe")).toBeInTheDocument();
    await act(async () => emit({ type: "process_removed", sequence: 3, instance_id: "99:0x2" }));
    expect(screen.queryByText("new-app.exe")).not.toBeInTheDocument();
  });

  it("updates measurements while preserving the selected instance", async () => {
    render(<ProcessMonitorView />);
    fireEvent.click(await screen.findByRole("button", { name: "Show details for worker.exe" }));
    await act(async () => emit({
      type: "process_metrics_updated", sequence: 2, instance_id: processFixture.instance_id,
      process: { ...processFixture, cpu_percent: 24.4, memory_bytes: 4096 },
    }));
    expect(screen.getByRole("region", { name: "Details for worker.exe" })).toBeInTheDocument();
    expect(screen.getByText("24.4%", { selector: "td" })).toBeInTheDocument();
    expect(screen.getByText("4.0 KB", { selector: "td" })).toBeInTheDocument();
  });

  it("buffers display updates while paused and applies them on resume", async () => {
    render(<ProcessMonitorView />);
    fireEvent.click(await screen.findByRole("button", { name: "Pause display" }));
    await act(async () => emit({
      type: "process_added", sequence: 2,
      process: { ...processFixture, pid: 777, instance_id: "777:0x3", name: "paused-app.exe" },
      instance_id: "777:0x3",
    }));
    expect(screen.queryByText("paused-app.exe")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Resume display" }));
    expect(screen.getByText("paused-app.exe")).toBeInTheDocument();
  });

  it("shows reconciliation and inaccessible telemetry honestly", async () => {
    render(<ProcessMonitorView />);
    expect(await screen.findByText("Snapshot reconciliation")).toBeInTheDocument();
    expect(screen.getByText(/uses periodic reconciliation/i)).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "Not assessed" })).toBeInTheDocument();
  });

  it("distinguishes service telemetry from a local fallback and an unavailable monitor", async () => {
    const setHealth = (source: "protection_service" | "local_fallback" | "unavailable", source_error?: string) => {
      emit({
        type: "health", sequence: 2,
        health: {
          state: source === "unavailable" ? "stopped" : "running",
          source,
          source_error,
          event_source: "degraded",
          dropped_events: 0,
          sample_interval_seconds: 5,
          reconcile_interval_seconds: 5,
        },
      });
    };
    render(<ProcessMonitorView />);
    await screen.findByText("worker.exe");
    await act(async () => setHealth("protection_service"));
    expect(screen.getByText("Protection service · live telemetry")).toBeInTheDocument();
    await act(async () => setHealth("local_fallback", "pipe timeout"));
    expect(screen.getByText("Local process fallback")).toBeInTheDocument();
    expect(screen.getByText(/not connected.*pipe timeout/i)).toBeInTheDocument();
    await act(async () => setHealth("unavailable", "service and local collectors stopped"));
    expect(screen.getByText("Process monitor unavailable")).toBeInTheDocument();
  });

  it("changes the real monitor sampling profile through the local API", async () => {
    render(<ProcessMonitorView />);
    await act(async () => {
      fireEvent.change(await screen.findByRole("combobox", { name: "Sampling frequency" }), { target: { value: "high" } });
      await Promise.resolve();
    });
    expect(setProcessMonitorProfile).toHaveBeenCalledWith("high");
  });

  it("groups processes by their observed parent and filters by scan classification", async () => {
    const child = { ...processFixture, pid: 4121, instance_id: "4121:0x2", name: "child.exe", parent_pid: 4120 };
    jest.mocked(subscribeToProcessMonitor).mockImplementation((onEvent, onState) => {
      emit = onEvent;
      onState("connected");
      onEvent({
        type: "snapshot", sequence: 1, observed_at: "2026-10-14T12:00:00Z",
        processes: [{ ...processFixture, parent_pid: 4 }, child],
        health: { state: "running", event_source: "degraded", dropped_events: 0, sample_interval_seconds: 5, reconcile_interval_seconds: 5 },
      });
      return jest.fn();
    });
    render(<ProcessMonitorView />);
    expect(await screen.findByText("worker.exe")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: "Group by parent" }));
    expect(screen.getByText("Parent 4120")).toBeInTheDocument();
    expect(screen.getByText("Parent 4")).toBeInTheDocument();
    fireEvent.change(screen.getByRole("combobox", { name: "Filter by risk" }), { target: { value: "detected" } });
    expect(screen.getByText(/No accessible processes match/)).toBeInTheDocument();
  });

  it("sorts on request and holds the chosen order when live sorting is off", async () => {
    const high = { ...processFixture, pid: 10, instance_id: "10:0x1", name: "a-high.exe", cpu_percent: 80 };
    const low = { ...processFixture, pid: 11, instance_id: "11:0x2", name: "z-low.exe", cpu_percent: 1 };
    jest.mocked(subscribeToProcessMonitor).mockImplementation((onEvent, onState) => {
      emit = onEvent;
      onState("connected");
      onEvent({ type: "snapshot", sequence: 1, observed_at: "2026-10-14T12:00:00Z", processes: [low, high], health: { state: "running", event_source: "degraded", dropped_events: 0, sample_interval_seconds: 5, reconcile_interval_seconds: 5 } });
      return jest.fn();
    });
    render(<ProcessMonitorView />);
    await screen.findByText("a-high.exe");
    fireEvent.change(screen.getByRole("combobox", { name: "Sort processes by" }), { target: { value: "cpu_percent" } });
    const processRows = screen.getAllByRole("row").slice(1);
    expect(processRows[0]).toHaveTextContent("a-high.exe");
    expect(processRows[1]).toHaveTextContent("z-low.exe");
    await act(async () => emit({ type: "process_metrics_updated", sequence: 2, instance_id: high.instance_id, process: { ...high, cpu_percent: 0 } }));
    expect(screen.getAllByRole("row").slice(1)[0]).toHaveTextContent("a-high.exe");
  });

  it("updates the executable entropy score and automatic scan status from live telemetry", async () => {
    render(<ProcessMonitorView />);
    await screen.findByText("worker.exe");
    await act(async () => emit({
      type: "process_metrics_updated", sequence: 2, instance_id: processFixture.instance_id,
      process: { ...processFixture, entropy_score: 7.81, entropy_state: "available", entropy_source: "sampled executable file bytes", entropy_threshold: 7.2, auto_scan_status: "scanning" },
    }));
    expect(screen.getByText("7.81")).toBeInTheDocument();
    expect(screen.getByText("7.81").closest("td")).toHaveClass("text-red-300");
    expect(screen.getByText("Scan pending")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Show details for worker.exe" }));
    expect(screen.getByText(/7.81 bits per byte/)).toBeInTheDocument();
  });

  it("scans the selected executable and attaches the returned evidence to its instance", async () => {
    render(<ProcessMonitorView />);
    fireEvent.click(await screen.findByRole("button", { name: "Show details for worker.exe" }));
    fireEvent.click(await screen.findByRole("button", { name: "Scan executable" }));
    expect(scanProcessExecutable).toHaveBeenCalledWith(processFixture.instance_id);
    expect(await screen.findByText(/Executable scan: clean/)).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "No known match" })).toBeInTheDocument();
  });
});
