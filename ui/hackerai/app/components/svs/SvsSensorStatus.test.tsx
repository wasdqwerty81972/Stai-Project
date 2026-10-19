import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import {
  getSensorRuntimeStatus,
  respondToStaiApproval,
  startSensorMonitoring,
  stopSensorMonitoring,
  type SensorRuntimeStatus,
} from "@/lib/stai-api";
import { SvsSensorStatus } from "./SvsSensorStatus";

jest.mock("@/lib/stai-api", () => ({
  getSensorRuntimeStatus: jest.fn(),
  respondToStaiApproval: jest.fn(),
  startSensorMonitoring: jest.fn(),
  stopSensorMonitoring: jest.fn(),
}));

const status: SensorRuntimeStatus = {
  running: false,
  platform: "windows",
  capabilities: [
    {
      id: 1,
      key: "process_creation",
      name: "Process Creation",
      state: "available",
      source: "Windows Security event log",
      permissions: ["Read Security log"],
    },
    {
      id: 6,
      key: "cross_process_access",
      name: "Cross-Process Access",
      state: "unavailable",
      source: "Sysmon Operational log",
    },
  ],
  registry: [
    {
      id: 1,
      key: "process_creation",
      name: "Process Creation",
      description: "Detects whenever a new program or process starts.",
      category: "Process lifecycle sensors",
      layer: 1,
      kind: "collector",
      platform_support: { windows: "conditional" },
      host_support: "conditional",
      telemetry_source: "Windows Security event 4688",
      shared_collector_id: "windows.security_eventlog",
      required_permissions: ["Read Security event log"],
      event_schema: { id: "svs.normalized_sensor_event.v1", required_fields: [], specific_fields: ["process", "pid"], privacy: "redacted" },
      collection_method: "Shared Windows Event Log reader",
      operational_status: "implemented",
      performance_cost: { class: "low", measured: false },
      test_refs: ["tests/test_sensor_registry.py"],
      coverage_notes: "Audit coverage is unverified.",
      derived_from: [],
      phase1_requested_id: 1,
      phase1_requested_name: "Process Creation",
      runtime_state: "available",
    },
    {
      id: 17,
      key: "process_handle_access",
      name: "Process Handle Access",
      description: "Monitors one process requesting access to another process.",
      category: "Cross-process activity sensors",
      layer: 1,
      kind: "collector",
      platform_support: { windows: "partial" },
      host_support: "partial",
      telemetry_source: "Windows Security event 4656",
      shared_collector_id: "windows.security_eventlog",
      required_permissions: ["Read Security log"],
      event_schema: { id: "svs.normalized_sensor_event.v1", required_fields: [], specific_fields: ["source_pid", "target_pid"], privacy: "redacted" },
      collection_method: "Shared Event Log reader",
      operational_status: "partial",
      performance_cost: { class: "moderate", measured: false },
      test_refs: ["tests/test_sensor_registry.py"],
      coverage_notes: "Partial access evidence only.",
      derived_from: [],
      phase1_requested_id: 6,
      phase1_requested_name: "Cross-Process Access",
      runtime_state: "unavailable",
    },
  ],
  queue: { depth: 2, capacity: 256, dropped: 1, deduplicated: 3 },
  pending_approvals: [],
  privacy: {
    collect_file_paths: false,
    collect_dns_names: false,
    collect_command_lines: false,
  },
};

describe("SvsSensorStatus", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.mocked(getSensorRuntimeStatus).mockResolvedValue(status);
  });

  it("shows source coverage and per-sensor health", async () => {
    render(<SvsSensorStatus />);

    expect(await screen.findByText("Windows monitoring stopped")).toBeInTheDocument();
    expect(screen.getByText("2 Phase 1 mappings · 1 sources readable; audit coverage unverified")).toBeInTheDocument();
    expect(screen.getByText("Queue 2/256 · dropped 1")).toBeInTheDocument();

    fireEvent.click(screen.getByText("Sensor registry (2)"));
    expect(screen.getByText("#1 Process Creation")).toBeInTheDocument();
    expect(screen.getByText("#17 Process Handle Access")).toBeInTheDocument();
    expect(screen.getByText("Phase 1 request #6: Cross-Process Access")).toBeInTheDocument();
    expect(screen.getByText(/Read Security log/)).toBeInTheDocument();
  });

  it("starts passive collection and reflects the returned runtime status", async () => {
    const running = { ...status, running: true };
    jest.mocked(startSensorMonitoring).mockResolvedValue(running);
    render(<SvsSensorStatus />);

    expect(await screen.findByText("Windows monitoring stopped")).toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Start monitoring" }));

    await waitFor(() => expect(startSensorMonitoring).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("Windows monitoring active")).toBeInTheDocument();
    expect(stopSensorMonitoring).not.toHaveBeenCalled();
  });

  it("exposes pending containment decisions and refreshes after approval", async () => {
    const awaiting = {
      ...status,
      pending_approvals: [
        {
          approval_id: "response-1",
          alert_id: "alert-1",
          summary: "Source IP 203.0.113.5 is suspicious",
          severity: "HIGH",
          proposed_actions: ["Block source IP"],
        },
      ],
    };
    jest
      .mocked(getSensorRuntimeStatus)
      .mockResolvedValueOnce(awaiting)
      .mockResolvedValueOnce(status);
    jest.mocked(respondToStaiApproval).mockResolvedValue({ request_id: "response-1", approved: true });
    render(<SvsSensorStatus />);

    expect(await screen.findByText("Containment needs approval")).toBeInTheDocument();
    expect(screen.getByText(/Block source IP/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(respondToStaiApproval).toHaveBeenCalledWith("response-1", true),
    );
    await waitFor(() =>
      expect(screen.queryByText("Containment needs approval")).not.toBeInTheDocument(),
    );
  });
});
