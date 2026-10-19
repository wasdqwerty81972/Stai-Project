import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { DeviceActivityView } from "../components/DeviceActivityView";
import { getDeviceActivity, type DeviceActivity } from "../protection-api";

jest.mock("../protection-api", () => ({ getDeviceActivity: jest.fn() }));

const snapshot: DeviceActivity = {
  observed_at: "2026-10-14T09:00:00Z", cpu_count: 8, errors: [],
  database: { available: true, demo: true, version: "demo-1", rule_count: 1, coverage: "Demo rules only" },
  network: { download_bytes_sec: 2048, upload_bytes_sec: 1024, bytes_received: 2000, bytes_sent: 1000 },
  processes: [
    { pid: 10, name: "packed.exe", username: "user", exe: "C:\\packed.exe", cpu_percent: 12, memory_bytes: 2048, status: "running", assessment: { classification: "needs_review", entropy: 7.8, reason: "High entropy; no rule match", rule_id: null, rule_version: "demo-1", sha256: null, sampled_bytes: 1024 } },
    { pid: 20, name: "Process 20", username: null, exe: null, cpu_percent: null, memory_bytes: null, status: "unknown", visibility_errors: ["Executable path restricted"], assessment: { classification: "unavailable", entropy: null, reason: "Executable is inaccessible", rule_id: null, rule_version: null, sha256: null, sampled_bytes: 0 } },
  ],
  connections: [{ pid: 10, process_name: "packed.exe", protocol: "TCP", local_address: "127.0.0.1:5000", remote_address: "1.2.3.4:443", state: "ESTABLISHED" }],
};

beforeEach(() => { jest.useFakeTimers(); jest.mocked(getDeviceActivity).mockReset(); });
afterEach(() => { jest.useRealTimers(); });

test("shows all tasks, review evidence and restricted tasks without claiming they are safe", async () => {
  jest.mocked(getDeviceActivity).mockResolvedValue(snapshot);
  render(<DeviceActivityView mode="processes" />);
  await act(async () => {});
  const table = within(screen.getByRole("table"));
  expect(table.getByText("packed.exe")).toBeInTheDocument();
  expect(table.getByText("Process 20")).toBeInTheDocument();
  expect(table.getByText("Needs review")).toBeInTheDocument();
  expect(table.getByText("Not assessed")).toBeInTheDocument();
  fireEvent.change(screen.getByRole("textbox", { name: "Search device activity" }), { target: { value: "20" } });
  expect(table.queryByText("packed.exe")).not.toBeInTheDocument();
  expect(table.getByText("Process 20")).toBeInTheDocument();
  fireEvent.click(table.getByRole("button", { name: /Process 20/ }));
  expect(screen.getByText("Executable path restricted")).toBeInTheDocument();
});

test("shows_active_service_rules_without_reporting_an_unknown_count_as_zero", async () => {
  jest.mocked(getDeviceActivity).mockResolvedValue({
    ...snapshot,
    database: {
      available: true,
      demo: true,
      version: "svs-eicar-demo-1",
      rule_count: null,
      coverage: "The service has the signed package; local matching is unavailable.",
      analysis_available: false,
      active_in_protection_service: true,
    },
  });

  render(<DeviceActivityView mode="processes" />);
  await act(async () => {});

  expect(screen.getByText("svs-eicar-demo-1 · count not reported")).toBeInTheDocument();
  expect(screen.getByText("The service has the signed package; local matching is unavailable.")).toBeInTheDocument();
});

test("keeps the last task snapshot visible during a transient disconnect and reconnects", async () => {
  jest.mocked(getDeviceActivity).mockResolvedValueOnce(snapshot).mockRejectedValueOnce(new Error("API offline")).mockResolvedValue(snapshot);
  render(<DeviceActivityView mode="network" />);
  await act(async () => {});
  expect(screen.getByText("1.2.3.4:443")).toBeInTheDocument();
  await act(async () => { jest.advanceTimersByTime(10000); });
  expect(screen.getByRole("alert")).toHaveTextContent("last successful snapshot");
  expect(screen.getByText("1.2.3.4:443")).toBeInTheDocument();
  await act(async () => { jest.advanceTimersByTime(10000); });
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

test("waits ten seconds between activity reads", async () => {
  jest.mocked(getDeviceActivity).mockResolvedValue(snapshot);
  render(<DeviceActivityView mode="processes" />);
  await act(async () => {});
  expect(getDeviceActivity).toHaveBeenCalledTimes(1);
  await act(async () => { jest.advanceTimersByTime(9999); });
  expect(getDeviceActivity).toHaveBeenCalledTimes(1);
  await act(async () => { jest.advanceTimersByTime(1); });
  expect(getDeviceActivity).toHaveBeenCalledTimes(2);
});

test("a recycled PID does not inherit selected process evidence", async () => {
  const original = { ...snapshot.processes[0], process_identity: "10:old", assessment: { ...snapshot.processes[0].assessment, reason: "Original process evidence" } };
  const recycled = { ...original, process_identity: "10:new", name: "replacement.exe", assessment: { ...original.assessment, reason: "Replacement process evidence" } };
  jest.mocked(getDeviceActivity).mockResolvedValueOnce({ ...snapshot, processes: [original] }).mockResolvedValue({ ...snapshot, processes: [recycled] });
  render(<DeviceActivityView mode="processes" />);
  await act(async () => {});
  fireEvent.click(within(screen.getByRole("table")).getByRole("button", { name: /packed.exe/ }));
  expect(screen.getByText("Original process evidence")).toBeInTheDocument();
  await act(async () => { jest.advanceTimersByTime(10000); });
  expect(screen.queryByText("Replacement process evidence")).not.toBeInTheDocument();
  expect(screen.queryByText("Original process evidence")).not.toBeInTheDocument();
});

test("a recycled socket owner cannot borrow process evidence by PID", async () => {
  jest.mocked(getDeviceActivity).mockResolvedValue({ ...snapshot,
    processes: [{ ...snapshot.processes[0], process_identity: "10:original" }],
    connections: [{ ...snapshot.connections[0], process_identity: null, ownership_status: "pid_reused" }],
  });
  render(<DeviceActivityView mode="network" />);
  await act(async () => {});
  const table = within(screen.getByRole("table"));
  expect(table.getByText("Owner unavailable")).toBeInTheDocument();
  expect(table.queryByText("Needs review")).not.toBeInTheDocument();
});

test("does_not_call_an_unmatchable_database_a_signed_rule_database", async () => {
  jest.mocked(getDeviceActivity).mockResolvedValue({
    ...snapshot,
    database: {
      available: true,
      demo: false,
      version: "svs-rules-2026.10",
      rule_count: 420,
      coverage: "The protection service reports this signed package as active.",
      analysis_available: false,
      active_in_protection_service: true,
    },
  });

  render(<DeviceActivityView mode="processes" />);
  await act(async () => {});

  expect(screen.getByText("Rule matching unavailable")).toBeInTheDocument();
  expect(screen.queryByText("Signed rule database")).not.toBeInTheDocument();
  expect(screen.getByText(/cannot read its rule contents/)).toBeInTheDocument();
});

test("unmeasured_entropy_does_not_render_a_zero_value_meter", async () => {
  jest.mocked(getDeviceActivity).mockResolvedValue(snapshot);
  render(<DeviceActivityView mode="processes" />);
  await act(async () => {});

  // Only the one process with a measured score may draw a meter.
  expect(screen.getAllByRole("meter")).toHaveLength(1);
  expect(screen.getByText("Entropy not measured")).toBeInTheDocument();
});

test("caps_the_rendered_process_table_and_discloses_the_cap", async () => {
  const many = Array.from({ length: 180 }, (_, index) => ({
    ...snapshot.processes[0],
    pid: 1000 + index,
    process_identity: `${1000 + index}:x`,
    name: `proc-${index}.exe`,
  }));
  jest.mocked(getDeviceActivity).mockResolvedValue({ ...snapshot, processes: many });

  render(<DeviceActivityView mode="processes" />);
  await act(async () => {});

  expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(151); // header + 150
  expect(screen.getByText(/Showing the first 150 of 180 processes/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Show all 180" }));
  expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(181);
});
