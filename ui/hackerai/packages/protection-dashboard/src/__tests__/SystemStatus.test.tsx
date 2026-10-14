import { render, screen } from "@testing-library/react";
import { SystemStatus } from "../components/SystemStatus";
import type { ProtectionStatus } from "../protection-api";

test("labels readable threat intelligence as advisory and inactive", () => {
  const status = {
    state: "degraded",
    driver_state: "stopped",
    service_state: "running",
    rules_version: "rules-1",
    rules_trusted: true,
    last_scan: null,
    counts: { detected: 0, blocked: 0, quarantined: 0 },
    windows_security: null,
    sensor_coverage: {},
    sensors: null,
    sensor_error: null,
    last_error: null,
    threat_intel: {
      state: "advisory",
      integrity_ok: true,
      block_eligible_records: 12,
      activation: "inactive",
    },
  } as ProtectionStatus;

  render(<SystemStatus status={status} error={null} />);

  expect(screen.getByText("Advisory · 12 eligible; inactive")).toBeInTheDocument();
  expect(screen.getByText(/Feed-based blocking stays inactive/)).toBeInTheDocument();
});


test("shows unavailable threat intelligence without implying protection", () => {
  const status = {
    state: "degraded",
    driver_state: "stopped",
    service_state: "running",
    rules_version: "rules-1",
    last_scan: null,
    counts: { detected: 0, blocked: 0, quarantined: 0 },
    windows_security: null,
    sensor_coverage: {},
    sensors: null,
    sensor_error: null,
    last_error: null,
    threat_intel: {
      state: "unavailable",
      integrity_ok: false,
      block_eligible_records: 0,
      activation: "inactive",
    },
  } as ProtectionStatus;
  render(<SystemStatus status={status} error={null} />);
  expect(screen.getByText("unavailable")).toBeInTheDocument();
});
