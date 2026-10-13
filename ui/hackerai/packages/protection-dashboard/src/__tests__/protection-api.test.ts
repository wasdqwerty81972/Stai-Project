/**
 * @jest-environment jsdom
 * @jest-environment-options {"url":"http://localhost:1420/"}
 */
import { invoke, isTauri } from "@tauri-apps/api/core";
import {
  getScanSchedule,
  isTrustedProtectionContext,
  refreshScanProfile,
  setScanSchedule,
} from "../protection-api";

jest.mock("@tauri-apps/api/core", () => ({
  invoke: jest.fn(),
  isTauri: jest.fn(() => false),
}));

test("allows_only_the_bundled_or_dedicated_loopback_tauri_origin", () => {
  expect(isTrustedProtectionContext({
    isTauri: true,
    protocol: "http:",
    hostname: "tauri.localhost",
    port: "",
  })).toBe(true);
  expect(isTrustedProtectionContext({
    isTauri: true,
    protocol: "http:",
    hostname: "127.0.0.1",
    port: "1420",
  })).toBe(true);
  expect(isTrustedProtectionContext({
    isTauri: true,
    protocol: "https:",
    hostname: "hackerai.co",
    port: "",
  })).toBe(false);
  expect(isTrustedProtectionContext({
    isTauri: false,
    protocol: "http:",
    hostname: "localhost",
    port: "1420",
  })).toBe(false);
});

test("routes_schedule_requests_only_through_the_local_tauri_bridge", async () => {
  jest.mocked(isTauri).mockReturnValue(true);
  jest.mocked(invoke).mockResolvedValue({} as never);
  await refreshScanProfile();
  await getScanSchedule();
  await setScanSchedule({
    enabled: true,
    cadence: "weekly",
    localTime: "10:30",
    daysOfWeek: ["mon"],
  });

  expect(invoke).toHaveBeenNthCalledWith(1, "refresh_protection_scan_profile", undefined);
  expect(invoke).toHaveBeenNthCalledWith(2, "get_protection_scan_schedule", undefined);
  expect(invoke).toHaveBeenNthCalledWith(3, "set_protection_scan_schedule", {
    enabled: true,
    cadence: "weekly",
    localTime: "10:30",
    daysOfWeek: ["mon"],
  });
});
