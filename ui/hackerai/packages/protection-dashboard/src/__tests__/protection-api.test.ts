import { isTrustedProtectionContext } from "../protection-api";

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
