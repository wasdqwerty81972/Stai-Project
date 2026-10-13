# SVS Cyber Real Protection Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing user-mode scanner and dashboard usable in the Windows Tauri app while reporting the limited rule coverage and unavailable service/driver accurately.

**Architecture:** Keep the Tauri protection pipe as the primary client when it is reachable. Add one typed loopback HTTP adapter for the local scanner API and use it from browser mode or as Tauri's fallback when the pipe is unavailable. The API verifies rules against the pinned repository key and reports scanner/rules/service/driver as separate capabilities.

**Tech Stack:** Python, FastAPI, pytest, React, TypeScript, Vite, Jest, Tauri 2, Rust.

**Spec:** `docs/superpowers/specs/2026-10-14-demo-reliability-design.md`

## Global Constraints

- Keep HTTP traffic bound to loopback and allow only the dashboard's exact local origins.
- Verify rule manifests with the pinned `trusted-rules.pub`; never trust an editable adjacent public key.
- Label the bundled `svs-eicar-demo-1` package as test-only and limited to the EICAR test file.
- Keep local user-mode scanner status separate from Windows service and minifilter driver status.
- Use harmless inert markers in automated tests; do not install or execute malware.
- Scheduled scans remain explicitly unavailable in local API mode unless the Windows service is reachable.
- The AI Agent sidebar integration with the existing `StaiChatWorkspace` is a separate follow-up after this plan.

## Review Focus

- Partial or invalid installed rule files must fail closed and must not silently fall back to the EICAR package.
- A Tauri named-pipe error must switch the client to the loopback API once; later operations must use the same selected adapter.
- HTTP write requests from an unapproved origin must not trigger scans, restores, or agent actions.
- A healthy API with unavailable scanner/rules must stay degraded in the dashboard.
- A completed scan must refresh threat and quarantine data so the displayed dashboard reflects the stored result.

---

### Task 1: Verify rules against the pinned key and report real component status

**Files:**
- Modify: `ui/api_server.py`
- Modify: `cyber_os/protection/windows_service.py`
- Modify: `ui/hackerai/packages/desktop/src-tauri/src/protection_bridge.rs`
- Test: `tests/test_windows_protection_api.py`
- Test: `tests/test_windows_protection_service_lifecycle.py`
- Test: `ui/hackerai/packages/desktop/src-tauri/src/protection_bridge.rs` (Rust unit tests)

**Interfaces:**
- Add `_load_protection_rules(data_dir: Path) -> tuple[RuleSet, bool, str | None, str]` in `ui/api_server.py`, returning rules, trust state, diagnostic, and scope (`installed`, `test-only-eicar`, or `unavailable`).
- Extend the protection status JSON and Rust/TypeScript status types with `scanner_state`, `rules_scope`, and `rules_trust_established`; preserve the existing `service_state` and `driver_state` fields.
- A local API scanner reports `scanner_state="ready"` only after the real scanner and store initialize; it does not report a Windows service or driver as running.

- [ ] **Step 1: Add failing rules, status, and fail-closed tests**

Add tests named `test_missing_installed_package_loads_pinned_eicar_rules_as_test_only`, `test_partial_installed_package_does_not_fall_back_to_demo_rules`, `test_invalid_installed_signature_reports_degraded_status`, and `test_local_scanner_status_does_not_claim_service_or_driver`. Assert the bundled version is `svs-eicar-demo-1`, the pinned key at `cyber_os/protection/resources/trusted-rules.pub` establishes trust, the scope is `test-only-eicar`, and partial/invalid installed packages remain unavailable or degraded. Assert local scanner readiness is distinct from Windows service and driver states.

- [ ] **Step 2: Run the API tests and confirm the expected failures**

Run: `python -m pytest -q tests/test_windows_protection_api.py`
Expected: the new cases fail because the API currently creates `dev-empty` rules when installed files are absent and does not return the required component status contract.

- [ ] **Step 3: Implement the pinned rules loader and explicit status fields**

Use the bundled resource manifest only when no installed manifest or signature exists. Verify installed manifests against `trusted-rules.pub`. Treat partial files, invalid signatures, or missing trust material as unavailable/degraded. Keep `service_state` and `driver_state` distinct from the local scanner state. Pass the same status contract through `ProtectionServiceHost.get_status` and the Rust bridge.

- [ ] **Step 4: Run backend regression tests**

Run: `python -m pytest -q tests/test_windows_protection_api.py tests/test_windows_protection_service_lifecycle.py tests/test_windows_protection_scanner.py tests/test_windows_protection_demo_rules.py`
Expected: all pass; scanner tests include the existing YARA-failure/SHA-256-block regression.

- [ ] **Step 5: Commit**

Commit as `fix: report trusted protection readiness accurately`.

### Task 2: Add the loopback API adapter and keep dashboard data current

**Files:**
- Modify: `ui/hackerai/packages/protection-dashboard/src/protection-api.ts`
- Modify: `ui/hackerai/packages/protection-dashboard/src/App.tsx`
- Modify: `ui/api_server.py` (local-origin allowlist for Tauri HTTP fallback)
- Modify: `ui/hackerai/packages/desktop/src-tauri/tauri.conf.json` (loopback API access in CSP)
- Test: `ui/hackerai/packages/protection-dashboard/src/__tests__/protection-api.test.ts`
- Test: `ui/hackerai/packages/protection-dashboard/src/__tests__/App.test.tsx`
- Test: `tests/test_windows_protection_api.py`

**Interfaces:**
- Keep existing exported client functions and their return types.
- Resolve a single backend mode (`tauri` or `http`) on first status request; cache the in-flight resolution so simultaneous dashboard loads use the same backend. Reset it after a failed initialization so a later refresh can retry.
- HTTP mode uses `VITE_PROTECTION_API_BASE_URL` (default `http://127.0.0.1:6764`) and the existing FastAPI routes for status, scans, threats, triage, agent conversations/messages, quarantine, and restore.
- In HTTP mode, `getScanSchedule` and `setScanSchedule` reject with a clear Windows-service-required error instead of returning fabricated schedule state.

- [ ] **Step 1: Add failing API client and CORS tests**

Test that browser mode issues the expected method/path/body for status, scan start/progress/cancel, threats, triage, agent history/message, quarantine, and restore. Test that an unavailable Tauri status command selects HTTP once and that later calls use HTTP. Test schedule operations return the service-required error. Add API tests that allow the exact Tauri origin and reject untrusted browser origins for write requests.

- [ ] **Step 2: Run the focused frontend tests and confirm failure**

Run from `ui/hackerai`: `node node_modules/jest/bin/jest.js --runInBand packages/protection-dashboard/src/__tests__/protection-api.test.ts`
Expected: FAIL because the current client only accepts Tauri contexts and invokes commands directly.

- [ ] **Step 3: Implement the typed HTTP adapter and origin policy**

Preserve Tauri command names and payloads. Add HTTP response/error decoding against the existing API shapes. Add only the exact Tauri origin(s) to `COMMUNICATIONS_ALLOWED_ORIGINS` and add the loopback API URL to the Tauri content security policy. Keep HTTP bound to loopback.

- [ ] **Step 4: Refresh status, threats, and quarantine after terminal scans**

Add an App test that transitions a scan from `running` to `completed` or `partial` and asserts the dashboard refreshes those three data sources once for that terminal result. Implement the refresh without polling-loop duplication.

- [ ] **Step 5: Run frontend tests, typecheck, and build**

Run from `ui/hackerai`: `node node_modules/jest/bin/jest.js --runInBand packages/protection-dashboard/src/__tests__/protection-api.test.ts packages/protection-dashboard/src/__tests__/App.test.tsx`
Run from `ui/hackerai/packages/protection-dashboard`: `node node_modules/typescript/bin/tsc --noEmit` and `node node_modules/vite/bin/vite.js build`
Expected: both tests pass, typecheck exits 0, and Vite produces the dashboard build.

- [ ] **Step 6: Commit**

Commit as `feat: connect Tauri dashboard to local scanner API`.

### Task 3: Make the Windows launcher select a current, runnable Tauri app

**Files:**
- Modify: `cyber_main.py`
- Modify: `ui/hackerai/packages/desktop/src-tauri/tauri.windows.conf.json`
- Modify: `tests/test_cyber_main_launcher.py`

**Interfaces:**
- Add a pure dashboard selection helper used by `main()` and tests. It chooses native Tauri when the app can be run with the current UI; otherwise it chooses local Vite browser mode. Explicit `--browser` remains a force-browser option; explicit `--desktop` returns an actionable error if native prerequisites are missing.
- Start the browser fallback with the local Node + Vite entry point, not a global `pnpm` shim.
- The Tauri development config starts Vite through the local Node dependency path so `cyber_main.py` does not depend on global pnpm resolution.

- [ ] **Step 1: Add failing launcher selection tests**

Cover fresh release app, current debug app, complete Tauri development prerequisites, stale/missing native app with Vite available, no runnable dashboard, explicit `--browser`, and explicit `--desktop` without prerequisites. Assert `/health` alone never prints protection-ready.

- [ ] **Step 2: Run launcher tests and confirm expected failures**

Run: `python -m pytest -q tests/test_cyber_main_launcher.py`
Expected: FAIL because Windows currently selects Tauri unconditionally and the browser path requires `pnpm`.

- [ ] **Step 3: Implement deterministic mode selection and launch checks**

Use release app when present; use a debug executable only when it is at least as new as the dashboard build; use Tauri dev when Cargo, Node, and the local CLI are available; otherwise use Vite browser mode. Set `VITE_PROTECTION_API_BASE_URL` in the Vite child environment. Check API liveness and protection status separately, and report the actual selected mode.

- [ ] **Step 4: Remove global pnpm dependency from Tauri development startup**

Update `beforeDevCommand` to invoke the local Vite script through Node with the loopback host and configured port.

- [ ] **Step 5: Run the full focused backend and UI verification**

Run: `python -m pytest -q tests/test_cyber_main_launcher.py tests/test_windows_protection_api.py tests/test_windows_protection_service_lifecycle.py tests/test_windows_protection_scanner.py tests/test_windows_protection_demo_rules.py`
Run the Task 2 frontend tests, typecheck, and build commands again.
Expected: all selected tests pass, typecheck/build succeed, and no dashboard mode reports active protection when service/driver are absent.

- [ ] **Step 6: Build and launch the native app on Windows**

Use the local Tauri CLI with the Windows config. If Cargo is absent, install the stable MSVC Rust toolchain through the official `rustup` installer, then rebuild. Launch through `python cyber_main.py --desktop`; check the app opens, the status panel shows limited EICAR rules and the actual service/driver state, and the API-backed scan controls load. If Tauri build prerequisites cannot be satisfied, report that blocker and verify `--browser` mode instead; do not describe the browser fallback as a Tauri build.

- [ ] **Step 7: Commit**

Commit as `fix: launch the current SVS Cyber dashboard reliably`.

## Final acceptance

- Run the harmless inert-marker scanner/quarantine/persistence test with its explicit test-only ruleset; verify the marker never leaves the temporary test root except during quarantine and restore.
- On this Windows host, start `python cyber_main.py`, perform a real local user-mode scan through the displayed dashboard, and inspect the visible component status.
- Confirm that only signed EICAR test coverage is labeled as test-only, and that unavailable service/driver components keep overall protection degraded.
- Record any unavailable live driver/service evidence. A source test or dashboard status is not proof of production kernel protection.
- After this plan is complete, create a separate design/plan for connecting the AI Agent sidebar to the existing `StaiChatWorkspace` inside the Tauri experience.
