# STAI Dark Windows Protection Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a dark STAI-branded Windows protection dashboard with working status, scan, threat, quarantine, and AI-agent views backed by the local protection service.

**Architecture:** Add a dedicated locally bundled React/Vite protection UI for Tauri rather than granting privileged commands to the existing hosted page. The Rust Tauri bridge exposes a small typed command set to the local protection service; Python FastAPI contracts remain for local development and agent compatibility. Every card and count comes from durable service data.

**Tech Stack:** React 19, TypeScript, Vite, CSS custom properties, Tauri 2 Rust commands, FastAPI, pytest, Jest/Testing Library.

**Spec:** `docs/superpowers/specs/2026-10-12-stai-custom-windows-protection-design.md`

## Global Constraints

- Dashboard navigation: Dashboard, AI Agent, System Status, Threat Activity, Scans, Quarantine, Settings.
- Use STAI branding and dark design tokens; do not reuse Bitdefender artwork or marks.
- Show Active, Degraded, or Unavailable based on service evidence; never simulate success.
- Blocked and quarantined counts reflect only confirmed outcomes.
- The hosted web page is not granted privileged protection commands.
- Scan, restore, and response actions use typed local interfaces; no arbitrary shell command bridge.

## Review Focus

- Local service unavailable: all pages show an honest unavailable state; test in Tasks 1 and 3.
- Scan error or inaccessible volume: show per-scope errors and partial progress; test in Tasks 1 and 3.
- Zero or null evidence: do not invent blocked/quarantine counts; test in Task 2.
- Hosted origin: cannot invoke the Tauri protection bridge; test in Task 2.
- Narrow window and keyboard navigation: keep navigation and scan controls reachable; test in Task 3.

---

### Task 1: Local service contract and FastAPI development routes

**Files:**
- Modify: `ui/api_server.py`
- Modify: `ui/hackerai/lib/stai-api.ts` only for shared local-dev types if retained
- Test: `tests/test_windows_protection_api.py`

**Interfaces:**
- `GET /api/protection/status`
- `POST /api/protection/scans` with `{ "scope": "quick" | "system" }`
- `GET /api/protection/scans/{job_id}` and `DELETE /api/protection/scans/{job_id}`
- `GET /api/protection/threats`
- `GET /api/protection/triage?detection_id={id}`
- `POST /api/protection/triage/{detection_id}` to request/retry typed analysis for one recorded detection
- `GET /api/protection/agent/conversations/{session_id}`
- `POST /api/protection/agent/messages` with `{ "session_id": string, "message": string, "detection_id": string | null }`
- `GET /api/protection/quarantine`
- `POST /api/protection/quarantine/{item_id}/restore`
- Responses use service `ProtectionStatus`, `ScanJob`, `DetectionRecord`, and `QuarantineItem` fields; no client-supplied scan roots.
- Status includes Windows-registered antivirus provider and Defender mode when the OS query is available, plus existing sensor registry/coverage. Both are read-only observations; the service never changes Defender configuration.
- Triage response contains only stored `triage_id`, `detection_id`, `summary`, `recommendations`, `state`, and timestamps.
- Agent chat is local and investigation-scoped. It can discuss the selected detection and stored evidence but cannot invoke tools, change the Level 1 verdict, or accept arbitrary privileged actions.

- [ ] **Step 1: Write failing tests** named `test_status_reports_degraded_when_driver_or_rules_unhealthy`, `test_status_includes_registered_av_and_defender_mode_when_available`, `test_scan_rejects_client_supplied_paths`, `test_scan_job_routes_report_persisted_progress`, `test_threats_endpoint_does_not_conflate_detected_and_blocked`, `test_restore_requires_existing_quarantine_item`, and `test_protection_agent_chat_cannot_execute_tools`. Assert `status.state == "degraded"` when driver/rules are unhealthy; `status.windows_security.registered_av_provider is None` when the OS query is unavailable; `client.post("/api/protection/scans", json={"scope":"quick", "roots":["C:/"]}).status_code == 422`; only `STATUS_ACCESS_DENIED` increments `blocked`; a detection alone increments `detected`; and agent chat returns a response while `tool_calls == []` and `response_action is None`.
- [ ] **Step 2: Run** `python -m pytest -q tests/test_windows_protection_api.py`; expect missing routes.
- [ ] **Step 3: Implement** route handlers that delegate to the protection service, return 503 when it is unavailable, and validate the exact scope/item schemas.
- [ ] **Step 4: Run** `python -m pytest -q tests/test_windows_protection_api.py tests/test_ui_api_contract.py`; expect all protection contract tests and existing API contract tests to pass.

### Task 2: Trusted Tauri protection bridge

**Files:**
- Modify: `ui/hackerai/packages/desktop/src-tauri/src/lib.rs`
- Modify: `ui/hackerai/packages/desktop/src-tauri/capabilities/default.json`
- Test: Rust unit tests in `src-tauri/src/protection_bridge.rs` (new)

**Interfaces:**
- Tauri commands: `get_protection_status`, `start_protection_scan(scope)`, `get_protection_scan(job_id)`, `cancel_protection_scan(job_id)`, `list_protection_threats`, `get_protection_triage(detection_id)`, `request_protection_triage(detection_id)`, `get_protection_agent_history(session_id)`, `send_protection_agent_message(session_id, message, detection_id)`, `list_quarantine_items`, and `restore_quarantine_item(item_id)`.
- Rust client calls the local protection service over the named pipe `\\.\pipe\STAI.Protection.v1`; it cannot accept a command string or arbitrary path.
- Register commands only for the bundled local Tauri origin; the hosted HackerAI origin receives no protection capability.

- [ ] **Step 1: Write failing Rust tests** named `bridge_rejects_unknown_scope`, `bridge_has_no_shell_command_operation`, `bridge_maps_service_unavailable_to_error`, `bridge_serializes_status_contract`, `bridge_rejects_hosted_origin`, and `bridge_agent_chat_is_typed` using an injected named-pipe client and a Tauri capability harness. Assert invalid scope returns `Err`, the operation enum has no shell/file-command variant, unavailable service returns `Err("protection service unavailable")`, hosted origin is denied, and agent request serialization contains exactly session ID, message, and optional detection ID.
- [ ] **Step 2: Run** `cargo test --manifest-path ui/hackerai/packages/desktop/src-tauri/Cargo.toml protection_bridge`; expect missing module/tests.
- [ ] **Step 3: Implement** allowlisted typed commands, bounded pipe frames, timeout handling, and origin-scoped Tauri capabilities.
- [ ] **Step 4: Run** the same cargo test command; expect all five bridge tests to pass.

### Task 3: Dark local dashboard and page tests

**Files:**
- Create: `ui/hackerai/packages/protection-dashboard/package.json`
- Create: `ui/hackerai/packages/protection-dashboard/index.html`
- Create: `ui/hackerai/packages/protection-dashboard/src/App.tsx`
- Create: `ui/hackerai/packages/protection-dashboard/src/protection-api.ts`
- Create: focused components under `src/components/`
- Create: focused tests under `src/__tests__/`
- Modify: `ui/hackerai/packages/desktop/package.json` build scripts and `ui/hackerai/packages/desktop/src-tauri/tauri.conf.json` frontend build settings
- Modify: `ui/hackerai/packages/desktop/scripts/build.js` to build the local dashboard instead of rewriting an external hosted URL

**Interfaces:**
- `protection-api.ts` exports typed `getProtectionStatus`, `startScan`, `getScan`, `cancelScan`, `listThreats`, `listQuarantine`, and `restoreQuarantine` backed by the Tauri `invoke` commands above.
- `protection-api.ts` also exports `getAgentHistory(sessionId)` and `sendAgentMessage(sessionId, message, detectionId)`; both call typed commands and cannot name arbitrary tools or actions.
- Page state is selected through accessible navigation labels matching the seven names in Global Constraints.
- Package name is `@stai/protection-dashboard`; scripts are `dev`, `build`, and `typecheck`; root Jest config covers `packages/protection-dashboard/src/__tests__`.

- [ ] **Step 1: Write failing UI tests** named `renders_degraded_state_without_fake_counts`, `shows_last_scan_rule_version_and_agent_escalations`, `starts_and_tracks_quick_scan`, `shows_distinct_detection_block_and_quarantine_totals`, `renders_quarantine_restore_result`, `sends_typed_detection_follow_up_and_renders_agent_reply`, `renders_service_unavailable_on_bridge_error`, and `keeps_navigation_and_scan_action_keyboard_reachable`. Assert each navigation label is present; totals come verbatim from the fixture (`detected=4`, `blocked=2`, `quarantined=1`); unavailable/error states never render a success badge; Quick Scan calls `startScan("quick")`; status shows last scan time, rule version, and triage count; the AI Agent page displays stored triage, calls `sendAgentMessage(sessionId, message, detectionId)`, and exposes no direct command control.
- [ ] **Step 2: Run** `pnpm --dir ui/hackerai exec jest --runInBand --runTestsByPath packages/protection-dashboard/src/__tests__/App.test.tsx`; expect missing workspace package/components.
- [ ] **Step 3: Implement** the dark dashboard hierarchy inspired by the supplied reference: status-first overview, recommended action, Quick/System Scan cards, recent threat activity, and persistent left navigation. Add complete Scans, Threat Activity, System Status, Quarantine, Settings, and AI Agent views with explicit loading/error/empty states.
- [ ] **Step 4: Run** `pnpm --dir ui/hackerai exec jest --runInBand --runTestsByPath packages/protection-dashboard/src/__tests__/App.test.tsx` and `pnpm --dir ui/hackerai --filter @stai/protection-dashboard typecheck`; expect all UI tests and TypeScript checks to pass.
- [ ] **Step 5: Review** the app at 1280x800 and 900x600; verify dark contrast, responsive navigation, and no Bitdefender marks. Capture a screenshot in the implementation report.

## Handoff

The packaging plan owns the local UI build and installs the matching service/driver bundle. The Tauri app must show unavailable protection until that service reports healthy driver and rules.
