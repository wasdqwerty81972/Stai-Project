# SVS-Cyber V4 P0/P1 Process Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair confirmed P0 protection-status/startup defects and make the installed protection service the authenticated owner of live Windows process telemetry while preserving the dashboard’s existing process API and truthful fallback states.

**Architecture:** Keep `ProcessRegistry` as the process-instance and metrics implementation, but instantiate and lifecycle-manage it from `ProtectionServiceHost`. Expose bounded read-only snapshots, deltas, health, and the existing sampling profile through the authenticated named pipe; make FastAPI prefer that service source and retain its current local collector only as a clearly identified fallback. The service collector must start independently of driver availability and must not perform scans inside its sampling loop.

**Tech Stack:** Python, pytest, FastAPI, existing `ui.ProcessRegistry`, Windows named pipes, existing TypeScript dashboard and package scripts, PyInstaller service packaging.

**Spec:** `docs/superpowers/specs/2026-10-14-svs-cyber-antivirus-v4-design.md`

## Global Constraints

- Preserve all pre-existing user changes and local artifacts; edit and stage only files listed in the approved task being executed.
- Do not claim kernel, WFP, or service protection is active unless its runtime state is verified.
- Keep process identity tied to PID plus creation time; do not join events or findings on PID alone.
- Keep the named-pipe protocol version, client authorization, operation allowlist, and 1 MiB frame limit; validate every new operation and bound its response.
- Retain startup enumeration and periodic reconciliation when lifecycle event subscription is unavailable; report the actual source and failure.
- Keep file hashing/YARA/database lookups out of the high-frequency process metrics loop.
- Do not silently change the installed service's startup type or running state. Any installer lifecycle change must be separately tested and explicitly reported.
- Do not install or load an experimental driver on the development host.
- No synthetic process records in production runtime; synthetic records are allowed only in tests.

## Review Focus

- Service pipe unavailable or times out: API reports source unavailable/fallback accurately and never labels local telemetry as service-owned. Test in Task 5.
- Process list exceeds one pipe frame: page at a stable registry sequence and fail/resync instead of truncating or exceeding the 1 MiB cap. Test in Task 3.
- PID reuse between start/exit, snapshot, and scan result: retain instance identity and never associate old evidence with a new process. Test in Task 2 and Task 6.
- ETW/WMI source denied or stops after startup: reconciliation remains operational and health exposes degraded event collection. Test in Task 2.
- Slow/disconnected dashboard client: cannot block the service collector; missed sequence requires a fresh snapshot. Test in Task 5 and Task 7.

## File Map

- `cyber_os/protection/service.py` — correct protection readiness/status only where a focused P0 regression test reproduces a false claim.
- `cyber_os/protection/filter_client.py` — make bounded scan-queue shutdown interruptible and resolve already received requests fail-open on service stop.
- `cyber_os/protection/windows_service.py` — own process monitor lifecycle; add strict allowlisted pipe operations and service dispatch.
- `ui/process_monitor.py` / `ui/windows_process_events.py` — retain the existing registry and event source; make only fixes proven necessary by service-context tests.
- `ui/api_server.py` — add a service-backed provider for existing HTTP/WebSocket process routes and preserve a clearly labeled local fallback.
- `cyber_os/protection/windows_pipe_client.py` — typed client helpers for the new bounded process-monitor operations, following existing request/error behavior.
- `windows_protection/installer/pyinstaller.spec` — include only required service-side telemetry dependencies/modules and verify the packaged imports.
- Existing focused tests under `tests/` for service status, `tests/test_reliability_bounded_queue.py`, pipe protocol, process registry, API routes, and process streaming — add regression coverage beside the current implementation.
- `docs/security/antivirus-audit.md` — reconcile only claims disproven by the fresh P0 baseline or verified changes; retain explicit blocked/unverified language.
- `docs/verification/v4-p0-p1-process-telemetry.md` — record fresh baseline, post-change tests, service/event-source state, and Windows live-test evidence or exact blockers.

---

### Task 1: Capture a fresh P0 baseline and repair only reproduced defects

**Files:**
- Modify: `cyber_os/protection/service.py` only if the focused status test below reproduces false `running`/ready reporting.
- Modify: `docs/security/antivirus-audit.md` to align claims with current source and fresh test evidence.
- Create: `docs/verification/v4-p0-p1-process-telemetry.md`
- Test: `tests/test_protection_status_truthfulness.py`, `tests/test_windows_protection_service_lifecycle.py`, and the full current Python suite.

**Interfaces:**
- Consumes: current protection status fields and the existing service lifecycle.
- Produces: a saved baseline report and status behavior that reports `running` only when the service is actually running.

- [ ] **Step 1: Record repository state and run focused status/lifecycle tests before editing.** Save exact commands, result counts, and environment limitations in the verification report. Do not include unrelated dirty files in the report as product changes.
- [ ] **Step 2: Run the full Python test suite and the existing frontend typecheck/build commands.** Capture failures and durations; do not “fix” unrelated failures without a focused reproduction tied to this phase.
- [ ] **Step 3: Reproduce the confirmed bounded-queue shutdown failure in `tests/test_reliability_bounded_queue.py`.** Add an assertion that every request already received from the transport receives either a completed scan verdict or a fail-open shutdown reply.
- [ ] **Step 4: Run the focused status and queue tests and verify the queue test fails for the hang/unanswered-request behavior.** Status-truthfulness tests already exist; if they pass, do not change status implementation and record the audit discrepancy.
- [ ] **Step 5: Implement interruptible bounded enqueue in `cyber_os/protection/filter_client.py`.** Keep backpressure while running; when stop is signaled, do not wait forever on a full queue and immediately send an explicit fail-open reply for a received request that cannot be queued.
- [ ] **Step 6: Run the reliability queue tests and focused status/startup tests.** Confirm shutdown returns within the test deadline and already received requests are not left pending.
- [ ] **Step 7: Run the full applicable backend suite.** Record exact outcomes and update only stale audit statements.

### Task 2: Make the process registry safely owned by `ProtectionServiceHost`

**Files:**
- Modify: `cyber_os/protection/windows_service.py`
- Modify only if needed: `ui/process_monitor.py`, `ui/windows_process_events.py`
- Test: `tests/test_windows_protection_service_lifecycle.py`, `tests/test_process_monitor.py`, and `tests/test_windows_process_events.py`.

**Interfaces:**
- Consumes: `ProcessRegistry.start()`, `stop()`, `snapshot()`, `drain_events(after_sequence)`, `get_process_details(instance_id)`, `connections()`, and `set_sampling_profile(profile)`.
- Produces: `ProtectionServiceHost.process_monitor` with `start()`, `stop()`, `snapshot_page(offset, limit, sequence=None)`, `events_after(sequence, limit)`, `get_details(instance_id)`, `set_profile(profile)`, and `health()`; unavailable data is represented explicitly, never fabricated.

- [ ] **Step 1: Add host lifecycle tests with a fake monitor.** Verify monitor starts once during `start()`, stops on `stop()`, and repeated start/stop is idempotent.
- [ ] **Step 2: Add degraded-start tests.** A monitor/event-source startup failure must be captured in monitor health, while named pipe, scanner, and other independent service components still follow their existing startup behavior.
- [ ] **Step 3: Run the focused tests and verify the new assertions fail.**
- [ ] **Step 4: Inject the monitor into `ProtectionServiceHost` and wire start/stop with exception isolation.** `create_default_host()` constructs the existing registry using the installed service context; driver availability is not a prerequisite.
- [ ] **Step 5: Verify event-source behavior in service context.** Retain initial snapshot and reconciliation on denied/unavailable ETW/WMI subscription; report event source, last error category, reconciliation interval, dropped events, and sample freshness in health. Do not take over an ETW session owned by another component.
- [ ] **Step 6: Run lifecycle, registry, PID-reuse, source-denied, and host shutdown tests.** Confirm handles/threads are released and a new process instance cannot inherit old metrics or findings.

### Task 3: Add bounded, authenticated process telemetry operations to the named pipe

**Files:**
- Modify: `cyber_os/protection/windows_service.py`
- Modify: `cyber_os/protection/windows_pipe_client.py`
- Test: `tests/test_process_monitor_pipe.py`, `tests/test_windows_protection_service_lifecycle.py`, and `tests/test_windows_pipe_client.py`.

**Interfaces:**
- Consumes: `ProtectionServiceHost.process_monitor` from Task 2 and protocol version 1.
- Produces: allowlisted operations `get_process_snapshot_page`, `get_process_events`, `get_process_monitor_status`, `get_process_details`, `get_process_connections`, and `set_process_monitor_profile`.
- Request schemas: snapshot page `{offset: int, limit: int, sequence: int|null}` with `0 <= offset <= 10,000,000`, `1 <= limit <= 500`; events `{after_sequence: int, limit: int}` with nonnegative sequence and `1 <= limit <= 500`; status `{}`; details `{instance_id: str}` bounded to 96 UTF-8 bytes and matching the registry’s verified PID/creation-time or explicit unverified instance ID format; connections `{}`; profile `{profile: "low"|"normal"|"high"}`.
- Snapshot page response includes `sequence`, `observed_at`, `processes`, `offset`, `next_offset`, `total`, and `health`. A sequence mismatch between pages requires resnapshot. Events return at most 500 deltas and a `resync_required` indicator. Every operation remains below `MAX_FRAME_BYTES` or returns the existing bounded protocol error.
- Connection response is `{connections, total, truncated, observed_at}`; when the frame budget requires shortening the list, `truncated` is true and the original count remains visible. Never silently cut records.

- [ ] **Step 1: Add request-validation tests for each allowed operation and reject unknown fields, negative/oversized pagination, malformed instance IDs, invalid profiles, and unallowlisted operations.**
- [ ] **Step 2: Add host-dispatch tests for stable paging, event cursor gaps, missing instances, denied details, bounded connection snapshots, and the 1 MiB response cap.** Test an oversized process set without manufacturing a successful silently truncated process page.
- [ ] **Step 3: Run protocol tests and verify the new schema/dispatch tests fail.**
- [ ] **Step 4: Add only the listed operations to the existing allowlist and exact-schema validator.** Implement stable-sequence page reads and bounded deltas; use the current JSON serializer/frame guard.
- [ ] **Step 5: Add typed client wrappers in `windows_pipe_client.py`** with bounded timeout, response schema validation, and existing service-unavailable/error semantics.
- [ ] **Step 6: Run all pipe protocol, authorization, size-limit, and client tests.** Confirm no permission or operation allowlist was broadened.

### Task 4: Package the service-owned monitor without pulling the UI server into the service

**Files:**
- Modify: `cyber_os/protection/windows_service.py` if construction needs a small service-side factory.
- Modify: `windows_protection/installer/pyinstaller.spec`
- Modify: `requirements-windows-protection.txt`
- Test: `tests/test_windows_process_monitor_packaging.py` plus the existing Windows service packaging/import validation command.

**Interfaces:**
- Consumes: the monitor factory and telemetry bridge from Tasks 2–3.
- Produces: a packaged `STAIProtection` service that can start the process monitor without importing `ui.api_server` or starting a second FastAPI server.

- [ ] **Step 1: Add a factory test proving default host construction wires the monitor and does not require API-server imports, plus a package dependency test for the monitor’s runtime modules.**
- [ ] **Step 2: Run it and verify it fails before host composition changes.**
- [ ] **Step 3: Add the minimum PyInstaller hidden imports/data declarations required by the existing process monitor and event source.** Keep UI-only modules out of the privileged service bundle.
- [ ] **Step 4: Run the repository’s service packaging/import validation.** If a Windows packaging tool is absent, record the exact unavailable tool and validate imports/analysis without claiming a distributable binary was built.

### Task 5: Route existing FastAPI process endpoints through the service, with an honest local fallback

**Files:**
- Modify: `ui/api_server.py`
- Modify: `cyber_os/protection/windows_pipe_client.py` only if Task 3 reveals a required compatible wrapper.
- Test: `tests/test_process_monitor_api.py`, `tests/test_process_scan_api.py`, and `ui/hackerai/app/components/svs/protection/ProcessMonitorView.test.tsx`.

**Interfaces:**
- Consumes: Task 3 typed client operations.
- Produces: a process telemetry provider selected at API startup. On Windows, a healthy service is the production source; when service IPC fails, the current API-owned registry remains a labeled local fallback, not service-owned protection.
- Existing routes stay compatible: `/api/antivirus/processes`, `/api/antivirus/processes/{instance_id}`, `/api/antivirus/processes/{instance_id}/connections`, `/api/antivirus/process-monitor/status`, `/api/antivirus/process-monitor/events`, and `/api/antivirus/process-monitor/stream`.
- Health identifies `source` (`protection_service`, `local_fallback`, or `unavailable`), event source, last sample time, degraded reason, and resync state.

- [ ] **Step 1: Add provider contract tests.** Healthy service supplies snapshot/details/events/profile; pipe timeout selects local fallback with explicit source; no available source yields unavailable instead of an empty healthy snapshot.
- [ ] **Step 2: Add WebSocket tests for initial snapshot, incremental add/update/remove events, heartbeat, sequence gap resync, reconnect, and disconnect isolation.** Assert a slow/broken client does not stop collection.
- [ ] **Step 3: Run new tests and verify they fail against the current API-owned-only registry.**
- [ ] **Step 4: Implement the provider abstraction and route existing endpoints through it.** Keep local mode for non-Windows development and use its pre-existing origin/loopback checks.
- [ ] **Step 5: Ensure provider polling is bounded and batched.** Do not re-download a complete snapshot each 250 ms; use deltas, periodic health checks, and a full snapshot only on initial connection or resync.
- [ ] **Step 6: Run all process API, WebSocket, origin, reconnect, and provider-fallback tests.**

### Task 6: Preserve process analysis and antivirus evidence on the service source

**Files:**
- Modify: `ui/api_server.py` and the smallest existing process-analysis module needed to consume provider events.
- Test: `tests/test_process_analysis.py`, `tests/test_process_entropy.py`, `tests/test_process_scan_api.py`, and `tests/test_device_process_identity.py`.

**Interfaces:**
- Consumes: Task 5 provider events keyed by process instance identity and existing scanner callback/results.
- Produces: process-added events schedule the existing bounded executable-on-disk analysis once per process instance/file identity; scan results attach to the same process instance only. Entropy remains explicitly executable-file entropy, not memory entropy.

- [ ] **Step 1: Add tests proving added process instances schedule analysis once, repeated metric deltas do not rescan, and PID reuse creates a distinct analysis identity.**
- [ ] **Step 2: Add a test that scanner verdicts remain attached to the instance/file identity that initiated the scan after the process exits.**
- [ ] **Step 3: Run tests and verify they fail where service-origin events currently bypass the local analysis worker.**
- [ ] **Step 4: Connect service-provider lifecycle events to the existing analysis worker without placing hashing/YARA work in service sampling or callbacks.** Preserve current scanner, quarantine, and authorization semantics.
- [ ] **Step 5: Run process analysis, entropy, scanner integration, and quarantine regression tests.**

### Task 7: Verify frontend source states, deltas, and large process tables

**Files:**
- Modify: `ui/hackerai/app/components/svs/protection/ProcessMonitorView.tsx` and its colocated frontend types/provider module as required; do not create a second dashboard.
- Test: `ui/hackerai/app/components/svs/protection/ProcessMonitorView.test.tsx`.

**Interfaces:**
- Consumes: Task 5 route and WebSocket schemas.
- Produces: existing process table keeps live metrics, stable selection, filters, and entropy/risk behavior while showing monitor source/health and explicit unavailable/access-denied states.

- [ ] **Step 1: Add frontend tests for `protection_service`, `local_fallback`, and `unavailable` source states; reconnect snapshot; sequence-gap resync; stable process-instance selection; and unavailable metrics.**
- [ ] **Step 2: Run focused frontend tests and confirm expected failures.**
- [ ] **Step 3: Update existing frontend API types and WebSocket reducer to consume snapshot pages/deltas and retain selection by `instance_id`.**
- [ ] **Step 4: Keep sorting/search behavior usable under live updates; do not resort continuously unless live-sort is enabled.**
- [ ] **Step 5: Run focused frontend tests, then the repository’s full typecheck/build command.** Record resource/time limits if the command cannot complete; do not claim it passed without exit code 0.

### Task 8: Run Windows live validation and close the P0/P1 evidence report

**Files:**
- Modify: `docs/verification/v4-p0-p1-process-telemetry.md`
- Modify: `docs/security/antivirus-audit.md` only where fresh evidence changes a claim.
- Test: harmless Windows integration test/script already aligned with repository conventions.

**Interfaces:**
- Consumes: completed Tasks 1–7.
- Produces: evidence for process start/exit delivery, CPU/RAM samples, source health, API reconnect/resync, service resource use, and remaining limitations.

- [ ] **Step 1: Launch a harmless bounded child process and verify it appears without a manual refresh; close it and verify it disappears.** Record PID, instance ID, delivery latency, source, and reconciliation fallback if used.
- [ ] **Step 2: Compare CPU and working-set values to Windows process counters over repeated samples; document definitions and timing tolerance.** Never substitute synthetic values for live validation.
- [ ] **Step 3: Test service/API reconnect and missed-sequence resynchronization.** Verify protected process metadata denial is represented as partial/access-denied.
- [ ] **Step 4: Measure idle monitor CPU/RAM and event delivery under the harmless workload.** Report measured numbers or explicitly say the measurement could not be collected.
- [ ] **Step 5: Re-run full applicable Python tests, focused Windows process tests, frontend typecheck/build, and service packaging validation.** Record exact command and exit code for each.
- [ ] **Step 6: Compare each P0/P1 exit criterion in the approved spec with collected evidence.** Mark service start/event subscription/driver/WFP as blocked or unavailable where they were not actually exercised; do not change the installed service startup mode to make the test pass.

## Self-review

- **Spec coverage:** Covers the immediate P0 and service-owned process telemetry slice in the approved V4 spec. P1 WFP observation and P2 scanner/threat-intelligence integration remain separate plans as required by the spec.
- **Step scan:** Each task has a concrete failing-test or validation gate before implementation. Pipe pagination and source attribution are explicit; no response may be silently truncated.
- **Type consistency:** The monitor adapter methods and page/event schemas are defined in Task 2 and consumed unchanged by Tasks 3–6.
- **Review Focus:** All five failure modes have owning test tasks (Tasks 2, 3, 5, and 6).
- **Proportion:** The plan limits implementation to P0, including the reproduced bounded-queue service shutdown defect, plus the user-approved first P1 slice; driver/WFP enforcement and broad AV feature work are explicitly excluded.

## Execution handoff

This plan is for service-owned user-mode process telemetry. Implementation must preserve the current dirty working tree, use the `superpowers:executing-plans` workflow if executed natively, and request fresh review before claiming the phase complete.
