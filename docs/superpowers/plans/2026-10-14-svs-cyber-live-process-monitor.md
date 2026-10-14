# SVS Cyber Live Process Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the existing Processes view into a real-time, instance-safe Windows process monitor with measured metrics and antivirus evidence.

**Architecture:** Add a process registry/source layer that starts with a real snapshot, consumes Windows process-trace notifications when available, and reconciles periodically. Expose bounded snapshots and deltas through the existing loopback FastAPI service, then update the existing Tauri dashboard to render stable process instances and honest source/metric health.

**Tech Stack:** Python, psutil, FastAPI, asyncio/WebSocket, React, TypeScript, Tauri, Windows ETW and process APIs, pytest, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-14-live-process-monitor-design.md`

## Global Constraints

- Preserve existing named-pipe schemas, authentication, authorization, loopback/origin checks, and operation allowlists.
- Never use PID alone for process identity; verify PID with process creation time.
- ETW errors activate a visible reconciliation fallback; do not take ownership of or stop an ETW session owned by another component.
- CPU and memory values must come from measured Windows data; unsupported values are unavailable.
- Entropy is a review signal only and cannot independently trigger termination or quarantine.
- Keep analysis off the high-frequency sampling path and bound all histories and client queues.
- Do not require or silently install a kernel driver for process monitoring.

## Review Focus

- ETW unavailable, already owned, or permission denied: retain snapshot and reconciliation monitoring with an explicit degraded source state.
- Process exits or reuses a PID between samples: stale metrics, connections, and findings must not move to the new instance.
- Access-denied processes or command-line/path lookup failures: preserve partial rows and label missing metadata.
- Slow or reconnecting UI client: collection remains live; a sequence gap triggers a fresh snapshot.
- Empty, large, and rapidly changing process sets: table remains bounded/responsive and does not invent metric values.

---

### Task 1: Process Registry and Windows Sources

**Files:**
- Create: `ui/process_monitor.py`
- Create: `ui/windows_process_events.py`
- Test: `tests/test_process_monitor.py`
- Test: `tests/test_windows_process_events.py`

**Interfaces:**
- `ProcessRegistry.start() -> None`, `stop() -> None`, `snapshot() -> dict[str, Any]`, `get_process(instance_id: str) -> dict[str, Any] | None`, and `drain_events(after_sequence: int) -> list[dict[str, Any]]`.
- `WindowsProcessEventSource.start(on_start, on_exit) -> SourceStatus`, `stop() -> None`; `SourceStatus` contains `state`, `error`, and dropped-event count.
- Registry records use the shared `process_identity(pid, create_time)` key and bounded metric/history data.

- [x] **Step 1: Add failing registry tests** for instance identity, process start/exit, PID reuse, bounded history, and monotonic sequence numbers.
- [x] **Step 2: Run those tests** and confirm they fail because the registry is absent.
- [x] **Step 3: Implement the locked registry and reconciliation loop** using the existing `psutil` dependency; preserve partial process metadata on access errors.
- [x] **Step 4: Add failing source tests** for event payload PID decoding and fallback status when the Windows trace subscription is unavailable.
- [x] **Step 5: Implement the Windows process trace subscription** without taking over another trace session; keep periodic process enumeration as the fallback and reconciliation source.
- [x] **Step 6: Run the focused tests**; this host's Windows WMI trace subscription was denied and the monitor reports reconciliation fallback.

### Task 2: Measured Metrics and Connections

**Files:**
- Modify: `ui/process_monitor.py`
- Modify: `ui/device_activity.py`
- Test: `tests/test_process_monitor_metrics.py`
- Test: `tests/test_device_activity.py`

**Interfaces:**
- `ProcessRegistry.sample_metrics() -> None` updates existing process instances with CPU-time deltas, working-set bytes, thread count, and supported per-process I/O counters.
- `ProcessRegistry.connections() -> list[dict[str, Any]]` returns observed endpoints with verified process instance ownership or an explicit unknown owner.

- [x] **Step 1: Add failing tests** for first CPU sample unavailable, valid normalized CPU deltas, stale samples, and PID reuse during connection correlation.
- [x] **Step 2: Run the focused tests** and verify the expected failure before adding instance-scoped connection enumeration.
- [x] **Step 3: Implement measured sampling profiles** from OS counters, keeping I/O semantics explicit and excluding hashes/YARA from the sampling path. Normal uses a 5-second cadence based on the measured cost of a full pass; Low uses 10 seconds and High-frequency requests 1-second metrics with 2-second reconciliation.
- [x] **Step 4: Add connection refresh with ownership validated against the same process instance**; leave throughput unavailable because this source measures ownership only.
- [x] **Step 5: Run metric tests**; existing device-activity tests remain separate and unchanged.

### Task 3: Local API and Stream Synchronization

**Files:**
- Modify: `ui/api_server.py`
- Create: `ui/process_monitor_api.py` (only if separation fits the existing route conventions)
- Test: `tests/test_process_monitor_api.py`

**Interfaces:**
- `GET /api/antivirus/processes` returns snapshot plus current sequence.
- `GET /api/antivirus/processes/{instance_id}` returns one exact process instance or 404.
- `GET /api/antivirus/processes/{instance_id}/connections` returns connections validated against that instance.
- `GET /api/antivirus/process-monitor/status` reports collection state, ETW/fallback source, last reconciliation, dropped events, and sampling interval.
- `WS /api/antivirus/process-monitor/stream` sends an initial snapshot and sequenced process-added, process-removed, metric-update, health, and heartbeat events.

- [x] **Step 1: Add API tests** for loopback/origin protection, instance detail lookup, monitor health, and sequence-gap resync.
- [x] **Step 2: Verify endpoint tests fail before implementation.**
- [x] **Step 3: Implement routes** with the existing local-only origin boundary; preserve `/api/device/activity` behavior.
- [x] **Step 4: Implement independent bounded-history WebSocket streaming**; each client detects history rollover and resynchronizes without blocking collection.
- [x] **Step 5: Run API and existing device-activity access tests**; 11 passed.

### Task 4: Live Processes Dashboard

**Files:**
- Modify: `ui/hackerai/lib/stai-protection-api.ts`
- Modify: `ui/hackerai/app/components/svs/SvsProtectionDashboard.tsx`
- Create: `ui/hackerai/app/components/svs/protection/ProcessMonitorView.tsx`
- Test: `ui/hackerai/app/components/svs/protection/ProcessMonitorView.test.tsx`

**Interfaces:**
- Add typed process monitor, process-instance, connection, status, and stream-event models.
- Add `Processes` stream subscription with snapshot/resync and cleanup when the page unmounts; keep `Network Activity` on verified current connection data.

- [x] **Step 1: Add UI tests** for process appearance/removal, metric updates, stable selection, paused rendering, and unavailable states.
- [x] **Step 2: Run focused UI tests** and confirm they pass.
- [x] **Step 3: Implement table controls** for process/PID search, CPU/memory sort selection, network and risk filters, parent grouping, optional parent/path columns, pause/resume display, live-sort, and monitor health.
- [x] **Step 4: Add expandable details** for parent PID, creation time, executable path, real metrics, sampled executable entropy, automatic scan status, and honest scan-evidence state.
- [x] **Step 5: Preserve the existing dark cyan SVS Cyber visual system** and label unavailable values explicitly.
- [x] **Step 6: Run focused dashboard tests**; 20 tests passed. Project-wide Next build and TypeScript checks were attempted but stopped after prolonged high memory/CPU use without diagnostic output.

### Task 5: Windows Runtime Verification and Performance Record

**Files:**
- Create: `scripts/verify_process_monitor_windows.ps1`
- Create or update: `docs/verification/live-process-monitor.md`

- [x] **Step 1: Add a harmless Windows verification script** that starts a bounded child workload, records its PID, changes CPU/memory within safe limits, opens a local TCP connection, then exits cleanly.
- [x] **Step 2: Run the script against the live FastAPI process monitor** and confirm process appearance, CPU/memory metrics, owned local connections, and disappearance without manual refresh.
- [x] **Step 3: Measure and record** normal-profile CPU/memory, sample duration, event-to-display latency, and update intervals on this host.
- [x] **Step 4: Compare live process count** with PowerShell `Get-Process` (a trusted local process view) and record the sampled counts.
- [x] **Step 5: Run the relevant existing protection and dashboard test suites**; 208 backend tests passed and 1 skipped; 20 dashboard tests passed. Entropy analysis and automatic scan handoff are covered. The full project suite and production frontend build remain unverified because their checks ran for a prolonged time without diagnostics.

---

## Plan Self-Review

- Spec coverage: collection/ETW/fallback/PID reuse (Task 1); metrics/connections/analysis isolation (Task 2); authenticated snapshots/stream/resync (Task 3); UI workflows and honest states (Task 4); runtime/performance verification (Task 5).
- Risk cases in Review Focus are covered by Tasks 1–4 and the runtime checks in Task 5.
- GPU telemetry is intentionally omitted unless a supported source already exists; the UI will report it unavailable.
- The ETW adapter must confirm current Windows privileges/session ownership during implementation; fallback remains a functional path if those preconditions are not met.
