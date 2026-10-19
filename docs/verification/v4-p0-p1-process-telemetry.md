# SVS-Cyber V4 P0/P1 Process Telemetry Verification

Date: 2026-10-14
Scope: P0 bounded filter-queue shutdown repair and P1 service-owned process telemetry through live Windows process lifecycle validation.

## Workspace and runtime state

- Branch: `codex/mobile-phase2-tools`.
- Existing worktree contains extensive pre-existing tracked/untracked changes; implementation remained in place and only plan-scoped files were edited.
- `STAIProtection`: installed, `Stopped`, startup type `Manual` at verification time. This implementation did not change its state or startup type.
- `pnpm` shim points at a missing `D:\OpenClaw` package-manager install. The pinned project version ran through Corepack (`pnpm@10.33.2`).

## Baseline before P0 change

| Command | Result |
|---|---|
| `python -m pytest -q tests/test_protection_status_truthfulness.py tests/test_windows_protection_service_lifecycle.py` | 23 passed in 13.62s |
| `python -m pytest -q` | 994 passed, 6 skipped, 1 failed, 303 subtests passed in 526.86s; failure: `tests/test_reliability_bounded_queue.py::test_saturated_loop_returns_when_its_stop_event_is_set` |
| `pnpm exec tsc --noEmit` | Could not start: global `pnpm` shim referenced missing `D:\OpenClaw\bin\node_modules\pnpm\bin\pnpm.cjs`. |
| `corepack pnpm exec tsc --noEmit` (in `ui/hackerai`) | Passed (exit code 0). |
| `corepack pnpm exec next build` (in `ui/hackerai`) | Stopped after prolonged build activity with high memory use and no new diagnostics. Production build is unverified. |

## P0 post-change verification

| Command | Result |
|---|---|
| `python -m pytest -q tests/test_reliability_bounded_queue.py` | 6 passed in 7.86s. |
| `python -m pytest -q` | 995 passed, 6 skipped, 303 subtests passed in 578.06s; no failures. |

The existing `tests/test_protection_status_truthfulness.py` and service lifecycle tests were included in the full passing suite. No status implementation edit was necessary.

## P0 confirmed defect and repair

The saturated-queue regression reproduced in the full suite and as an isolated test: receiver threads blocked indefinitely in `Queue.put()` after the stop event, and the service loop joined them without a timeout. The process could remain in service-stop-pending until Windows terminated it.

`cyber_os/protection/filter_client.py` now uses timed bounded queue puts that observe shutdown. On loop shutdown, it sends a fail-open verdict for every still-pending request before closing the transport. This preserves bounded backpressure while running and avoids silently abandoning received driver requests on shutdown.

| Command | Result |
|---|---|
| `python -m pytest -q tests/test_reliability_bounded_queue.py::test_saturated_loop_returns_when_its_stop_event_is_set` before fix | Failed as expected: did not return within the 10-second shutdown deadline. |
| `python -m pytest -q tests/test_reliability_bounded_queue.py` after fix | 6 passed in 7.86s. |

The protection-status truthfulness tests already passed before code changes; the earlier reported default-`running` defect is not present in the inspected working tree, so no status implementation change was made.

## Remaining verification

- The interactive user's WMI `Win32_ProcessTrace` subscription is denied by Windows access control. The monitor remains functional through periodic reconciliation, which the live lifecycle test exercised. A service-context or elevated ETW/WMI run has not been verified because `STAIProtection` remains stopped/manual.
- ETW delivery and service-owned named-pipe telemetry have unit/integration coverage, but live delivery from the installed Windows service has not been exercised.
- Filter-driver loading/enforcement, WFP enforcement, release signing, installer rollback, and production readiness are outside the verified scope. The service packaging manifest continues to report `production_ready: false`.

## P1 implementation progress

### Task 4 — frozen Windows service packaging

The Windows service now declares the pinned `psutil==7.2.2` runtime and PyInstaller hidden imports for the process registry and its Windows event/identity modules. The default service host already wires the monitor factory; a regression test now asserts this without importing `ui.api_server`.

| Command | Result |
|---|---|
| `python -m pytest -q tests/test_windows_protection_service_lifecycle.py tests/test_windows_process_monitor_packaging.py` | 23 passed in 18.80s. |
| `windows_protection/installer/build-service.ps1 -Configuration Test` | Built `STAIProtectionService.exe`; frozen `--stai-smoke-check` passed. The manifest correctly reports `production_ready: false`; signed-driver, VM installer/rollback and release-signing gates remain blocked. |

### Task 5 — service-first process API

On Windows, the API now checks the authenticated service pipe and uses the service-owned process monitor when its health state is `running`. Process snapshots are paged at a fixed sequence; service event gaps request a fresh snapshot. Existing details, connections, scan, sampling-profile, HTTP event and WebSocket routes use the selected provider. If IPC fails, the API keeps local telemetry available and labels it `local_fallback` with a `source_error`; it never presents the fallback as service-owned data. The WebSocket now polls at a bounded 250 ms interval and falls back to a fresh local snapshot if the service pipe drops.

| Command | Result |
|---|---|
| `python -m pytest -q tests/test_process_monitor_api.py tests/test_service_process_monitor.py tests/test_process_monitor_pipe.py tests/test_windows_pipe_client.py tests/test_process_scan_api.py` | 46 passed in 18.97s. |

### Task 6 — process analysis and evidence association

The API now feeds service-owned process-start events into the existing bounded asynchronous process-analysis worker. Repeated additions for the same stable process instance are deduplicated, including after analysis completes. A bounded analysis overlay merges entropy and scanner outcomes into service snapshots/details and retains those outcomes under the originating instance ID if the process exits before the UI requests them. Hashing and YARA remain outside the metric sampler. Local-registry analysis continues to update its registry directly.

| Command | Result |
|---|---|
| `python -m pytest -q tests/test_process_analysis.py tests/test_process_monitor_api.py tests/test_process_scan_api.py tests/test_service_process_monitor.py` | 27 passed, 16 FastAPI deprecation warnings in 19.89s. |

### Task 7 — frontend telemetry source states

The existing Processes panel displays whether telemetry comes from the Windows protection service, the local fallback, or no available collector. Fallback and unavailable states include the API-reported reason. Existing reconciliation warnings and process table behavior remain in place.

| Command | Result |
|---|---|
| `ui/hackerai/node_modules/.bin/jest.cmd app/components/svs/protection/ProcessMonitorView.test.tsx --runInBand` | 10 passed in 8.984s. React `act()` warnings were emitted by existing asynchronous detail/connection fetch tests. |
| `ui/hackerai/node_modules/.bin/tsc.cmd --noEmit` | Exited 0. |

### Task 8 — live Windows process lifecycle and performance

The live Windows test starts a harmless child process and confirms it appears in the registry without refreshing, obtains real CPU and working-set samples, then confirms it disappears after exit. No driver or service installation was required. It initially exposed an expensive reconciliation query: requesting parent PID for every process took 4.839 seconds on this host. Reconciliation now collects only PID, name, and creation time; parent PID is deferred to selected-process details or event data. This reduced measured registry startup from about 8 seconds to 0.833 seconds for roughly 390 processes.

WMI process-event subscription is denied in the current interactive user session, so this run used periodic reconciliation. The monitor reports that source limitation; it does not claim event-driven collection is active. The installed `STAIProtection` service remains stopped/manual, and its state was not changed.

Measured post-change performance on this host: approximately 393 processes, 0.833 s registry startup, 0.812 s last metrics sample, and 1.734 CPU seconds over an 8 s observation window including a sample and reconciliation (21.7% of one core). Sampling overhead remains material and needs tuning before presenting this as low-overhead protection. No benchmark is generalized beyond this host/run.

| Command | Result |
|---|---|
| `python -m pytest -q tests/test_process_monitor_windows_live.py` | Passed: real child appearance, CPU/memory sampling, and exit removal. |
| `python -m pytest -q tests/test_process_monitor.py tests/test_process_monitor_windows_live.py tests/test_windows_process_events.py tests/test_process_monitor_api.py tests/test_service_process_monitor.py tests/test_process_monitor_pipe.py tests/test_windows_pipe_client.py tests/test_process_analysis.py tests/test_process_scan_api.py tests/test_windows_protection_service.py tests/test_windows_protection_service_lifecycle.py tests/test_windows_process_monitor_packaging.py tests/test_reliability_bounded_queue.py` | 105 passed in 46.59s on the final focused run. |
| `python -m pytest -q` | **1,047 passed, 4 skipped, 17 warnings, 303 subtests passed in 290.71s.** |
| `ui/hackerai/node_modules/.bin/jest.cmd app/components/svs/protection/ProcessMonitorView.test.tsx --runInBand` | 10 passed. |
| `ui/hackerai/node_modules/.bin/tsc.cmd --noEmit` | Exited 0. |

The full backend suite emits existing FastAPI `on_event` deprecation warnings and one AnyIO alias deprecation warning. The React component tests emit existing asynchronous `act()` warnings. These did not fail verification.

## Completion boundary

P0/P1 user-mode process telemetry implementation and the Windows interactive-session lifecycle path are implemented and tested. This is not a claim that the custom antivirus is production-ready: live service context, driver load/enforcement, WFP, signing, installer rollback, and production threat-protection validation remain unverified or blocked.
