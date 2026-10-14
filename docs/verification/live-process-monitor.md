# Live Process Monitor Verification

**Validation date:** 2026-10-14
**Host:** Windows 11 Home Single Language, build 26200; Intel Core i5-1035G1, 8 logical processors; Python 3.11.9

## Automated checks

- Backend protection and process-monitor suites: **208 passed, 1 skipped**. This included process registry, metrics, event-source fallback, API stream/resync, selected-process scan, device activity, and existing protection tests.
- Dashboard suites: **20 passed** across `ProcessMonitorView` and `SvsProtectionDashboard`, including parent grouping, risk filtering, static/live sorting, and live entropy/scan-status updates.
- Entropy analysis tests cover bounded sampling, low/high entropy results, and the automatic scan handoff. The score is sampled from executable-file bytes and is not memory-region entropy. Set `SVS_PROCESS_ENTROPY_SCAN_THRESHOLD` (0–8, default 7.2) to adjust the scan trigger.
- The focused UI suites were run with the repository-installed Jest entry point. The global `pnpm` shim currently points to a missing `D:\OpenClaw` installation.
- A full Next production build and TypeScript check were attempted earlier, but stayed active with high memory use and no diagnostics; they were stopped. They remain unverified.

## Live Windows check

The harmless bounded process probe was run against the live local FastAPI monitor. It allocated a bounded working set, generated CPU activity, held a loopback TCP connection, and exited cleanly.

- Process count: **364** in SVS-Cyber and **364** from `Get-Process` at the comparison samples.
- Probe appearance: **2,496 ms** in the final run; timing varies with when the reconciliation loop next samples.
- Observed probe CPU: **12.1569%**, normalized across the host's 8 logical processors.
- Observed working set: **39,178,240 bytes**.
- Process-owned loopback connections: **3**.
- Probe disappearance after exit: **verified**.
- One metric-sampling pass over about 335 processes took about **1.016 seconds**. Normal-profile monitor CPU was measured at about **2.99% normalized across 8 logical processors**; monitor RSS reached about **32.8 MiB** after 10 seconds.

These are measurements from this host and run, not general performance guarantees. The process scan/quarantine route has automated tests; it was not exercised against a live threat sample during this check.

## Source and metric limits

- The Windows WMI process start/stop trace subscription returned **Access denied** for this account. The monitor reports the source as unavailable and uses periodic snapshot reconciliation. Process appearance therefore follows the configured reconciliation cadence rather than event-driven ETW delivery on this host.
- CPU is calculated from process CPU-time deltas and normalized to total logical CPU capacity. The first sample is unavailable until a valid delta exists.
- Memory is the measured working set. Process I/O counters are shown as bytes and are not described as physical disk throughput.
- TCP/UDP ownership is displayed when Windows exposes it. Connection ownership is not a bandwidth measurement, so throughput remains unavailable.
- Publisher/signature and GPU telemetry are not supplied by this implementation and remain unavailable. Risk remains unassessed until an executable scan returns evidence.
- No kernel minifilter or WFP driver was required for this user-mode process monitor, and monitor health does not claim kernel protection.

## Reproduce

Run `scripts/verify_process_monitor_windows.ps1` with the local protection API available. The child workload is bounded and uses a loopback connection only.
