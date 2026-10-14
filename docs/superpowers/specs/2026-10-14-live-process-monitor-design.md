# SVS Cyber Live Process Monitor

## Goal

Upgrade the existing Processes and Network Activity views into a responsive, evidence-backed Windows process monitor. Real process state, measured metrics, and antivirus findings must stay tied to a stable process instance; inaccessible or unsupported measurements must be shown as unavailable.

## Current repository state

- `ui/device_activity.py` collects process snapshots, connections, and asynchronously cached executable assessments; it remains the source for its existing device-activity endpoint.
- `ui/api_server.py` exposes `/api/device/activity` with loopback and allowed-origin checks.
- The Windows dashboard is `ui/hackerai/app/components/svs/SvsProtectionDashboard.tsx`; before this work it had no dedicated Processes tab. Its local FastAPI client is `ui/hackerai/lib/stai-protection-api.ts`.
- `process_identity` and connection ownership helpers exist in `ui/device_process_identity.py` and are reused so process and socket evidence share one identity scheme.
- This implementation adds a dedicated process registry, local stream, Processes tab, and selected-process details while keeping the independent device-activity collector intact.

## Design

### Collection and identity

Keep the current collector as the source for existing scan assessments and compatible snapshots. Add a dedicated process-monitor registry that uses an accessible startup snapshot, Windows process-trace notifications where available, and periodic snapshot reconciliation to repair dropped events, races, permission changes, and PID reuse. The implementation uses `Win32_ProcessStartTrace`/`Win32_ProcessStopTrace` WMI notifications without taking over a global kernel trace session. If the subscription is unavailable, continue with reconciliation and expose the fallback state and error. Do not require the unfinished minifilter driver for user-mode process enumeration.

Identify each process instance by PID plus validated creation time (or an equivalent OS-provided instance token). Process exit must remove only the matching instance and preserve bounded investigation history. Process metadata lookup failures are per-process partial data, not reasons to drop the row.

### Metrics and analysis

Sample CPU from process CPU-time deltas and normalize against total logical CPU capacity. Mark the first or invalid sample unavailable. Collect working-set memory, thread count, supported per-process I/O counters, and accessible executable metadata. Label generic I/O counters accurately; do not call them physical-disk throughput. Connections may show protocol, endpoints, state, and verified owner when Windows provides that data. Do not infer per-process bandwidth from connection ownership. GPU and unsupported throughput remain unavailable unless a genuine supported source is integrated.

Do not hash or scan in the sampling loop. Reuse the existing bounded asynchronous executable analysis and cache. A high entropy value is review evidence only; it may flag an executable for analysis but cannot alone justify process termination or quarantine. Any disruptive action remains behind existing authorization and policy code and must show its real result.

### Backend and synchronization

Add a thread-safe registry with stable instance identifiers, sequence numbers, bounded event/history queues, dropped-event/source-health counters, clean startup/shutdown, and reconciliation. Add read-only process snapshot, detail, connection, and monitor-status routes protected by the same loopback/origin policy as device activity. Publish a process snapshot at connection, then bounded deltas/metrics over a dedicated authenticated local WebSocket or a compatible extension to the existing local channel. Check sequences and resynchronize after reconnect. Collection must not wait on slow WebSocket clients. Keep file analysis off the high-frequency path.

Provide Low resource, Normal, and High-frequency profiles. Normal is 5-second sampling/reconciliation, Low is 10 seconds, and High-frequency requests 1-second metrics with 2-second reconciliation. Normal's 5-second cadence reflects measured Windows overhead: a CPU/memory pass takes about one second for roughly 335 processes on the validation host. Process trace callbacks remain event-driven when available. Report actual source, sample duration, and refresh health; measure rather than claim event-to-display latency.

### Dashboard

Extend the existing dark SVS Cyber Processes view; do not add a separate application. Display actual Process, PID, CPU, working-set memory, accurately labeled I/O, connections, and evidence-based risk. Add optional columns for publisher/signature and supported telemetry. Provide name/PID search, evidence/network filters, stable process selection, expandable details, parent grouping where metadata is available, pause/resume display, and an optional live-sort mode. Preserve the current Network Activity view. Do not inject synthetic runtime processes or fabricated charts.

Details must clearly distinguish unavailable, access denied, pending, and measured values. The local UI can request an executable scan through the existing signed-rule scanner; high-confidence block detections use the existing quarantine policy, and the route returns the actual verdict, hash, rule, and containment result. Hash/YARA evidence appears only after a scan actually produced it. Any process action must use existing authorization/policy checks and confirm its recorded outcome.

Each new process instance is also queued for a bounded asynchronous entropy sample of its executable file. The UI displays the sampled Shannon entropy in bits per byte; the default `SVS_PROCESS_ENTROPY_SCAN_THRESHOLD` is 7.2 (configurable from 0 to 8). Scores at or above the threshold trigger the existing executable scanner asynchronously. Entropy is triage only and cannot itself block, quarantine, or terminate a process. This implementation measures the on-disk executable sample; memory-region entropy is a separate capability and is not represented as available here.

## Security and compatibility constraints

- Preserve protection status semantics, named-pipe schemas, authentication, authorization, and operation allowlists.
- Do not claim kernel protection from process-monitor health.
- Do not use repeated PowerShell or `tasklist.exe` invocations for collection.
- Do not install or load experimental or unsigned drivers.
- Never bind evidence to PID alone or transfer evidence across PID reuse.
- Do not terminate critical Windows processes because of entropy or another weak heuristic.

## Verification

Tests should cover registry start/exit and PID reuse, source fallback/health, metric deltas and invalid first samples, access-denied partial metadata, bounded history/backpressure, API authorization, reconnect/resync, and dashboard selection/sorting/filtering. Windows runtime checks should launch and exit a harmless process, exercise controlled CPU/memory changes, and attribute a local TCP connection where permitted. Compare against Task Manager using documented metric definitions and sampling tolerances. Record measured idle overhead, event latency, update bandwidth, and performance with hundreds of processes; do not invent benchmark results. Where this environment cannot exercise WDK or ETW scenarios, state that limitation explicitly.

## Out of scope

This feature does not implement a new kernel minifilter, network firewall, per-process network byte attribution without a supported source, a malware corpus/database, or autonomous process termination based only on heuristic scores.

## Acceptance criteria

1. Real processes appear and exit without manual refresh, using ETW when available and a clearly reported reconciliation fallback otherwise.
2. CPU and memory values update from measured Windows data; first samples and inaccessible values are not fabricated.
3. Stable process instance IDs prevent PID reuse from corrupting selection, connections, or detection history.
4. The existing antivirus assessment is associated only with the exact executable/process instance and remains off the sampling loop.
5. Reconnects resynchronize without duplicate rows; slow clients do not block collection.
6. Existing dark Processes and Network Activity views stay integrated and expose monitor health and real limitations.
7. Automated and live checks report passed, failed, and environment-blocked cases separately.
