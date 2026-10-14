# SVS-Cyber WFP Callout and Network Policy Design

## Goal

Add reliable, low-latency Windows network activity observation and narrowly scoped, reversible network containment to SVS-Cyber. Use Windows Filtering Platform (WFP) through its documented user-mode management APIs, with a separate minimal kernel callout for telemetry that needs callout-specific observation. Keep the existing filesystem minifilter separate. Complement WFP with process lifecycle telemetry so the application can attribute connection events accurately without claiming that WFP enumerates all processes.

This document is a design specification. It does not add or install a driver. The matching Windows Driver Kit (WDK) is not available in the current environment, so driver compilation and all kernel validation remain gated on a correctly provisioned isolated Windows VM.

## Current state and constraints

- `windows_protection/driver` is a Filter Manager filesystem minifilter. It handles file activity through `FltRegisterFilter`, `FltCreateCommunicationPort`, and `FltStartFiltering`; it is not a WFP network driver.
- No WFP callout project, WFP policy manager, or WFP integration tests currently exist in the repository.
- The existing protection service and named-pipe protocol are for the filesystem minifilter. WFP needs a distinct driver identity and a separately versioned, secured communication contract.
- `ui/device_activity.py` collects process and socket snapshots using psutil. It does not provide event-driven process start/stop tracking. Process identity must continue to account for PID reuse by pairing PID with process creation time.
- The local host has Windows SDK user-mode WFP headers/libraries, but lacks the matching kernel WDK headers, `Fwpkclnt.lib`, WDK build targets, and `Inf2Cat`. The WFP driver cannot be built or package-validated here. Microsoft requires compatible SDK and WDK build numbers: [WDK download and installation](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).
- The existing service has reported degraded protection. WFP work must not imply that the filesystem service or malware detection is repaired or active.

## Design decisions

1. **Create a dedicated WFP callout driver.** Keep it distinct from the filesystem minifilter and give it its own service name, provider/callout/sublayer identifiers, INF, package, lifecycle, and tests.
2. **Keep policy ownership in the Windows service.** The service uses documented `Fwpm*` management APIs and BFE transactions for narrowly scoped filters, rule state, audit, expiry, and reversal. Standard WFP filters should be preferred when they satisfy a policy. The callout exists only if a user-mode WFP event-subscription prototype cannot meet a documented event-field or timing requirement; record that comparison before adding driver code. `FwpmNetEventSubscribe*` delivers subscribed WFP net-event notifications in user mode, so it may be sufficient for current telemetry. A callout can observe selected classify indications directly, but does not mean every packet or byte is visible. Microsoft recommends using user-mode WFP management when built-in filtering is sufficient: [Callout driver programming considerations](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/callout-driver-programming-considerations), [FwpmNetEventSubscribe3](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventsubscribe3).
3. **Separate observation from enforcement.** The telemetry callout is an inline inspection callout: its filter uses `FWP_ACTION_CALLOUT_INSPECTION`, and its classify path never blocks or modifies traffic. It returns `FWP_ACTION_CONTINUE` when `FWPS_RIGHT_ACTION_WRITE` permits an action update; otherwise it leaves the current action untouched. Register it only at the required IPv4/IPv6 ALE authorization and flow-established layers; use flow-established for observation only. For exact app/endpoint blocks, prefer standard WFP filters managed through `Fwpm*`. A terminating custom ALE decision path is outside the MVP and requires a separate design, driver-loss behavior, action-right tests, and explicit enforcement gates; do not turn the observation callout into a blocker. ALE provides application/user identity at supported authorization points: [Application Layer Enforcement](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-), [Types of Callouts](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/types-of-callouts).
4. **Start in observation-only mode.** No automatic blocking is enabled by default. Any block must result from a deterministic policy decision based on high-confidence evidence or an explicitly configured rule, pass through the service's authorization path, be auditable, time-limited where applicable, and reversible.
5. **Fail open and avoid orphaned restrictive policy.** The MVP has no terminating callout filters. Do not install restrictive callout filters before the driver has registered and reported ready. Use a service-owned dynamic WFP session and transactions so service-process termination cleans up the WFP objects created with that session handle. In the MVP, provider, sublayer, management callout, and filter objects are session-owned and dynamic; installer-owned artifacts are limited to the service/driver package and service configuration. Kernel callout registration has driver lifetime and must be removed on driver unload. A service watchdog/recovery policy must terminate a hung manager process so its dynamic session closes; WFP does not automatically expire a time-limited rule while the session stays alive. A missing driver, service, or policy must not strand users behind an unavailable callout. Treat WFP's unregistered-callout behavior as a lifecycle hazard; do not rely on `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED` as a blanket safety switch because it has layer/action constraints. Microsoft documents callout registration and filter-engine behavior here: [Basic operation](https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation), [FWPM_FILTER0 flags](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0), [unloading a callout driver](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/unloading-a-callout-driver).
6. **Keep kernel callbacks bounded.** No hashing, YARA, database access, HTTP, AI, waiting on a service, or unbounded allocation in classify callbacks. Perform only required metadata extraction, a small prevalidated policy lookup if applicable, and bounded event enqueueing.
7. **Use ETW and process snapshots for process lifecycle.** Initialize a process snapshot, subscribe to supported ETW process start/stop events, reconcile periodically, and key each process by `(PID, creation time)`. Unknown or inaccessible metadata remains unknown; it is not a threat verdict.

## Components and boundaries

### WFP callout driver

Proposed location: `windows_protection/wfp/driver/` with shared ABI definitions in `windows_protection/wfp/shared/` and driver-only tests/build assets in the same WFP subtree. The exact project naming can follow repository conventions during implementation.

Responsibilities:

- Register and unregister the selected WFP callouts with the filter engine.
- Observe the minimum connection metadata available at the selected ALE layers for TCP/UDP and IPv4/IPv6 only if the user-mode event-subscription comparison establishes a real gap that requires a callout.
- Emit compact versioned telemetry to the authorized service through a restricted device interface and fixed-size IOCTL/event framing.
- The observation callout always continues and never blocks. If `FWPS_RIGHT_ACTION_WRITE` is absent, it leaves the action untouched. A future terminating ALE callout requires a separate design, driver-loss semantics, action-right tests, and explicit enforcement approval; it may consult only a bounded, prevalidated in-memory policy representation.
- Maintain bounded queues and monotonic event sequence/drop counters; release all resources on unload.

The driver does not enumerate processes, calculate file entropy, scan files, classify malware, resolve domains, call AI, or execute commands from user mode.

### Windows service WFP manager

The existing `STAIProtectionService` may host the manager after implementation review, but the WFP driver is a separate kernel component and must not reuse the minifilter's file protocol as an implicit network protocol.

The manager owns:

- A uniquely identified provider and sublayer, with documented ownership of every filter and callout object it creates.
- WFP engine/session lifecycle, BFE transactions, readiness gating, policy validation, audit records, TTL expiry, removal, and rollback.
- Standard WFP filters for exact app/endpoint policies where built-in filtering is sufficient; the observation callout itself is not a policy enforcement path.
- Maximum lifetime enforcement and manager watchdog/recovery. Every temporary containment filter is created in the dynamic policy session; service health loss closes that session and removes its owned filters.
- Driver readiness handshake before registering any restrictive callout filters.
- A separate authenticated, versioned, strictly validated driver-to-service interface. Access is limited to the service SID; messages have fixed upper bounds, sequence numbers, and no arbitrary memory or command fields.
- Graceful handling of driver/service restart, device removal, BFE unavailability, queue saturation, malformed messages, and stale policy.
- Teardown ordering: delete session-owned WFP filters before unregistering callouts or unloading the driver; verify this ordering under normal shutdown and failure recovery.

Use service-owned GUIDs to enumerate and remove only SVS-Cyber objects. Never clear unrelated WFP filters or alter system-wide policy. Establish and test transaction rollback before enabling any enforcement mode.

### Process and connection attribution

The user-mode process monitor combines an initial snapshot, ETW process start/stop events, and periodic reconciliation. It carries process identity as `(PID, creation time)` across API responses and event correlation, so PID reuse cannot attach a later connection to an earlier process. Access-denied path, command line, publisher, or hash fields stay unavailable rather than being guessed.

The WFP event carries the PID and application identity only when Windows exposes them at the chosen layer. The backend joins that metadata to the process monitor's identity table. If attribution is stale or incomplete, the UI displays an unknown/unresolved owner. WFP is not a complete process inventory or a general packet-capture mechanism. ALE authorization reports TCP connect/accept and first UDP packets for a unique remote tuple; flow-established follows the TCP handshake and follows authorization immediately for UDP. Reauthorization is not a new connection and must be labeled/deduplicated. UDP termination is not indicated at a WFP layer. The MVP does not associate a kernel flow context for close notification; it reports observed flows and uses user-mode socket reconciliation for current-state snapshots, with close time/status marked unavailable unless confirmed by that source. These limits are documented in [ALE layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers), [UDP packet flows](https://learn.microsoft.com/en-us/windows/win32/fwp/udp-packet-flows), and [ALE reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization).

### Event pipeline and UI

The service normalizes WFP events and process lifecycle events into the existing backend's device-activity model. Each record distinguishes observation from a policy verdict and includes evidence/reason, timestamp, direction, IP family, protocol, endpoint fields when available, process identity, WFP layer, reauthorization status, and capture/attribution status. The UI shows only values delivered by these sources. It must not invent packet payload visibility, total traffic volume, exact per-flow byte counts, or malware verdicts from entropy/network activity alone. The kernel event path never blocks waiting for consumers: a bounded queue drops on saturation, increments a counter, and preserves sequence gaps so user mode can report incomplete telemetry.

Network events are correlated with existing file/hash/YARA evidence in user mode. Network behavior alone can be suspicious evidence, but is not a malware verdict. AI may summarize or investigate evidence, but it cannot issue WFP/kernel commands; enforcement remains deterministic and service-authorized.

## Failure behavior and safety invariants

- Installation, driver load, and policy activation are separate health states. API liveness or process visibility does not imply that WFP filtering is active.
- Initial behavior is observation-only. Restrictive filters remain absent unless the service, driver, BFE session, policy, and authorization state all pass readiness checks and enforcement has been explicitly enabled.
- If the service process terminates, its dynamic session removes only the WFP objects created through that session handle. If the driver disconnects, the observation callout cannot block; the manager marks telemetry degraded, closes the dynamic policy session, and removes its temporary containment filters before rebuilding readiness. The MVP uses ordinary WFP filters for blocking, not filters referencing an unregistered terminating callout. A watchdog must terminate a hung manager so session cleanup still occurs. Invalid policy is rejected transactionally. The product reports the actual failure/degraded reason.
- Loopback, local networking, essential Windows connectivity, and unrelated WFP policy are protected from broad rules. Rules target exact application identity or exact endpoint/protocol/direction scopes, with bounded lifetime and explicit reason.
- Removing a rule records the reversal and result. The UI must not imply an existing connection was terminated unless that behavior is separately verified.
- No real malware is required for development. Driver and enforcement tests use benign fixtures and controlled local endpoints in an isolated VM.

## Phased implementation boundary

1. **Policy manager and event contract:** define stable identifiers, versioned event/policy schemas, ownership, readiness, safe dynamic-session lifecycle, and user-mode WFP capability checks. Prototype `FwpmNetEventSubscribe*` and compare its fields, completeness, and observed latency with the requirements. Keep enforcement disabled. Add the custom inspection callout only if the prototype demonstrates a required gap.
2. **Process lifecycle telemetry:** add snapshot + ETW starts/stops + reconciliation and stable identity correlation. Preserve snapshot fallback and report ETW health separately.
3. **Observation callout:** implement the minimal separate WFP driver and secured event transport. Validate event loss/backpressure and driver/service recovery.
4. **UI and evidence integration:** connect real process/network rows to the dashboard and show operational state and evidence accurately.
5. **Controlled enforcement:** only after review and VM validation, enable exact, reversible, authorized WFP rules. Default installation/configuration remains observation-only until separately approved and signed.

The feature is not complete when only the manager, mock, or UI exists. Each phase reports precisely what is active and what remains unavailable.

## Verification and acceptance criteria

### Source-level and host tests

- ABI tests cover version, field lengths, enum values, malformed/truncated messages, sequence handling, and unknown fields.
- Production C classify code has direct tests proving the observation callout never blocks, handles supported layers and absent/invalid metadata safely, and respects `FWPS_RIGHT_ACTION_WRITE`. If a separate terminating ALE callout is later approved, its allow/deny/no-decision, unregistered-driver, and action-right behavior must have direct C tests; Python-only reimplementations are not sufficient evidence.
- Manager tests cover policy validation, exact GUID ownership, dynamic-session teardown, BFE transaction commit/rollback, TTL expiry, duplicate/reversal behavior, driver readiness ordering, and all failure states.
- Queue tests cover bounded memory, nonblocking callback behavior, backpressure, drops, sequence gaps, shutdown, and concurrent producers/consumers.
- Process tests cover initial enumeration, start/stop, short-lived processes, PID reuse, missing permissions, and reconciliation.
- Integration tests verify that unavailable sources stay degraded and never become a clean/protected verdict.

### Isolated Windows VM tests

After installing the matching WDK/SDK and preparing a disposable Windows test VM, validate build/package/signing, driver load/unload, HVCI compatibility where supported, Driver Verifier, WFP layer behavior, BFE transactions, service/driver crash and recovery, manager watchdog behavior, queue saturation and reported sequence gaps, and controlled IPv4/IPv6 TCP/UDP plus loopback allow/block/reversal cases. Test reauthorization deduplication and application attribution where Windows exposes it. Capture test logs and confirm only SVS-owned policy objects are changed.

### Completion gates

- A matching WDK build and package validation succeed; no kernel build claim is made before this evidence exists.
- The callout is installed and exercised only in an isolated VM with a test-signed driver and supported development settings; host security settings are not weakened.
- Observation starts with no blocking policy and reports event drop/health state.
- Exact policy can be enabled, audited, expired, removed, and verified to restore access in the VM.
- Service/driver/BFE failures produce a visible degraded state and do not leave restrictive orphaned policy.
- Driver-loss and watchdog paths remove only SVS-owned temporary filters, then allow policy recreation only after readiness is restored.
- UI data is sourced from real event/process collectors and labels unknown or unsupported fields accurately.
- Automated unit/integration evidence and VM/kernel evidence are reported separately. Neither mocks nor source inspection count as kernel validation.

## Out of scope

- Modifying the existing filesystem minifilter to handle network traffic.
- General packet capture, payload/TLS inspection, network-byte accounting, or claims that every flow is visible.
- Automatic malware verdicts based on entropy, process name, destination reputation alone, or AI output alone.
- Installing an unverified driver on the developer/user host, disabling Secure Boot/HVCI/signature enforcement, or testing with real malware.
- Broad third-party threat-feed ingestion, a kernel hash/YARA engine, a production signing program, or replacement of Windows Defender.
- Claiming that this WFP work fixes the currently degraded filesystem protection service.

## References

- [Microsoft: Callout driver programming considerations](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/callout-driver-programming-considerations)
- [Microsoft: Application Layer Enforcement (ALE)](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-)
- [Microsoft: WFP basic operation](https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation)
- [Microsoft: FWPM_FILTER0 flags](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)
- [Microsoft: Registering callouts with the filter engine](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/registering-callouts-with-the-filter-engine)
- [Microsoft: Processing classify callouts](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts)
- [Microsoft: Types of callouts](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/types-of-callouts)
- [Microsoft: ALE layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)
- [Microsoft: UDP packet flows](https://learn.microsoft.com/en-us/windows/win32/fwp/udp-packet-flows)
- [Microsoft: ALE reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)
- [Microsoft: WDK download and installation](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
