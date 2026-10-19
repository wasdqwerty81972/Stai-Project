# SVS-Cyber WFP Callout Implementation Plan

> **For implementation agents:** Follow this plan in order. Keep the filesystem minifilter unchanged. Treat this plan and `docs/superpowers/specs/2026-10-14-svs-cyber-wfp-callout-design.md` as the approved scope.

**Goal:** Build a reliable Windows Filtering Platform (WFP) network telemetry and reversible policy subsystem, starting with a user-mode WFP event/policy manager and process lifecycle correlation. Add a separate observation-only kernel callout only if the user-mode event subscription plus process reconciliation leaves a measured required gap.

**Architecture:** Put WFP components under `windows_protection/wfp/` and normalized models/manager under `cyber_os/network_telemetry/`. Keep WFP policy and service health separate from `windows_protection/driver` filesystem minifilter health. The Windows service owns the dynamic WFP session, subscribes without changing global event collection options, and exposes bounded read-only telemetry through its authenticated local pipe. A small native SDK-built helper may wrap WFP APIs where Python `ctypes` cannot safely express the callback ABI. No WFP object is installed on this host while implementing or verifying source behavior.

**Safety contract:** No live filter/audit setting changes, no automatic blocking, no driver installation, no malware execution, and no host security-setting changes. Standard WFP app/endpoint rules are kernel-enforced and may be added only through explicit validated service policy. Temporary rules are dynamic-session-owned, exact, audited, time-limited, and reversible. The custom callout (if needed) is inspection-only and always continues traffic. Kernel build/load/enforcement validation is gated on matching WDK/SDK plus a disposable Windows VM.

## Repository facts

- `windows_protection/driver/StaiProtection.vcxproj` is an existing Filter Manager filesystem minifilter; do not add network logic to it.
- `ProtectionServiceHost` in `cyber_os/protection/windows_service.py` already owns optional sensor lifecycle and the authenticated pipe.
- `ui/device_activity.py` and `ui/device_process_identity.py` provide process/socket snapshots and PID+creation-time ownership; `tests/test_device_activity.py` and `tests/test_device_process_identity.py` cover current behavior.
- WFP user-mode SDK artifacts are present, but WDK kernel headers, `Fwpkclnt.lib`, driver targets, and `Inf2Cat` are absent. `FWPM_NET_EVENT_HEADER3` contains app/user and endpoint metadata but no PID. The custom callout gate therefore depends on whether ETW plus socket reconciliation provides the required owner attribution; do not infer PID from app ID.

## Task 1: Add normalized telemetry and policy contracts

**Files:**
- Create `cyber_os/network_telemetry/__init__.py`.
- Create `cyber_os/network_telemetry/models.py`.
- Create `tests/test_wfp_telemetry_models.py`.

**Changes:**
- Define strict, versioned event and health structures for WFP net events, process lifecycle events, and socket snapshots.
- Preserve UTC timestamp, source sequence, event type, layer/type, direction, IP family, protocol, local/remote endpoint, app ID/user SID, optional PID, stable process identity, reauthorization marker/reason, policy action/reason/rule ID, attribution state, and source loss/health counts.
- Bounds-check strings, buffers, ports, addresses, IDs, event count, and enum values. Unknown fields remain unavailable. Never use PID without creation time as stable identity.
- Keep source health independent from antivirus/minifilter `active` status. The event schema has no implied malware verdict or network byte/packet counters.

**Verification:** Run the new model tests and existing device-identity/activity tests. Verify malformed, oversized, unknown-version, and PID-only records are rejected or represented as unresolved.

## Task 2: Add WFP event subscription capability path

**Files:**
- Create `windows_protection/wfp/native/` for an SDK-only native bridge if callback ABI inspection confirms Python `ctypes` is unsafe.
- Create `cyber_os/network_telemetry/wfp_events.py` for subscription lifecycle, normalization, source health, and bounded snapshot/drain API.
- Create `tests/test_wfp_event_source.py`.
- Update `windows_protection/installer/pyinstaller.spec` and build script only if the bridge is required for the packaged service.

**Changes:**
- Open a user-mode WFP engine session and subscribe with documented `FwpmNetEventSubscribe*` APIs. Copy callback data into a bounded queue before callback return; never retain WFP-owned pointers.
- Subscribe to supported classify allow/drop events without calling `FwpmEngineSetOption*`; do not enable persistent global event collection or alter audit/firewall state.
- Normalize only fields whose WFP flags mark them present. Preserve event type/layer/action, app ID/user SID, endpoints, direction, reauthorization reason, queue drops, and source health. WFP net-event metadata does not contain PID.
- Implement deterministic unsubscribe/engine close, BFE unavailable/access denied/subscribe-failure states, and bounded overflow counters/sequence gaps.
- Add a Windows-only benign local-connection probe behind an explicit opt-in test command; it reports coverage and latency but does not change firewall/audit settings or claim universal flow visibility.

**Verification:** Run mock adapter tests on this host. A Windows VM probe is required to claim real BFE subscription/event delivery. Do not run an unrequested live subscription against the user's host as part of development.

## Task 3: Add safe WFP policy manager with enforcement disabled

**Files:**
- Create `cyber_os/network_telemetry/wfp_policy.py`.
- Create `tests/test_wfp_policy_manager.py`.
- Add only native bridge APIs needed by this manager under `windows_protection/wfp/native/` if the SDK interface is not safely callable from Python.

**Changes:**
- Inject a `WfpApi` adapter for session, transaction, provider/sublayer, filter enumeration/add/delete, and close calls; test manager logic without opening BFE.
- Own temporary objects through a `FWPM_SESSION_FLAG_DYNAMIC` service session. Never delete objects by broad enumeration or foreign GUID. Establish stable SVS provider/sublayer GUIDs.
- Keep `enforcement_enabled=False`. Reject policy by default; provide only exact app ID/endpoint, protocol, direction, reason, rule ID, expiry, and authorization records. Reject wildcard/broad rules and loopback/local-network protection scopes.
- Implement transaction begin/commit/abort, idempotent exact add/remove, TTL, reversal/audit, manager watchdog contract, and cleanup on stop/health loss. Never install a restrictive callout filter in this phase.
- Do not turn the disabled manager into an API/UI action surface yet.

**Verification:** Fake-adapter tests cover readiness gates, unauthorized/default-deny rule requests, dynamic object ownership, transaction rollback, exact cleanup, TTL, duplicate operations, BFE failures, service stop, driver-not-ready, and preservation of unrelated filters. No host BFE mutation.

## Task 4: Add process lifecycle telemetry and stable correlation

**Files:**
- Create `cyber_os/network_telemetry/process_events.py` and, if needed, an SDK-built ETW helper under `windows_protection/wfp/native/`.
- Extend `ui/device_process_identity.py` only if a shared event identity helper is missing.
- Add `tests/test_process_lifecycle_telemetry.py`.

**Changes:**
- Start process event collection before the initial snapshot; buffer and deduplicate the snapshot/ETW race; reconcile periodically.
- Use documented ETW process start/stop events where available, keyed by `(PID, creation time)`. Report ETW unavailable/permission/session conflict as snapshot-only or degraded, never clean.
- Enrich WFP app ID with exact process identity only when unambiguous. If the ETW/socket snapshot cannot resolve a short-lived or reused PID, mark owner unresolved; never guess from process name or app ID alone.
- Keep command line, publisher, hash, and path optional when Windows denies access.

**Verification:** Mock tests cover start/stop, short-lived processes, snapshot races, duplicate/reordered events, PID reuse, unknown stop, access denied, reconciliation, and ETW unavailable. A benign-child Windows ETW smoke test runs only in a disposable VM.

## Task 5: Integrate the optional network telemetry into the service and local API

**Files:**
- Update `cyber_os/protection/windows_service.py` to own and report optional WFP/process monitor lifecycle.
- Update pipe schemas/dispatch with a read-only telemetry snapshot operation and strict bounded response.
- Update `ui/api_server.py` and `ui/device_activity.py` to merge service telemetry with current snapshots without presenting the WFP monitor as AV/minifilter health.
- Add `tests/test_wfp_service_lifecycle.py` and extend relevant API tests.

**Changes:**
- Start/stop sources independently and preserve degraded reasons per source; optional source failure must not crash the protection pipe or change current antivirus readiness.
- Expose actual source state, events, sequence gaps, drops, coverage, and timestamps through loopback/authenticated local APIs. Keep unrelated health states separate.
- Keep UI changes minimal until event fields and lifecycle data are stable; no fabricated byte rates, threat verdicts, or `active` status.

**Verification:** Fake monitor lifecycle tests prove order/idempotence/cleanup and status truthfulness. API tests prove local access controls and exact source-health mapping. Existing protection service lifecycle and device activity tests remain green.

## Task 6: Decide and implement the separate inspection callout only if justified

**Files if the gate is met:**
- Create `windows_protection/wfp/driver/` with independent WDM/WFP project, service identity, INF/package, and source.
- Create fixed-size shared event ABI in `windows_protection/wfp/shared/`.
- Add C classify tests/harness and update the WDK VM validation scripts.

**Gate:** A measured required event field or latency requirement is still absent after WFP event subscription, ETW, and socket reconciliation. In particular, per-event PID is not in the WFP net-event header; ETW/socket correlation must be assessed before claiming that a callout solves owner attribution.

**Changes:**
- Driver registers only needed ALE v4/v6 callouts and emits compact bounded telemetry. Observation filter action is `FWP_ACTION_CALLOUT_INSPECTION`; classify always continues, respects `FWPS_RIGHT_ACTION_WRITE`, and never blocks.
- Use a restricted service-SID interface, versioned fixed-size records, bounded nonblocking queue, sequence/drop counters, deterministic driver unload, and no analysis/AI/database work in kernel.
- No terminating callout in MVP. Standard WFP filters remain the only block mechanism and are dynamic-session-owned.

**Verification:** Source build/package and `Inf2Cat` require the matching WDK. Driver load/unload, HVCI/Driver Verifier, real classify metadata, v4/v6 TCP/UDP, loopback, event pressure, BFE/service/driver failure, cleanup, and rule reversal require a disposable Windows VM. Never install or test the driver on this host.

## Task 7: Report completion accurately

- Run the authorized automated tests and list the exact command/results.
- Separate host/mock/unit evidence from real Windows WFP/ETW and kernel VM evidence.
- State whether the callout gate was met and whether the WDK/VM validation remains pending.
- Keep filesystem minifilter degradation visible and do not claim that network filtering repaired it.

## Execution notes

- Do not reset or stage the existing dirty working tree. Keep changes limited to new WFP/network telemetry files and necessary integration points.
- Do not enable global WFP event collection, add real filters, install the driver, alter audit policy, change Windows security settings, or test with real malware.
- If native compilation is unavailable, preserve source, report the exact missing SDK/WDK component, and do not claim a successful native build.
