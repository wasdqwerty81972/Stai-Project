# Always-On Sensor Response Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Start the Windows sensor runtime at boot, show honest per-sensor status, and route detected anomalies through protection or AI triage without losing warnings.

**Architecture:** Extend the existing `STAIProtection` Windows service to host the sensor collector and a durable warning/response coordinator. The local API reads status and pending AI escalations through the protected named-pipe boundary; the React UI presents sensors by category and warnings. File anomalies are checked by the local protection engine first; non-file anomalies go directly to the AI agent, and AI recommendations retain the existing human approval checks.

**Tech Stack:** Python 3.11, pywin32 Windows service and named-pipe APIs, SQLite, FastAPI, React/TypeScript, existing protection engine and CyberAgent runtime.

**Spec:** `docs/superpowers/specs/2026-10-13-cyberos-sensors-always-on-response-design.md`

## Global Constraints

- The installed Windows sensor runtime starts at Windows boot independently of the UI/API process.
- All 256 catalog rows remain visible under their existing `category` and `layer`; a row reports `collecting` only when a real configured collector is healthy.
- The service does not silently change Windows audit policies, install third-party collectors, or enable privacy-sensitive collection.
- A file path needed for a protection scan may be passed transiently in memory to the local protection engine, but is not added to the durable sensor event or sent to the UI/AI agent.
- File anomalies go to the installed protection engine first; `blocked` or `contained` requires explicit confirmation. An unresolved or unverified file anomaly goes to AI triage.
- Non-file anomalies go directly to AI triage because the file protection engine cannot act on them.
- Disruptive AI recommendations remain behind the existing human approval flow.

## Review Focus

- **Protection service unavailable at boot:** service remains running, reports protection `unknown`, persists the warning, and queues AI escalation.
- **Event queue replay after process restart:** a repeated event ID produces one warning and one AI investigation.
- **File anomaly with paths omitted by privacy settings:** the transient local path may be used only for protection; it is absent from durable records, UI payloads, and AI context.
- **Protection returns `clean` or times out:** a clean scan does not mark a behavioral anomaly handled; unresolved cases reach AI with the correct outcome.
- **AI requests a disruptive action:** the action cannot run without the current explicit approval path; collection and warning delivery continue while approval is pending.

---

### Task 1: Host sensors in the boot-start protection service

**Files:**
- Modify: `cyber_os/protection/windows_service.py`
- Modify: `cyber_os/sensors/windows_sensor_service.py`
- Create: `scripts/install_stai_protection_service.ps1`
- Test: `tests/test_windows_protection_service_lifecycle.py`
- Test: `tests/test_windows_sensor_service.py`

**Interfaces:**
- `ProtectionServiceHost.__init__(..., sensor_service: Any | None = None, response_coordinator: Any | None = None)` receives the service-owned sensor runtime and its event handler.
- `ProtectionServiceHost.start() -> None` starts health, protection, named-pipe, and sensor components idempotently; a sensor startup failure is recorded without falsely reporting that its sources are active.
- `ProtectionServiceHost.stop() -> None` stops the sensor runtime and response workers before closing the host.
- Sensor runtime contract: `start() -> bool`, `stop(timeout: float = 5.0) -> bool`, `get_status() -> dict[str, Any]`.

- [ ] **Step 1: Write failing lifecycle tests** for automatic sensor start, idempotent host start/stop, and sensor-start failure reporting.
- [ ] **Step 2: Run the focused lifecycle tests and verify they fail for the missing sensor ownership.**
- [ ] **Step 3: Wire the sensor runtime into `ProtectionServiceHost`** using an injected instance/factory so tests can provide a fake; do not start a second parallel Windows service.
- [ ] **Step 4: Add an elevated install/update script** that installs or updates `STAIProtection` with `--startup auto`, verifies its SCM start type is Automatic, and documents service stop/uninstall commands; retain the existing service identity.
- [ ] **Step 5: Run the focused lifecycle tests and verify clean shutdown and recovery status.**
- [ ] **Step 6: Commit the service lifecycle slice.**

### Task 2: Publish catalog-aligned runtime status through the local service API

**Files:**
- Modify: `cyber_os/sensors/sensor_registry.py`
- Modify: `cyber_os/engine.py`
- Modify: `cyber_os/protection/windows_service.py`
- Modify: `ui/api_server.py`
- Test: `tests/test_sensor_registry.py`
- Test: `tests/test_windows_protection_service.py`
- Test: `tests/test_ui_api_contract.py`

**Interfaces:**
- Runtime capability records use canonical `registry_id` values; legacy Phase 1 `id` aliases remain accepted during migration.
- `CyberOSEngine` no longer creates, starts, or stops a process-local `WindowsSensorService`; the Windows service is the single collector owner.
- Add named-pipe operation `get_sensor_status` with an empty payload; it returns the service state, all 256 catalog rows, source states, errors, queue state, and privacy settings.
- `GET /api/sensors/status` reads that operation and returns the same JSON shape to the UI.
- Remove the process-local `POST /api/sensors/start` and `POST /api/sensors/stop` controls; the Windows service manager owns collector lifecycle after installation.

- [ ] **Step 1: Write failing tests** for canonical ID mapping, all 256 rows, non-Windows unsupported states, and pipe/API status forwarding.
- [ ] **Step 2: Run the focused tests and verify they fail on the current phase-1-only runtime join.**
- [ ] **Step 3: Join runtime evidence using canonical catalog IDs** while retaining the legacy alias mapping.
- [ ] **Step 4: Add the allowlisted `get_sensor_status` pipe operation and API forwarding.**
- [ ] **Step 5: Remove the process-local sensor start/stop routes** so they cannot start a duplicate collector or imply a false stop.
- [ ] **Step 6: Run the focused tests and confirm catalog rows with no collector remain `not_implemented`, `integration_required`, or `unsupported_on_host`.**
- [ ] **Step 7: Commit the status contract slice.**

### Task 3: Detect anomalies, persist warnings, and coordinate protection outcomes

**Files:**
- Create: `cyber_os/sensors/warnings.py`
- Create: `cyber_os/sensors/anomaly_rules.py`
- Create: `cyber_os/sensors/response_coordinator.py`
- Modify: `cyber_os/sensors/windows_sensor_service.py`
- Modify: `cyber_os/protection/service.py`
- Modify: `cyber_os/protection/windows_service.py`
- Test: `tests/test_sensor_response_coordinator.py`
- Test: `tests/test_windows_protection_service.py`
- Test: `tests/test_windows_sensor_service.py`

**Interfaces:**
- `SensorWarning` contains `event_id`, `sensor_ids`, `timestamp`, `severity`, `summary`, redacted `evidence`, `protection_state`, and `ai_state`.
- `SensorAnomalyRules.evaluate(event: SensorEvent) -> SensorWarning | None` applies deterministic rules; the initial event-log rule emits a brute-force warning at the configured `failed_logons` count within `failed_logon_window` seconds (defaults: 5 failures in 60 seconds).
- `SensorResponseCoordinator.submit_warning(warning: SensorWarning, *, artifact_path: str = "") -> None` persists a warning before response work, uses `event_id` as its idempotency key, and never persists `artifact_path`.
- Add `ProtectionService.scan_file_for_sensor(path: Path) -> tuple[ScanVerdict, str]` to record a sensor-triggered scan without invoking the existing immediate `on_detection` triage callback; the coordinator owns escalation after verifying protection outcome. The minifilter's current callback behavior stays unchanged.
- `SensorEvent` gains a private `_protection_target: str` field populated from eligible file events; `SensorEvent.to_dict()` always omits it. The collector passes it only to `SensorResponseCoordinator.submit` in the current process.
- `SensorResponseCoordinator.get_warnings(limit: int = 100) -> list[dict[str, Any]]` returns redacted warning records newest first.
- `SensorResponseCoordinator.claim_ai_escalations(worker_id: str, limit: int = 20, lease_seconds: float = 60.0) -> list[dict[str, Any]]` claims or reclaims expired escalations; `complete_ai_escalation(event_id: str, worker_id: str, result: dict[str, Any]) -> bool` records completion idempotently.
- Protection outcome values are exactly `pending`, `blocked`, `contained`, `clean`, `failed`, and `unknown`; AI values are `not_required`, `pending`, `running`, `completed`, and `failed`.

- [ ] **Step 1: Write failing store/coordinator tests** for persistence, event replay, file vs. non-file routing, privacy redaction, and outcome transitions.
- [ ] **Step 2: Run the focused tests and verify each fails for the missing warning contract.**
- [ ] **Step 3: Implement `SensorAnomalyRules.evaluate`** using the configured failed-login threshold/window; unrelated observations do not create warnings.
- [ ] **Step 4: Implement the SQLite warning store and `SensorResponseCoordinator`** with unique event IDs and atomic claim/complete operations.
- [ ] **Step 5: Pass `_protection_target` transiently from normalization to the coordinator** without including it in `SensorEvent.to_dict()` or SQLite; if a process restart loses that target, record protection as `unknown` and retain the redacted warning for escalation.
- [ ] **Step 6: Add `scan_file_for_sensor` so a sensor-triggered finding does not invoke AI triage before protection outcome is known; leave minifilter detection callbacks unchanged.**
- [ ] **Step 7: For an eligible file anomaly, call `scan_file_for_sensor` and quarantine only a confirmed signed-rule block; record `contained` only after the quarantine outcome confirms success.**
- [ ] **Step 8: Queue AI escalation for non-file anomalies and file anomalies with `clean`, `failed`, or `unknown` outcomes; do not treat scan completion as containment.**
- [ ] **Step 9: Add allowlisted pipe operations `list_sensor_warnings`, `claim_sensor_ai_escalations`, and `complete_sensor_ai_escalation` with strict payload validation, lease expiry/reclaim, and the existing local-client ACL.**
- [ ] **Step 10: Run focused tests for duplicate delivery, protection unavailable, ambiguous clean scan, and path privacy.**
- [ ] **Step 11: Commit the warning and response coordinator slice.**

### Task 4: Deliver queued escalations to the AI agent

**Files:**
- Modify: `ui/api_server.py`
- Modify: `cyber_agent.py`
- Modify: `cyber_os/agent_runtime.py`
- Test: `tests/test_sensor_ai_escalation.py`
- Test: `tests/test_ui_api_contract.py`

**Interfaces:**
- Add an API-startup background worker that calls the protected service pipe for pending escalations; it does not start or stop the Windows sensor runtime.
- `CyberAgent.investigate_sensor_warning(warning: dict[str, Any]) -> None` submits redacted sensor evidence to `agent_runtime.run_investigation` with a stable investigation ID derived from `event_id`.
- The worker calls `complete_sensor_ai_escalation` only after an investigation result is persisted; unavailable agent/API leaves the item queued for retry.

- [ ] **Step 1: Write failing tests** for stable investigation IDs, suppression of concurrent duplicate claims, API offline/restart replay, AI failure retry, and privacy-filtered investigation context.
- [ ] **Step 2: Run the focused tests and confirm they fail because the agent is not connected to sensor warnings.**
- [ ] **Step 3: Add the idempotent `CyberAgent.investigate_sensor_warning` bridge** using the existing investigation runtime and approval checks.
- [ ] **Step 4: Add the non-blocking API startup consumer** and publish warning/escalation updates on the local event bus.
- [ ] **Step 5: Run the focused tests and confirm unavailable AI leaves the warning pending and collection unaffected.**
- [ ] **Step 6: Commit the AI escalation slice.**

### Task 5: Show all sensors by category and remove the manual start requirement

**Files:**
- Modify: `ui/hackerai/app/components/svs/SvsSensorStatus.tsx`
- Modify: `ui/hackerai/lib/stai-api.ts`
- Test: `ui/hackerai/app/components/svs/SvsSensorStatus.test.tsx`

**Interfaces:**
- `SensorRuntimeStatus` includes service boot state, grouped registry rows, recent warnings, and response state fields from the API contract.
- The component displays all registry rows grouped by `category` and `layer`; no Start button is required for automatic operation. An administrative stop control may remain only if stopping the Windows service is supported by an explicit privileged API.

- [ ] **Step 1: Write failing UI tests** in `ui/hackerai/app/components/svs/SvsSensorStatus.test.tsx` for category grouping, status distinctions, warning display, and no Start action.
- [ ] **Step 2: Run the scoped Jest suite and confirm it fails on the existing flat, manually controlled view.**
- [ ] **Step 3: Group the registry by category/layer and show service, per-sensor, warning, protection, and escalation states.**
- [ ] **Step 4: Remove the UI Start action and keep status refresh/read-only behavior.**
- [ ] **Step 5: Run the scoped Jest suite and the repository's change-aware frontend selector for this component.**
- [ ] **Step 6: Commit the sensor UI slice.**

### Task 6: Expand Windows collection to the remaining supported sensor families

**Files:**
- Modify: `cyber_os/sensors/windows_sensor_service.py`
- Modify: `cyber_os/sensors/sensor_registry.py`
- Modify: `cyber_os/sensors/sensor_registry_data.json` only when source/status metadata is inaccurate
- Create or modify: source-family adapters under `cyber_os/sensors/`
- Test: source-family tests under `tests/`

**Interfaces:**
- Each adapter declares its `shared_collector_id`, source readiness, and canonical sensor IDs; derived sensors consume parent evidence and do not create duplicate collectors.
- Windows-native profile groups are: profiles 1-10 (process, execution, files, persistence, configuration); profiles 11-18 (boot, DNS, network, authentication, accounts); profiles 21-26 (applications, devices, security products, system health, auditing, containers/VMs); and profile 32 (SVS-Cyber internal health).
- Profiles 19-20 (browser/email/collaboration), profiles 27-31 (other operating systems, cloud, and network infrastructure) require their own configured integration plans and do not become Windows collectors by association.
- Each family adds a source-specific normalizer and only the anomaly rules supported by its evidence. Unimplemented or unavailable rows remain visibly non-collecting.

- [ ] **Step 1: Add a failing coverage test** asserting every Windows-native registry row maps to one of the listed profile groups and every derived sensor names its required input IDs.
- [ ] **Step 2: Run the coverage test and verify it identifies the unmapped rows.**
- [ ] **Step 3: For each profile group, add source-specific failing tests** for raw-event normalization, canonical sensor-ID mapping, unavailable-source state, and defined anomaly rules.
- [ ] **Step 4: Implement one shared adapter per actual telemetry source** in the profile group and wire it into the boot service; do not create one collector per logical sensor.
- [ ] **Step 5: Run that profile group's tests and confirm only genuinely ready sensors report `collecting`.**
- [ ] **Step 6: Repeat for profiles 1-18, 21-26, and 32 until every Windows-native row has working source/rule coverage or a truthful `needs_permission`/`not_implemented` state. Commit each profile group independently.**

## Follow-on scope

After Windows-native coverage, create separate platform plans for Linux, macOS, Android, cloud accounts, and network infrastructure. Those sensors require their own service lifecycle, permissions, credentials, and source-specific adapters; they must not be represented as active by the Windows service.
