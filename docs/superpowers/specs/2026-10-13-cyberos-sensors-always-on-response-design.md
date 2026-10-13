# CyberOS Always-On Sensors and Response Design

**Date:** 2026-10-13  
**Status:** Draft for owner review

## Goal

Make the sensor catalog useful as an always-on endpoint monitoring system. On a supported Windows installation, the sensor runtime should start at Windows boot without requiring the UI or a manual Start action. Sensors should appear in their existing categories, report truthful per-sensor runtime state, and raise a visible warning when a detection rule identifies an anomaly.

Warnings should enter the appropriate response path:

- File and executable anomalies go to the installed protection engine first. A detection is considered protected only when the protection outcome confirms that the operation was blocked or the artifact was successfully contained. A scan that merely completed is not proof of remediation.
- Non-file anomalies, such as suspicious logins, network activity, or privilege changes, go directly to AI triage because the file protection engine cannot act on those events.
- If file protection is unavailable, fails, or cannot confirm the outcome, the warning is escalated to AI triage with the protection result marked unknown or failed.
- AI triage analyzes and recommends. Disruptive actions remain behind the existing human approval flow.

## Current state

The catalog contains 256 logical sensors in `cyber_os/sensors/sensor_registry_data.json`. `sensor_registry.py` validates and exposes the catalog, but catalog entries do not mean that collectors or rules exist. The Windows Event Log service currently maps 14 Phase 1 capabilities to real sources. `CyberOSEngine.start()` starts that collector, but the UI still requires an explicit Start action and the API does not start CyberOS at process startup.

The sensor queue is durable, but sensor events are not connected to the protection service. The protection service scans files using signed local rules, can report a block verdict, and sends confirmed detections to advisory triage. It does not act as a general antivirus for login or network anomalies. The AI agent is not currently called by the sensor event path.

## Design

### 1. Background runtime and boot lifecycle

Run a dedicated Windows service at automatic start. It owns the sensor collectors and durable event queue independently of the UI/API process. The service runs with the least privileges that still allow configured sources to be read. It must not silently change Windows audit policies, install third-party collectors, or enable privacy-sensitive collection.

The local API/UI attaches as a client to read status and warnings. If the API or AI agent is offline, sensor detections remain durably queued. When the agent becomes available, pending escalations are delivered idempotently using the stable sensor event ID. Service installation, upgrade, stop, uninstall, and service recovery behavior must be explicit and observable.

### 2. Catalog placement and truthful runtime status

Keep all 256 catalog rows available under their existing `category` and `layer`, grouped by category in the sensor UI. Show each row's support and live runtime state separately. Use clear states such as `collecting`, `partial`, `needs_permission`, `integration_required`, `unsupported_on_host`, `not_implemented`, `stopped`, and `error`.

Only a real, configured collector with a healthy source may be reported as collecting. Derived detections reference their input sensors and do not create duplicate collectors. External integrations and other operating-system sensors stay visible in their categories but show what is required before they can run.

### 3. Shared collectors and per-sensor rules

Implement collectors by shared telemetry source, then map observed events to one or more catalog sensor IDs. This avoids opening the same operating-system source once for every logical sensor. Each normalized event carries stable event ID, sensor IDs, source, timestamp, severity, and privacy-filtered evidence.

Expand Windows source families incrementally. A sensor becomes active only when its source adapter, normalizer, and runtime status are wired. Detection rules are separate from collection: benign observations do not become warnings by default. Each anomaly rule must state its evidence and threshold, and warnings retain the originating sensor IDs and evidence references.

### 4. Warning and response coordinator

When a rule detects an anomaly, persist and publish a warning immediately, before attempting response. Then route by evidence type:

1. **File or executable evidence:** submit the eligible local artifact to the configured protection engine. Correlate the request and outcome to the sensor event. `blocked` or `contained` requires explicit confirmation from the protection service. `clean` means no matching rule was found; it does not prove that a behavioral anomaly is harmless, so an unresolved anomaly still goes to AI triage. `failed` and `unknown` are distinct outcomes.
2. **Non-file evidence:** send the redacted event context directly to AI triage.
3. **Unresolved file outcome:** send the event and protection result to AI triage when protection fails, is unavailable, or cannot verify that it handled the threat.

AI triage runs off the collector thread so a slow or unavailable model cannot stop sensor collection. It produces analysis and suggested actions. Existing approval controls remain mandatory for process termination, quarantine, firewall changes, or other disruptive actions.

### 5. UI and alert visibility

Show the overall service state, individual sensor states, last event/error, queue health, warning, protection outcome, and AI escalation state. Remove the need for a Start action; an explicit administrative stop may remain as an override. Warning updates use the existing local event bus and remain queryable after reconnect from durable storage.

## Failure handling and privacy

- An unavailable source is reported as unavailable or requiring configuration; it is never counted as an active sensor.
- Missing audit policy or permissions produce partial/permission states and a user-visible explanation. The service does not change host policy on its own.
- Queue backpressure preserves source checkpoints and must not silently discard an anomaly.
- Repeated delivery is idempotent by stable sensor event ID.
- Default privacy settings continue to hash or omit paths, DNS names, and command lines. Only evidence needed for a file scan is sent to the protection engine; only minimal, redacted context is sent to the AI agent.
- If protection or AI is unavailable, preserve the warning, expose the unresolved stage, and retry delivery without claiming success.

## Delivery sequence

1. Create the Windows service lifecycle and durable client handoff; make boot startup and service health observable.
2. Present the 256 sensors grouped by category and layer by default; make runtime/source readiness distinct from catalog metadata.
3. Connect existing Windows collectors to immediate warnings and an idempotent response coordinator.
4. Route file anomalies through verified protection outcomes and other anomaly classes to AI triage; preserve approval-gated remediation.
5. Add Windows collector families and anomaly rules in source-based increments, reporting exact coverage as each becomes operational.
6. Add separate Linux, macOS, Android, cloud, and network-infrastructure adapters only with their platform and provider-specific runtime/permission models.

## Acceptance criteria

- On Windows, the installed service starts automatically at boot and continues collecting with the UI closed.
- The UI presents the 256 catalog rows in their existing categories and reports which rows are collecting, partial, waiting for configuration/permission, unsupported, or not implemented.
- A detected anomaly creates a durable, visible warning containing its sensor IDs and evidence reference.
- File anomalies use the protection path first; only an explicit protective outcome is described as handled. Failed or unknown protection outcomes reach AI triage.
- Non-file anomalies reach AI triage without being sent to a file-only protection operation.
- An unavailable UI/API or AI agent does not stop collection or lose queued warnings.
- AI recommendations do not bypass human approval for disruptive remediation.
- No host audit policy or sensitive collection setting is silently changed.

## Out of scope for the first Windows milestone

- Claiming all 256 catalog entries are immediately implemented on Windows.
- Building Linux, macOS, Android, cloud, or router collectors as part of the first Windows service milestone.
- Treating successful scan invocation as proof of containment.
- Letting the AI agent automatically execute disruptive remediation without the existing approval flow.
