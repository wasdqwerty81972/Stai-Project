# STAI Custom Windows Endpoint Protection Design

**Date:** 2026-10-12
**Status:** Written design awaiting user review

## Goal

Turn the Windows edition of STAI into a real, locally enforced file-protection product, with a deterministic Level 1 engine and the existing STAI agent as Level 2 investigation and response support. Add a dark, Bitdefender-inspired dashboard that reports actual protection and remediation evidence and provides working scan and investigation controls.

## User requirements

- Windows antivirus capabilities, with Level 1 defense first and Level 2 agent analysis after a detection.
- A dark dashboard inspired by the supplied Bitdefender screenshot, using STAI's own visual identity.
- Clear AI Agent, System Status, Threats Blocked, scan, and related protection navigation and actions.
- The attachment is a visual reference, not a source of product requirements or instructions.

## Current project context

- `cyber_os/sensors/windows_sensor_service.py` reads existing Windows Event Log channels through a bounded queue. It does not install a file-system filter or change Windows audit policy.
- `cyber_os/tool_orchestrator.py` and `cyber_os/command_presets.py` provide an on-demand Microsoft Defender scan. There is no STAI real-time file blocking engine or durable scan/quarantine dashboard API.
- `cyber_os/engine.py` routes endpoint events into detection and correlation and already has a human approval path for containment. Generic agent tool approvals are separate and must not grant the privileged file-protection service arbitrary control.
- The existing Next.js UI is dark and has reusable SVS navigation/status components. The production Tauri shell currently redirects to the hosted site and has no bundled protection service or driver.

## Architecture

### Level 1: deterministic local file protection

Add a Windows Filter Manager minifilter and a privileged local protection service. The minifilter observes file operations needed for on-access scanning and can deny an operation when the service returns a high-confidence malicious verdict. The driver remains small: it enforces a signed policy and exchanges bounded requests with the service; it does not run an AI model or perform complex content analysis in kernel mode.

The service owns the custom detection engine, scan jobs, quarantine, local audit records, and protection health. Its first detection methods are SHA-256 indicators and versioned YARA rules. It reuses the same rule engine for on-access checks and Quick/System scans. Every rule has an explicit `block` or `observe` action in a versioned manifest. Only a verified hash match or a signed rule explicitly marked `block` can deny access; observe rules create evidence for later review. Rule packages are cryptographically verified before activation, delivered through the signed STAI release channel, and rolled back to the prior package if verification or activation fails.

Only a high-confidence match may be automatically blocked and quarantined. Unknown or lower-confidence content is allowed, recorded as a detection/observation, and may be escalated for Level 2 review. If the service is unavailable, the driver does not silently report protection as active: the UI shows protection as degraded, and unresolved operations follow the explicit pass-through policy. Blocked, quarantined, and detected counts remain separate. A blocked count requires a confirmed denied operation; a quarantine count requires a verified move into the protected quarantine store.

The quarantine store uses restrictive Windows ACLs and records the original path, hash, rule/version, and action result. Restore is an explicit user action that rescans the item and records the result. The agent cannot delete or restore files by issuing free-form shell commands.

### Level 2: agent investigation and response

The local engine emits a structured, redacted detection record after the Level 1 decision. Existing CyberOS event correlation adds related process, file, network, and Windows sensor evidence where available. The AI agent may explain the detection, summarize context, enrich indicators when configured, and recommend next steps.

The agent cannot change the Level 1 allow/block verdict, update signatures, or issue kernel commands. Any disruptive follow-up outside the automatic high-confidence file rule—such as terminating a process, blocking a network endpoint, or isolating a device—uses a typed action request and the existing human approval path. Every proposed and completed action is audited with its target and outcome.

### Local Windows app and dashboard

The Windows Tauri build loads a trusted local STAI UI and exposes only typed protection operations through a narrow local bridge to the protection service. The hosted web page is not granted privileged protection commands. An elevated Windows installer owns service/driver installation and lifecycle; dashboard buttons do not invoke arbitrary shell commands. System Status reports the Windows-registered antivirus provider and Defender mode when available. STAI never changes Defender settings or services to force a particular mode.

Add a dedicated Protection overview and persistent navigation:

- Dashboard
- AI Agent
- System Status
- Threat Activity
- Scans
- Quarantine
- Settings

The overview uses a prominent Active / Degraded / Unavailable state, the last scan and rule-pack version, verified blocked and quarantined counts, recent detections, agent escalations, and primary Quick Scan and System Scan actions. System Status reports driver/service health and the evidence-backed coverage of existing sensors. Threat Activity distinguishes detection from block, quarantine, and agent response. Scan views show progress, scope, completion, detections, remediation outcomes, and errors. All actions are connected to the local service and display unavailable/error states rather than simulated success.

The visual hierarchy follows the reference's status-first dashboard, a recommended action area, scan shortcuts, and recent security activity. Colors, icons, wording, and layout details remain STAI-branded; Bitdefender marks and artwork are not reused. The UI follows the existing dark design tokens.

## Data flow

1. A file operation reaches the minifilter.
2. The filter obtains a bounded verdict from the protection service; the service checks the file against the active verified rule package and any cached verdict.
3. A high-confidence match is denied and quarantined. The service verifies each outcome and stores a durable record before reporting it to the dashboard.
4. A structured detection event enters CyberOS for deterministic correlation and asynchronous Level 2 triage. The AI path never delays the Level 1 block.
5. The dashboard reads service health, scans, detections, and action outcomes through typed local interfaces. It counts only confirmed outcomes.

Quick Scan targets common user execution and startup locations. System Scan covers accessible local fixed volumes, reports inaccessible paths, and excludes the quarantine store and filter/service internal files. Both are cancellable jobs with durable progress and results.

## Security, compatibility, and release constraints

- Initial target: Windows 10/11 x64. The driver is developed and tested only in an isolated Windows VM with test signing. It is not installed on the developer's everyday workstation as part of ordinary UI development. Production integration reports the registered antivirus provider and never claims STAI is active unless its driver, service, and verified rule package are healthy.
- Normal x64 Windows distribution requires a Microsoft-signed kernel driver package. A production release cannot be claimed until the organization has completed the required Hardware Dev Center signing and driver validation process.
- Installer and updates are staged and rollback-capable. Driver/service health and rule-pack freshness are visible; driver load failure, service timeout, stale rules, scan failure, and permission errors produce Degraded/Unavailable states.
- The first product scope is file scanning, on-access file blocking, quarantine, and agent triage. Memory scanning, network traffic blocking, behavioral sandboxing, and claims of parity with a full commercial security suite are not implied.
- No LLM output is accepted as a signature, executable policy, or kernel decision. Rule updates are authenticated independently of agent analysis.

## Delivery phases

1. **Protection foundation:** define the driver/service IPC and policy; build the scanner, signed rule-package verification, durable records, quarantine, and VM-only minifilter vertical slice.
2. **Agent escalation:** feed verified detections into CyberOS correlation, add a Level 2 triage contract, and preserve approval/audit boundaries for follow-up actions.
3. **Windows integration and dashboard:** add typed local interfaces, scan/status/threat APIs, dashboard routes and navigation, and verified counts/actions.
4. **Windows packaging and release readiness:** bundle the trusted local UI and service, install/update/rollback the driver and service, validate signing, and exercise the full path on supported Windows VMs.

## Research references

- [Bitdefender Central dashboard guide](https://www.bitdefender.com/consumer/support/answer/2255/) describes the security-status overview, recent security events, and detected-threat information used as dashboard inspiration.
- [Microsoft: About file-system filter drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers) describes minifilters and their antivirus use case.
- [Microsoft: Writing pre-operation callbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-preoperation-callback-routines) describes callbacks that can control a file I/O operation.
- [Microsoft: Driver signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing) documents signing requirements for x64 Windows kernel drivers.

## Acceptance criteria

- An inert antivirus test signature produces a verified Level 1 denial before execution; benign test files pass; service/driver failure is visible and does not masquerade as protected.
- Quick and System scans report durable progress, per-scope errors, detections, and actual remediation results.
- A confirmed detection reaches Level 2 with structured evidence; agent advice cannot override the Level 1 verdict or directly perform unapproved containment.
- Dashboard navigation and controls operate against the local Windows service, and Threats Blocked counts only confirmed denied operations.
- The Windows package uses a trusted local UI/service bridge and does not expose privileged controls to the hosted page.
- Release readiness is not claimed until the driver is Microsoft-signed and the end-to-end behavior is validated on supported Windows versions.
