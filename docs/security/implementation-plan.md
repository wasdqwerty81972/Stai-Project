# SVS-Cyber Sentinel Implementation Plan

Updated: 2026-10-13  
Source requirements: user-provided `SVS-CYBER SENTINEL` master prompt. The source prompt is treated as product requirements; its technical claims are checked against current code and runtime evidence.

## Goal and constraints

Build SVS-Cyber's own verifiable scanning, evidence, investigation, and response workflow in the existing Windows service and HackerAI/Tauri application. Keep Defender separate and enabled, do not install an experimental kernel driver on the developer host, do not use uncontrolled malware samples, and do not let model output bypass deterministic response authorization. Do not describe source-level or mocked behavior as production-ready.

## Current verified baseline

- Per-file scanning hashes stable regular files and matches signed SHA-256/YARA rules. The signed demo package recognizes the exact EICAR file.
- Background Quick and System scans exist but use fixed roots; LocalSystem Quick Scan can select the wrong profile. Full scan only targets `C:\`. Traversal errors and skipped/unknown files are not represented accurately.
- SQLite WAL persists scan jobs, detections, actions, quarantine, and Level 2 triage; there is no full reputation database or verified update activation system.
- A Windows service, authenticated named pipe, user-mode folder watcher, and minifilter source exist. The service/driver are not installed and there is no signed production driver package.
- The sensor catalogue has 256 definitions, of which 2 are source-marked implemented and 12 partial; zero were active on the inspected host. The watcher currently emits file sensor IDs that disagree with the canonical registry.
- The native dashboard has real protection APIs for overview, scans, detections, quarantine, status, and agent triage. Dedicated live Tasks and Network views are missing.
- This audit fixed SHA/YARA result precedence, removed AI-classification-driven quarantine, and corrected file watcher sensor IDs. The repository-wide Python suite passed: 636 passed, 1 skipped, 299 subtests passed; 22 framework/runtime warnings remain.

## Work sequence

### 1. Scanner correctness and truthful accounting

- [x] Keep an exact signed hash block verdict when optional YARA fails; preserve `unknown` when only YARA/observe evidence exists.
- [x] Ensure AI-generated classifications remain advisory and cannot manufacture a deterministic block verdict.
- [x] Align selected-folder watcher event IDs with the canonical file creation/modification sensors 49/50.
- [ ] Add scan outcome fields for files discovered, scanned, skipped, errors, unknown verdicts, detections, engine/rule versions, cancel state, and duration.
- [ ] Replace the count-then-rescan traversal with one bounded traversal that records root access failures, permission errors, reparse-point skips, locked/oversized files, and cancellation truthfully.
- [ ] Validate service-start recovery for interrupted jobs; do not show an incomplete job as clean.
- [ ] Correct Quick Scan to use the authenticated enrolled-user profile and persist an immutable root snapshot per job.
- [ ] Add a caller-selected Custom Scan scope with authenticated, constrained paths and durable results.
- [ ] Enumerate eligible local volumes for Full Scan and document archive/large-file behavior rather than implying unsupported coverage.
- [ ] Run isolated benign fixtures and exact raw EICAR through the application-owned engine; add ZIP-contained EICAR only when bounded extraction and traversal protections are implemented.

### 2. Custom analysis and threat database

- [ ] Add tested Shannon entropy for files and PE sections; keep entropy separate from severity and never use it alone for destructive action.
- [ ] Add bounded PE parsing, structural evidence, imports/sections, and Windows code-signature verification with unavailable/error states.
- [ ] Add a versioned local reputation/signature store and analysis cache keyed by content hash plus engine/rule version.
- [ ] Add a signed, staged, atomic rule-package update path with integrity validation and rollback; keep external/unverified indicators separate from confirmed signatures.
- [ ] Assess YARA-X compatibility and source/license provenance before changing the current matcher.

### 3. Sensor routing and attack cases

- [x] Fix file watcher IDs to the canonical catalogue mapping and test event schema/routing.
- [ ] Add per-sensor last-event, event count/rate, health, permission, error, and unsupported states without inventing active counts.
- [ ] Route normalized events into a bounded, deduplicating triage/correlation pipeline.
- [ ] Persist attack cases with stable IDs, evidence checklist states (`confirmed`, `not observed`, `unknown`), weighted risk and history.
- [ ] Add controlled synthetic multi-event tests before connecting additional live sources.

### 4. Agent investigation and safe response

- [x] Remove automatic containment based only on an AI `malicious` label or confidence score.
- [ ] Route evidence-backed cases to the existing agent with typed, read-only security tools; bound task count, time, and data exposure.
- [ ] Reuse specialist agents only where real callable tools exist; merge structured evidence and preserve partial failures.
- [ ] Add an independent approval policy for disruptive responses, then typed process identity/criticality checks and post-action verification.
- [ ] Retain automatic response only for narrowly defined, locally verified high-confidence signatures that have explicit tested policy.
- [ ] Harden quarantine for cross-volume, locked-file, crash-recovery, ACL-verification, critical-file, restore-authorization, and disk-space cases.

### 5. Dashboard, background protection, and delivery evidence

- [ ] Add genuine process inventory and asynchronous cached executable enrichment to the main protection dashboard.
- [ ] Add a Network view backed by real connection and attribution APIs; distinguish unavailable telemetry and preserve existing privacy controls.
- [ ] Connect scan/case/service events to honest notifications and degraded/empty/error states.
- [ ] Add service install/remove/start/recovery checks and ensure frontend exit leaves service behavior explicit.
- [ ] Keep the minifilter release blocked until a Microsoft-signed driver, approved altitude/publisher, isolated Windows 10/11 VM enforcement, and independent review evidence exist.
- [ ] Run subsystem and integration tests in a disposable environment; publish an acceptance matrix listing passed, failed, and unverified requirements.

## Next implementation slice

Continue Phase 1 with Quick Scan root correctness and scan accounting. These paths are foundational for reliable scheduled, custom, and full scans. Preserve fail-open behavior for unavailable analysis while displaying the job as incomplete or degraded; never turn an inaccessible file into a clean verdict.

## Acceptance ledger

| Requirement | Status | Evidence needed |
|---|---|---|
| Custom SVS-Cyber signature detection | Partial | Own-engine test for raw EICAR and inert test signatures, persisted source-attributed verdict |
| Quick/Full/Custom scan coverage | Incomplete | Real isolated roots/volumes, skipped/error counts, persisted scan record, cancellation/restart tests |
| Entropy and PE analysis | Missing | Correct measured fixtures, malformed PE handling, no entropy-only containment |
| Threat database and verified updates | Partial | Indexed lookups, version history, rejected tampered package, atomic rollback |
| Genuine process/network views | Missing | Runtime evidence from typed service operations and UI interaction |
| 256 sensor health | Partial | 256-row runtime inventory, truthful active count, event-routing tests for each implemented sensor |
| Correlation and case evidence | Missing/partial | Multi-event synthetic case, evidence state distinctions, persisted timeline |
| Real agent investigation | Partial | Actual bounded tool invocations, structured evidence, partial failures, approval separation |
| Safe response and quarantine | Partial | Approval rejection/acceptance, critical-process guards, identity recheck, recovery and restore tests |
| Background driver enforcement | Unverified | Signed package plus isolated VM test; no primary-host driver installation |
| Production readiness | Not met | Independent review, compatibility/performance/false-positive testing, release gates and signed artifacts |
