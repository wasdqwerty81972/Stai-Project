# SVS-Cyber Antivirus V4: Staged Endpoint Protection Roadmap

**Date:** 2026-10-14
**Status:** Draft for owner review
**Source:** User-approved `STAI / SVS-CYBER ANTIVIRUS V4` master prompt and current-worktree audit.

## Goal

Advance the existing SVS-Cyber application toward an integrated Windows endpoint protection and investigation product. It should combine supported file scanning, truthful process and network telemetry, threat intelligence, evidence correlation, the existing STAI investigation agent, controlled response, and the current Tauri security console.

This is a staged engineering program, not a claim that the current product is equivalent to Windows Defender, Bitdefender, or another established AV. Every capability remains separately labeled as verified, unverified, partial, blocked, or not implemented until its evidence supports a stronger status.

## Audited baseline

The following is a source/runtime inventory from 2026-10-14, not a complete fresh regression run:

- The custom scanner supports stable-file SHA-256 and signed-package YARA rules, bounded file size/read time, and typed unknown outcomes. The bundled signed package currently contains one EICAR test hash rule. Quarantine verifies the block evidence and hashes around move/restore; additional crash, ACL, and cross-volume hardening remains.
- `ThreatIntelStore` has provenance, freshness, retraction, corroboration, staging, rollback, and indexed lookup support. The local database was reported at 1,196,211 records, but its lookup decision is not connected to scanner verdicts. Feed authenticity and current freshness must be checked before activation.
- The process dashboard has a user-mode registry and real measured metrics. The current event subscription was denied and falls back to periodic reconciliation. The dashboard collector is not verified as owned by the installed protection service.
- Minifilter, installer, and lifecycle source exist, but no signed production driver or isolated-VM enforcement evidence exists. Release readiness is blocked on driver/signing/altitude/VM evidence.
- A WFP event bridge exists in source but is not built, packaged, or started by the default service. WFP policy code has no native enforcement adapter; network blocking is not implemented or verified.
- The sensor catalogue has 256 definitions, with 2 implemented and 12 partial source mappings in the latest coverage audit; catalogue rows alone do not indicate active collection. Sensor warning queues and a narrow incident correlator exist. A durable raw-event flight recorder and verified automatic CyberAgent worker for queued warnings remain gaps.
- `STAIProtection` was observed installed, stopped, and configured for Manual start on the inspected host. This host state must be reconciled with the intended installer/service lifecycle; do not change service state silently during implementation.
- The existing workspace has substantial pre-existing tracked and untracked changes, including local profile/build artifacts. Implementation must preserve them and use narrowly scoped file ownership; no cleanup, reset, or broad staging is part of this design.

Recent focused validation documented elsewhere includes 208 backend tests passed/1 skipped and 20 dashboard tests passed for the process-monitor slice. This is not a current full-suite baseline. Full-project and kernel/runtime claims require fresh evidence in the corresponding phase.

## Design principles

1. Keep the existing `STAIProtection` service, protection API, event bus, CyberAgent, and Tauri dashboard as the product backbone. Add narrowly bounded adapters instead of a second disconnected security or AI framework.
2. Keep deterministic detection/enforcement in the protection service and drivers. AI can investigate and recommend; it cannot invent evidence or bypass policy and approval checks.
3. Tie files, processes, connections, sensor events, detections, and response outcomes to stable identifiers and provenance. Never carry evidence across PID reuse or claim an action succeeded without verifying its result.
4. Use signed, versioned, provenance-bearing rule and intelligence updates with staging, integrity checks, activation, rollback, and clear age/revocation status.
5. Keep driver callbacks bounded. No hashing, YARA, database access, HTTP, AI, or blocking service waits in kernel callbacks.
6. Keep observation and enforcement separate. Any minifilter/WFP enforcement remains disabled or unavailable until build, signing, lifecycle, authorization, and isolated-VM tests prove the exact behavior.
7. Preserve local-first privacy. Minimize and redact data before persistence or AI context; require explicit consent for cloud analysis.
8. Expose unavailable, permission-denied, stale, partial, failed, and verified states separately. No simulated production activity, synthetic detections, or unsupported telemetry values.
9. Use harmless fixtures (including EICAR only where permitted) and isolated development environments; do not download or execute real malware in routine tests.

## Target architecture

```text
Windows collectors and supported drivers
        |
        v
Protection service: bounded normalized-event intake
        |
        +--> scanner + signed rules + threat-intel lookup
        +--> durable local event/incident recorder
        +--> deterministic policy and verified response
        +--> bounded, redacted AI-investigation queue
        |
        v
Authenticated local API / named pipe
        |
        v
Existing Tauri security console and CyberAgent workspace
```

The minifilter remains a file-operation enforcement component. WFP remains a separate network observation/policy component. Neither driver calls the AI or scans files. The service validates messages and owns durable state. UI health reflects the actual service, scanner, rules, driver, WFP, and sensor states independently.

The current Tauri/local API user-mode scanner fallback may remain available when the installed service is absent, but it must report its own scanner/rule readiness and must never claim Windows-service, minifilter, or WFP protection.

## Delivery sequence

Each phase is a separate implementation slice with its own detailed plan and acceptance evidence. Do not bundle the entire roadmap into one change.

### P0 — Baseline and repair

- Run and save a fresh test/build baseline before changes.
- Reconcile current code against `docs/security/antivirus-audit.md`, sensor coverage, approved specs/plans, and runtime/service state; update stale audit claims.
- Reproduce and repair confirmed correctness/security defects, prioritizing service-status truth, scan/quarantine accounting, startup/shutdown, named-pipe authorization, and regression failures.
- Keep product service and driver states truthful. Installer boot-start behavior is changed only through a tested installation/update path.

**Exit:** confirmed defects have focused regression tests; baseline and post-fix results are reported; no unrelated user changes are overwritten.

### P1 — Production-owned live telemetry

- Make process lifecycle collection an owned, health-reported part of the installed service, using a supported ETW-backed Windows event source with the required service privilege plus startup snapshot and reconciliation. Keep the existing process-instance identity and sampled CPU/memory implementation; preserve the UI/API contract where compatible.
- Diagnose why the current `Win32_ProcessStartTrace`/`Win32_ProcessStopTrace` subscription is denied. Select and validate the documented ETW-backed source in the service context without taking over a trace session owned by another component.
- Separately build/package/initialize the existing WFP observation bridge if the required SDK/toolchain is available. Report it unavailable otherwise. Attribute connections only when Windows supplies a verified owner and process instance.
- Do not enable network blocking in this observation phase.

**Exit:** harmless process start/stop tests show event delivery and reconciliation; real metrics and connection ownership have documented semantics; service health and UI show exact source state; WFP observation has separate live evidence or is explicitly blocked.

### P2 — Dependable scanner and threat intelligence

- Define deterministic precedence between signed rules and exact-hash intelligence. Only fresh, non-retracted, sufficiently trusted/corroborated exact-file indicators may produce a high-confidence block. IP/domain/URL reputation does not become a file verdict.
- Integrate the existing indexed local hash lookup into the scanner/service, preserving source/provenance, confidence, first/last seen, expiry, and revocation evidence in detections.
- Add authenticated feed ingestion and signed/staged update activation with rollback and validation. Never treat an unsigned/incomplete feed as production-active.
- Evaluate licensed YARA sources, compile/validate/deduplicate rules into Core/Extended/Full tiers, retain rule provenance, and benchmark scan costs. Keep the EICAR package explicitly test-only.
- Expand file coverage (including safe archives/PE metadata) only under explicit size/time/depth limits and accurate unknown/partial outcomes.

**Exit:** integration tests prove lookup-to-verdict and retraction/expiry behavior; rule counts include only validated unique licensed rules; staged update rollback is tested; harmless fixtures cover detection and false positives.

### P3 — Supported enforcement

- Validate the filesystem minifilter and driver/service protocol in an isolated supported Windows VM using documented Filter Manager APIs. Production release additionally requires Microsoft signing and allocated altitude evidence.
- Complete WFP observation packaging before designing/adding the separate native policy adapter. Add only exact, owned, auditable, reversible rules through documented WFP APIs and test service/driver/BFE failure behavior.
- Keep enforcement least-privilege, authorization-gated, bounded, and fail-safe according to a separately reviewed driver-specific design. Do not install experimental drivers on the development host or disable Windows security features.

**Exit:** reproducible VM evidence proves allow/block/cleanup/rollback for each enforcement path; release gates remain blocked until signing, altitude, and publisher evidence exist.

### P4 — Local evidence recorder and correlation

- Add a bounded durable event recorder with normalized source, timestamp, stable entity identifiers, provenance, confidence, retention, deduplication, and dropped-event health.
- Correlate process ancestry, file activity, network connections, detections, sensor warnings, and verified response outcomes only where telemetry supports each edge.
- Preserve incident query and timeline behavior; recover cleanly after service restart and avoid unbounded event growth.

**Exit:** integration tests trace benign controlled file/process/network events through persisted evidence and demonstrate deduplication, retention, restart recovery, and incomplete-evidence reporting.

### P5 — STAI investigation integration

- Wire durable warnings/incidents to the existing CyberAgent through bounded, idempotent leases and structured, redacted evidence projections.
- Keep model output advisory. Tool calls use existing validated defensive tools; disruptive actions require the current deterministic policy/approval path and independently verified outcomes.
- Add timeout, cancellation, retry, duplicate suppression, and AI-unavailable states.

**Exit:** a controlled harmless incident creates one durable investigation with real tool evidence, cannot bypass approval, and records verified/no-action outcomes accurately.

### P6 — Behavioral/ransomware coverage

- Add bounded, deterministic behavioral signals (including bulk file-change patterns) with contextual evidence, thresholds, allowlists, and false-positive controls.
- Observe/investigate by default. Narrow containment requires corroborated evidence and preauthorized policy; broader disruptive response is approval-gated.
- Test with harmless simulations and backup/sync/development workloads.

**Exit:** harmless simulations prove alerting and safe response boundaries; false-positive and performance results are recorded. Do not claim universal ransomware prevention/recovery.

### P7 — Reliability, privacy, and release hardening

- Benchmark process-event latency, scan throughput, hash lookup, rules, queue behavior, service CPU/RAM, database growth, and UI rendering using measured results.
- Add retention/export/deletion controls, redaction, cloud consent, secure updates, ACL checks, recovery, and health diagnostics.
- Run the full applicable suite, packaging, and isolated Windows VM matrix. Track independent lab evaluation as a separate future evidence gate.

**Exit:** all claims match reproducible tests and measurements; known limitations and blocked environment requirements are explicit; production release is blocked until all required signing/runtime gates pass.

## Required project practices

- Respect existing local changes and AGENTS.md project conventions. Use disjoint ownership and isolated worktrees for parallel implementation only after a phase plan identifies non-overlapping files and integration points.
- For feature code, write failing tests first and run focused tests during implementation. Run the full relevant regression suite after integration.
- Use primary Windows/vendor documentation for API/security decisions and check licenses before distributing detection content.
- Do not claim a phase complete from source inspection or mocked tests alone where live Windows/driver evidence is required.

## Review and immediate next phase

This roadmap does not replace the user's implementation objective. After owner review of this written spec, create a detailed plan for **P0 and the first P1 service-owned process-telemetry slice**. The later P1 WFP observation integration and P2 scanner/intelligence integration should each receive focused plans because they have distinct APIs, failure modes, and validation gates.
