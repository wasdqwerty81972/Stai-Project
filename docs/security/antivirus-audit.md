# SVS-Cyber Antivirus Audit

Audit date: 2026-10-13  
Scope: source and tests in the current `codex/mobile-phase2-tools` worktree. Runtime claims below are limited to the inspected Windows host and repository evidence.

## Summary

SVS-Cyber already has a custom user-mode scanner, a signed rule package, SQLite persistence, a Windows service and named-pipe bridge, a selected-folder file watcher, a minifilter source tree, and a native protection dashboard. These components are not equivalent to a complete or production-ready antivirus. The current detection content is a single exact SHA-256 EICAR rule; broad file analysis, archive inspection, complete scan coverage, process/network views, and signed-driver runtime validation remain absent or incomplete.

Three correctness and safety defects were fixed during this audit:

- A verified high-confidence SHA-256 block match now survives a YARA timeout or runtime failure. Without such a hash match, the result remains `unknown` when YARA is unavailable.
- AI classifications from sensor investigations are advisory. They no longer manufacture a high-confidence block verdict or quarantine a file. The existing automatic quarantine path is limited to local high-confidence rule matches; a general approval-gated response controller is still missing.
- File watcher create/modify events now use canonical catalogue IDs 49/50 instead of unrelated process-handle IDs 17/18.
- The Windows service now resolves Quick Scan roots for its enrolled dashboard SID, honors redirected Downloads/Desktop locations, and records a per-job root snapshot. If it cannot resolve the enrolled profile, it does not silently scan LocalSystem's profile.

## Findings by subsystem

| Subsystem | Status | Evidence and limits |
|---|---|---|
| File scanner | Implemented, narrow | `cyber_os/protection/scanner.py` hashes stable regular files and matches SHA-256 and YARA rules. It rejects reparse points and detects changes during scanning. It does not yet parse PE structure, measure entropy, inspect scripts or documents, or scan archive contents. |
| Detection rules | Implemented, minimal | `cyber_os/protection/rule_package.py` verifies the detached Ed25519 signature and schema. `cyber_os/protection/resources/demo-manifest.json` contains one exact raw EICAR SHA-256 block rule. No broader curated database is bundled. |
| Quick Scan | Partially implemented; roots corrected | The Windows host resolves Downloads, Desktop, Local Temp, and Startup from the enrolled dashboard user's profile and known-folder redirection. The selected roots are snapshotted with each durable scan job. Non-Windows development instances retain the local `Path.home()` defaults. Scan accounting, one-pass traversal, and honest error/skipped/unknown counts remain incomplete. |
| Full/System Scan | Partially implemented | The only root is hardcoded `C:\`. Other local volumes are not enumerated. Traversal errors can be swallowed, so `completed` does not prove full coverage. |
| Scan accounting | Partially implemented | SQLite stores job ID, scope, state, files scanned/total, detections, errors, and timestamps. Unknown scan verdicts are counted as scanned, skipped files are not counted, and root/iterator failures can disappear. Jobs left `running` after a service crash are not reconciled. |
| Custom and scheduled scans | Missing | Scan scope is constrained to `quick` and `system`. No caller-selected files/folders or persisted schedule is wired through service IPC. |
| Real-time file monitoring | Partial, post-write | `cyber_os/sensors/windows_file_watch.py` uses recursive `ReadDirectoryChangesW` on selected enrolled-user folders and debounces events before scanning. It covers Downloads, Desktop, and Local Temp, not all volumes or Startup, and does not provide pre-execution blocking. The source-level minifilter also checks read/execute opens and section mapping, but no signed driver package is present. |
| Threat database | Partial | SQLite WAL persistence exists in `cyber_os/protection/store.py` for detections, actions, scans, quarantine, and triage. The detection rules themselves are signed JSON files. There is no local reputation/signature database with revocation/expiry, safe updater, staged activation, or rollback. |
| Entropy and PE analysis | Missing | No Shannon entropy analyzer, PE section analysis, code-signature verification, or related scan result fields exist in the custom scanner path. |
| Behavior and case correlation | Partial | Sensor warnings include a few rule-based event detections, but there is no durable attack-case state machine and evidence checklist connecting normalized events across process, file, persistence, and network identities. |
| AI investigation | Partial | `cyber_os/protection/triage.py` provides bounded analysis-only triage with a strict evidence projection, but its default provider is unavailable and it has no response tools. Another sensor warning path invokes the existing agent, now restricted to advisory results for file containment. A complete specialist investigation pipeline is not present. |
| Quarantine | Implemented, needs hardening | `cyber_os/protection/quarantine.py` verifies SHA-256 before and after a same-volume move, stores metadata, and checks hashes before restoration. Cross-volume moves, crash recovery, durable ACL verification, and Windows-critical-file policy are not fully handled. |
| Safe process control | Missing | No typed process identity inspection, critical-process checks, approval-gated termination, or post-action verification is wired into the protection bridge. |
| Dashboard | Partial | `ui/hackerai/packages/protection-dashboard` has real status, scan, threat, triage, and quarantine views connected through Tauri. It currently has no dedicated Tasks/process inventory or Network view and no process/network IPC operations. |
| Windows service and IPC | Implemented in source; unavailable on inspected host | `cyber_os/protection/windows_service.py` hosts the named pipe, filter client, sensor service, and file watcher. The Tauri bridge uses typed commands and bounded pipe frames. No STAI protection service or SVS-Cyber app process was running during inspection. |
| Minifilter | Source present; production blocked | `windows_protection/driver` has create/read/execute and section callbacks. `windows_protection/installer/release-readiness.json` marks all production gates false; no WDK-built signed `.sys`/`.cat`, approved publisher, or isolated Windows VM enforcement evidence is recorded. The source still documents a development communication-port ACL. |
| Defender relationship | Correctly separated | The custom scanner owns its own verdicts. Windows Security posture reporting is separate; the project does not disable Defender. No Defender result is mislabeled as an SVS-Cyber detection in the reviewed path. |

## Verification performed

- `pytest tests/test_windows_protection_scanner.py -q` — 7 passed, 1 skipped after the hash/YARA precedence fix.
- `pytest tests/test_windows_protection_scanner.py tests/test_windows_protection_service.py tests/test_windows_protection_core.py tests/test_windows_protection_rules.py tests/test_windows_protection_store.py tests/test_sensor_warnings.py tests/test_windows_file_watch.py tests/test_windows_sensor_service.py tests/test_sensor_registry.py -q` — 57 passed, 1 skipped. This includes scanner, service, store, warning, watcher, sensor-service, and catalogue coverage after all three fixes.
- `pytest -q` — 644 passed, 1 skipped, 299 subtests passed. Pytest reported 13 existing framework deprecation warnings.
- Quick Scan regression and store migration checks — 32 protection service/store/lifecycle tests passed; verifies redirected enrolled-user roots, no LocalSystem fallback when the profile is missing, immutable job snapshots, and migration from schema version 2.
- The failing test was observed before each behavior change: hash block during YARA failure, and a high-confidence AI report attempting to quarantine an unrecognized file.
- `cyber_os/sensors/sensor_registry_data.json` contains exactly 256 catalog records. The implementation registry marks 2 as implemented and 12 as partial at the source level; the rest are registered-only. The protection service was not installed on the inspected host, so the active sensor count there is 0. The watcher ID mismatch was corrected and now has a regression test.
- Source-level or mocked tests do not prove live event-log collection, driver enforcement, or production readiness.

## Rule-source research

- EICAR's own test-file page defines the canonical 68-byte string and provides raw, single-ZIP, and nested-ZIP fixtures. The repo's current rule is an exact SHA-256 match for the raw string; archive-contained copies still require bounded archive inspection before they can be claimed as covered. See [EICAR's official test-file guidance](https://www.eicar.org/download-anti-malware-testfile/).
- YARA-X publishes a Python API and documents Windows support with Python 3.9 or later, which includes this project's Python 3.11 runtime. The current frozen service bundles classic `yara`; migration needs a packaging smoke test, rule-compatibility tests, and benchmark before adoption. See [YARA-X Python API documentation](https://virustotal.github.io/yara-x/docs/api/python/).
- SigmaHQ's rule repository states that its rule content is released under Detection Rule License 1.1. Treat this as a candidate source for behavioral detection after license review and an explicit conversion/attribution pipeline; it is not a drop-in file signature database. See [SigmaHQ's official repository](https://github.com/SigmaHQ/sigma).
- Community YARA repositories have mixed terms. Each rule needs provenance and a license check before redistribution; no public rule bundle was copied into the project during this audit.

## Important limitations

The current scanner reads the entire file for SHA-256 and recompiles YARA rules per file; there is no total byte/time budget or content cache. The current service pre-counts and then rescans roots, increasing I/O and creating a gap between progress discovery and scanning. Results can therefore overstate coverage and large files can outlast the minifilter request deadline. These are foundational gaps to address before claiming reliable whole-system scans.

No experimental kernel driver was installed or exercised on the developer host. The product must remain labeled as development software until the driver signing, altitude, isolated VM tests, false-positive evaluation, and independent security review gates are satisfied.
