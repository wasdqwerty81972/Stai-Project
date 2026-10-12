# STAI Windows Protection Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic, durable Windows file scanning core with authenticated rules, scan jobs, and verified quarantine outcomes.

**Architecture:** Add a focused `cyber_os.protection` package. It verifies signed versioned rule packages before use, scans files with SHA-256 and YARA, and stores jobs, detections, and quarantine actions in SQLite. The core is testable without a driver or AI runtime; only the later minifilter plan may use its verdict contract to deny file operations.

**Tech Stack:** Python, SQLite, `cryptography` Ed25519 verification, `yara-python`, pytest.

**Spec:** `docs/superpowers/specs/2026-10-12-stai-custom-windows-protection-design.md`

## Global Constraints

- Initial target is Windows 10/11 x64.
- Detection methods are SHA-256 indicators and versioned YARA rules.
- Only a verified hash match or a signed rule explicitly marked `block` with high confidence can deny access.
- Unknown or lower-confidence content is allowed and recorded as an observation.
- Blocked, quarantined, and detected counts remain separate; each count requires a verified outcome.
- The first product scope is file scanning, on-access file blocking, quarantine, and agent triage; do not claim memory scanning, network traffic blocking, behavioral sandboxing, or commercial-suite parity.
- The agent cannot delete or restore files by issuing free-form shell commands.
- Do not claim protection is active unless the driver, service, and verified rule package are healthy.

## Review Focus

- Tampered or malformed package: reject before activation; test in Task 1.
- A signed observe rule matches: record but never block; test in Task 1.
- File changes while being scanned: return `unknown` and do not cache a block; test in Task 2.
- Symlink/reparse point under a scan root: do not follow it outside the selected scope; test in Task 3.
- Quarantine move fails or hash differs: report failure and do not increment quarantine count; test in Task 3.
- Restore target no longer matches its recorded hash or scans as malicious: refuse restore; test in Task 3.

---

### Task 1: Signed rule package and verdict model

**Files:**
- Create: `cyber_os/protection/__init__.py`
- Create: `cyber_os/protection/models.py`
- Create: `cyber_os/protection/rule_package.py`
- Create: `requirements-windows-protection.txt`
- Test: `tests/test_windows_protection_rules.py`

**Interfaces:**
- `RulePackage.load(manifest_path: Path, signature_path: Path, public_key: bytes) -> RuleSet`
- `RuleSet.version: str`, `RuleSet.rules: tuple[DetectionRule, ...]`
- `DetectionRule(id: str, kind: Literal["sha256", "yara"], value: str, action: Literal["block", "observe"], confidence: Literal["high", "medium", "low"])`
- `ScanVerdict(status: Literal["clean", "detected", "unknown"], action: Literal["allow", "block"], rule_id: str | None, rule_version: str, sha256: str | None, reason: str)`

- [x] **Step 1: Write failing tests** named `test_signed_manifest_loads_and_preserves_rule_version`, `test_tampered_manifest_is_rejected`, `test_invalid_rule_and_block_without_high_confidence_are_rejected`. Use a generated Ed25519 test key. Assert `loaded.version == "test-1"`, `len(loaded.rules) == 1`, and `pytest.raises(InvalidRulePackage)` for modified bytes and a `block` rule with `confidence != "high"`.
- [x] **Step 2: Run tests** with `python -m pytest -q tests/test_windows_protection_rules.py`; expect the new imports to fail.
- [x] **Step 3: Implement** Ed25519 verification over the exact manifest bytes and strict JSON/schema checks (including duplicate-field rejection). Keep the production public key outside editable rule data; tests use a temporary key pair. Pin Windows-compatible `cryptography` and `yara-python` releases in `requirements-windows-protection.txt`.
- [x] **Step 4: Run tests** with `python -m pytest -q tests/test_windows_protection_rules.py`; expect all three tests to pass.

### Task 2: Deterministic file scanner

**Files:**
- Create: `cyber_os/protection/scanner.py`
- Test: `tests/test_windows_protection_scanner.py`

**Interfaces:**
- `scan_path(path: Path, rules: RuleSet, *, yara_timeout_seconds: int = 5) -> ScanVerdict`
- Hash files in bounded chunks; YARA rules are compiled only from the verified `RuleSet`.

- [x] **Step 1: Write failing tests** named `test_sha256_block_rule_returns_verified_block_verdict`, `test_observe_match_never_blocks`, `test_clean_file_returns_allow_verdict`, `test_file_mutated_during_scan_returns_unknown`, and `test_yara_timeout_returns_unknown`. Assert respectively: `(status, action, rule_id) == ("detected", "block", "hash-1")`; observe match has `action == "allow"`; clean file has `status == "clean"`; mutation/timeout have `status == "unknown"` and `action == "allow"`.
- [x] **Step 2: Run tests** with `python -m pytest -q tests/test_windows_protection_scanner.py`; expect scanner imports to fail.
- [x] **Step 3: Implement** bounded streaming SHA-256, YARA compilation/matching with a timeout, and pre/post file identity and metadata checks. A failed read, timeout, or changed file returns `unknown`/`allow`, never a block verdict.
- [ ] **Step 4: Run tests** with `python -m pytest -q tests/test_windows_protection_scanner.py`; expect all five tests to pass.

### Task 3: Durable jobs, detections, and quarantine

**Files:**
- Create: `cyber_os/protection/store.py`
- Create: `cyber_os/protection/quarantine.py`
- Create: `cyber_os/protection/service.py`
- Create: `cyber_os/protection/windows_health.py`
- Test: `tests/test_windows_protection_store.py`
- Test: `tests/test_windows_protection_service.py`

**Interfaces:**
- `ProtectionStore(database_path: Path)` provides `record_detection`, `record_action`, `get_status`, `list_threats`, `create_scan_job`, `update_scan_job`, and `get_scan_job`.
- `ProtectionStatus` provides `state`, `driver_state`, `service_state`, `rules_version`, `last_scan`, `counts { detected, blocked, quarantined }`, `windows_security { registered_av_provider, defender_mode }`, `sensor_coverage`, and `last_error`. `ScanJob` provides `job_id`, `scope`, `state`, `files_scanned`, `files_total`, `detections`, `errors`, `started_at`, and `completed_at`.
- `get_windows_security_status() -> WindowsSecurityStatus` reads the registered AV provider and Defender mode where available; it never changes Defender configuration or service state.
- `QuarantineItem` stores `item_id`, original path, quarantined path, SHA-256, rule ID/version, action result, and timestamps. `record_filter_completion(request_id: str, final_io_status: str) -> bool` increments blocked only for a driver completion carrying `STATUS_ACCESS_DENIED`.
- `ProtectionService(store: ProtectionStore, rules: RuleSet, quarantine_root: Path)` provides `scan_file(path: Path) -> ScanVerdict`, `start_scan(scope: Literal["quick", "system"]) -> ScanJob`, `cancel_scan(job_id: str) -> bool`, `quarantine_detection(detection_id: str) -> QuarantineResult`, and `restore_quarantine(item_id: str) -> QuarantineResult`.
- Quick Scan roots are the current user's Downloads, Desktop, and startup folders. System Scan enumerates accessible fixed local volumes. Client input cannot provide arbitrary roots.

- [ ] **Step 1: Write failing tests** named `test_detection_and_action_counts_are_separate`, `test_blocked_count_requires_denied_completion`, `test_scan_job_progress_survives_store_reopen`, `test_scan_cancellation_is_durable`, `test_scan_does_not_follow_symlink_outside_scope`, `test_quarantine_count_requires_verified_move`, `test_failed_move_does_not_count_as_quarantined`, `test_restore_rescans_and_refuses_detected_file`, and `test_windows_security_status_is_read_only_and_optional`. Assert `detected == 1` while `blocked == 0` before completion, then `blocked == 1` only after `record_filter_completion(id, "STATUS_ACCESS_DENIED")`; other final statuses leave it at zero. Assert reopened progress is unchanged, a symlink target outside roots is absent, failed moves do not change quarantine count, detected content is not restored, and an unavailable Windows provider query is represented as unavailable without mutating system state.
- [ ] **Step 2: Run tests** with `python -m pytest -q tests/test_windows_protection_store.py tests/test_windows_protection_service.py`; expect missing store/service symbols.
- [ ] **Step 3: Implement** transactional SQLite records, cancellable background scan jobs, path exclusion for the quarantine directory and service internals, and atomic quarantine moves with post-move SHA-256 verification. On Windows, create the quarantine directory with restrictive ACLs; keep ACL operations behind a platform adapter for unit tests.
- [ ] **Step 4: Run tests** with `python -m pytest -q tests/test_windows_protection_store.py tests/test_windows_protection_service.py tests/test_windows_sensor_service.py`; expect all nine store/service tests and the existing sensor suite to pass.

### Task 4: Core integration check

**Files:** `tests/test_windows_protection_core.py` (new).

- [ ] **Step 1: Write failing tests** named `test_signed_detection_is_durable_and_reproducible` and `test_unknown_verdict_never_creates_blocked_count`; run them and confirm the core integration is missing.
- [ ] **Step 2: Implement** only the small composition adapter needed to exercise package verification, scanning, and durable outcome records together.
- [ ] **Step 3: Run** `python -m pytest -q tests/test_windows_protection_rules.py tests/test_windows_protection_scanner.py tests/test_windows_protection_store.py tests/test_windows_protection_service.py tests/test_windows_protection_core.py`; expect all tests to pass.

## Handoff

The next plan, `2026-10-12-stai-minifilter.md`, consumes `ScanVerdict` and `ProtectionService.scan_file`; it owns the kernel enforcement and VM-only tests.

## Progress (2026-10-12)

Tasks 1–4 are implemented **and verified** this session (the `- [ ]` checkboxes above predate this run). `python -m pytest tests/test_windows_protection_{rules,scanner,store,service,core}.py` → **28 passed, 1 skipped** (the skip is a YARA-runtime test; `yara` is absent on this host). The Task 3 `store`/`service` tests and the Task 4 integration tests were written this run (TDD).

Two correctness bugs were found via the new tests and fixed:
- `ProtectionStore.get_status` fabricated the **Threats Blocked** count from block *verdicts*; it now counts only confirmed `STATUS_ACCESS_DENIED` filter completions (`detected` = all detections; `quarantined` = verified moves).
- `scanner._snapshot` compared a path-based `os.stat` to a handle-based `os.fstat`, so Windows execute-extension files (`.exe/.bat/.cmd/.com`) always tripped a false "file changed → unknown/allow"; it now compares `S_IFMT` type bits only.

Full details, verified source research, and remaining blockers: `docs/superpowers/notes/2026-10-12-stai-protection-progress-and-research.md`.
