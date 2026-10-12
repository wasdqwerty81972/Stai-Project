# Windows Scan Profiles and Scheduled Quick Scans Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Make Quick Scan use the enrolled Windows user's known folders and add one durable daily or weekly scheduled Quick Scan.

**Architecture:** The named-pipe server carries a trusted authenticated caller context into host dispatch. The service resolves a fixed allowlist of Windows known folders for the enrolled user, persists a profile, and snapshots roots atomically into each Quick Scan job. A service-owned scheduler claims at most one due occurrence, invokes the same scan service, and records schedule state. The schedule is exposed over the strict pipe API; a privileged dashboard bridge is a separate follow-on.

**Tech Stack:** Python 3, pywin32, Windows Shell known-folder API via ctypes, SQLite, pytest, existing Windows Filter Manager service and named-pipe protocol.

**Spec:** `docs/superpowers/specs/2026-10-12-windows-quick-scan-profile-design.md`; `docs/superpowers/specs/2026-10-12-windows-scheduled-quick-scan-design.md`

## Global Constraints

- The service remains LocalSystem.
- Quick Scan resolves only Desktop, Downloads, and Startup from the authenticated enrolled user.
- Never trust a SID or path from request JSON.
- Never fall back to `Path.home()`, the SYSTEM profile, or whole-drive scanning for Quick Scan.
- Raw paths remain in the protected service store and never appear in pipe responses.
- A scan's roots are immutable after job creation.
- Only an exact enrolled SID can refresh profile data, mutate the schedule, or start interactive Quick Scan.
- A schedule is one daily or weekly Quick Scan; only the service calculates occurrences.
- Scheduled occurrence claim, job creation, root snapshot, and schedule advancement are atomic.
- Schedule missed-run policy: at most one coalesced catch-up after service startup; skip and record when another scan is already active.
- Never claim production readiness or commercial antivirus parity; Windows VM, signing, and altitude gates remain.

## Review Focus

- LocalSystem or administrator caller cannot substitute user roots — cover exact SID authorization at pipe dispatch.
- One failed known-folder API lookup cannot publish a mixed or partial new profile — cover atomic refresh.
- A profile refresh during a scan cannot change roots — cover immutable snapshots.
- Missed schedule dates and DST repeated wall time cannot trigger duplicate or unbounded scans — cover unique local occurrence claims.
- Offline redirected roots cannot silently disappear from coverage — cover skipped-root/error accounting and zero-usable-root failure.

---

### Task 1: Persist scan profiles and immutable job roots

**Files:**
- Modify: `cyber_os/protection/store.py`
- Modify: `cyber_os/protection/models.py`
- Test: `tests/test_windows_protection_store.py`

**Interfaces:**
- Produces `ScanProfile(owner_sid: str, roots: tuple[tuple[str, str], ...], refreshed_at: str)` and `ScanRootSnapshot(job_id: str, folder_id: str, path: str)`.
- `ProtectionStore.replace_scan_profile(owner_sid, roots, refreshed_at) -> ScanProfile` replaces all fixed roots transactionally.
- `ProtectionStore.get_scan_profile(owner_sid) -> ScanProfile | None`.
- `ProtectionStore.create_scan_job_with_roots(job_id, scope, roots, source='interactive') -> ScanJob` atomically inserts job and root snapshots.
- Schema migration adds versioned `scan_profiles`, `scan_job_roots`, `scan_schedules`, and `scan_schedule_runs` tables without deleting existing rows.

- [x] Write failing store tests for migration preservation, per-SID isolation, atomic profile replacement, and immutable job snapshots.
- [x] Run the focused store tests and verify the expected failures.
- [x] Add the new data models, migration, and store methods.
- [x] Run focused store tests and the protection store suite.
- [x] Commit `feat: persist enrolled scan profiles and job roots`.

### Task 2: Resolve Windows known folders and carry caller identity

**Files:**
- Create: `cyber_os/protection/windows_profile.py`
- Modify: `cyber_os/protection/windows_service.py`
- Modify: `tests/test_windows_protection_service_lifecycle.py`
- Create: `tests/test_windows_protection_windows_profile.py`

**Interfaces:**
- `KnownFolderResolver.resolve(token_handle) -> tuple[tuple[str, str], ...]` resolves exactly Desktop, Downloads, Startup, failing the refresh if any API lookup fails.
- `_authenticated_client(handle) -> AuthenticatedPipeClient | None` returns the verified SID and a duplicated short-lived token handle; all handles close after dispatch.
- Pipe dispatch receives trusted `caller_sid` and token context separately from the JSON payload.
- `refresh_scan_profile` payload is `{}`; `get_scan_schedule` payload is `{}`; `set_scan_schedule` is strictly validated.

- [x] Write failing resolver and pipe tests for allowlisted folder IDs, lookup failures, spoofed SIDs, strict payloads, and enrolled-user authorization.
- [x] Run focused tests and confirm failures are from missing behavior.
- [x] Implement token capture/cleanup, known-folder resolution, and SID-gated dispatch; always revert impersonation in `finally`.
- [x] Run focused resolver and lifecycle tests.
- [x] Commit `feat: resolve scan roots for the enrolled Windows user`.

### Task 3: Make Quick Scan consume its saved root snapshot

**Files:**
- Modify: `cyber_os/protection/service.py`
- Modify: `cyber_os/protection/store.py`
- Modify: `tests/test_windows_protection_service.py`
- Modify: `tests/test_windows_protection_scanner.py`

**Interfaces:**
- `ProtectionService.refresh_scan_profile(owner_sid, token_handle) -> ScanProfile` resolves through an injectable provider and persists only a complete profile.
- `ProtectionService.start_scan(scope, *, roots=None, source='interactive') -> ScanJob` requires explicit saved roots for Quick Scan; System Scan keeps its existing fixed-volume policy for this task.
- The worker receives roots captured with the job and reports missing/unreadable roots as errors; zero usable roots fails.

- [x] Write failing service tests for no fallback, snapshot immutability, missing roots, and zero usable roots.
- [x] Run focused service tests and verify failures.
- [x] Implement profile refresh/readiness and snapshot-driven Quick Scan, removing production `Path.home()` roots.
- [x] Run focused service tests and the protection core suite.
- [x] Commit `fix: scan enrolled user roots in quick scans`.

### Task 4: Add a durable daily or weekly schedule

**Files:**
- Modify: `cyber_os/protection/store.py`
- Create: `cyber_os/protection/scheduler.py`
- Modify: `cyber_os/protection/windows_service.py`
- Modify: `tests/test_windows_protection_store.py`
- Create: `tests/test_windows_protection_scheduler.py`
- Modify: `tests/test_windows_protection_service_lifecycle.py`

**Interfaces:**
- `ScanSchedule(owner_sid, enabled, cadence, local_time, days_of_week, last_run_date, last_job_id, last_result)`.
- `ProtectionStore.set_scan_schedule(owner_sid, settings) -> ScanSchedule`; requires a saved profile before enabling.
- `ProtectionStore.claim_due_scan(owner_sid, now_local, scan_active) -> ScanJob | None` atomically snapshots current profile roots and claims one occurrence.
- `ProtectionScheduler.start()` checks once per minute; `stop()` joins promptly. At most one catch-up is run after service downtime; active-scan collisions are recorded as skipped.
- Pipe operations are exact enrolled-SID-only `get_scan_schedule` and `set_scan_schedule`.

- [x] Write failing store/scheduler tests for daily and weekly due times, unique occurrence claim, catch-up, active-scan skip, and disabled schedules.
- [x] Run focused schedule tests and verify expected failures.
- [x] Implement durable schedule storage, recurrence calculation, and service-owned polling.
- [x] Run focused scheduler and lifecycle tests.
- [ ] Commit `feat: schedule daily and weekly quick scans`.

### Task 5: Reconcile feature inventory and release limits

**Files:**
- Modify: `docs/superpowers/specs/2026-10-12-stai-custom-windows-protection-design.md`
- Modify: `docs/superpowers/specs/2026-10-12-windows-quick-scan-profile-design.md`
- Modify: `docs/superpowers/specs/2026-10-12-windows-scheduled-quick-scan-design.md`

- [x] Update implementation status to distinguish delivered service backend from UI bridge, driver, signature feed, signing, altitude, and VM gates.
- [x] Inspect the final diff and confirm no claim of production antivirus parity or active protection without evidence.
- [ ] Commit `docs: record Windows scan feature status`.

## Pre-flight / boundaries

- Existing dark dashboard UI and typed HTTP API are present, but the local HTTP development service does not connect to the installed Windows pipe. This plan does not wire privileged controls into the hosted UI.
- Driver callback scope remains limited to selected open/image-mapping operations; ransomware-style write/rename/delete protection remains a later security-reviewed driver phase.
- Rule verification exists; signed rule update delivery/rollback and real intelligence-feed depth remain missing.
- Quarantine ACL verification, local bundled UI bridge, cross-volume System Scan, Windows VM tests, Microsoft signing, and allocated altitude remain separate work.

## Manual Windows verification

- On an isolated Windows 10/11 VM with the development filter package, verify the service remains LocalSystem and profile roots match the logged-in enrolled SID, including a redirected folder.
- Save daily and weekly schedules, restart the service after one missed occurrence, and confirm one catch-up job with immutable roots.
- Log off the dashboard user, run the scheduled job, and verify inaccessible roots are reported without falling back to SYSTEM paths.
- Confirm the current hosted dashboard does not claim that these pipe-only schedule operations are connected.
