# Windows Quick Scan Profile Resolution Design

**Date:** 2026-10-12
**Status:** Service backend implemented; local dashboard bridge and Windows VM validation remain
**Parent design:** [STAI Custom Windows Endpoint Protection Design](2026-10-12-stai-custom-windows-protection-design.md)

## Goal

Make Quick Scan target the enrolled dashboard user's real Windows folders while keeping the protection service running as LocalSystem. Persist only Windows-resolved folder locations, associate each scan with an immutable root snapshot, and make unavailable or stale profile resolution visible instead of silently scanning the service account's profile.

This is a correctness phase inside the approved STAI Windows protection design. It does not claim parity with commercial antivirus products and does not complete the wider protection goal.

## Current evidence

- The installer invokes the service install command without a service account. The frozen pywin32 service command leaves `userName` as `None`, which Windows `CreateService` treats as LocalSystem.
- `cyber_os/protection/service.py` defines `SCAN_ROOTS_QUICK` at import time from `Path.home()` and uses that global when the worker starts. Under LocalSystem this can resolve to the SYSTEM profile, not the dashboard user's folders.
- `cyber_os/protection/windows_service.py` authenticates named-pipe callers, but `_authenticated_client()` returns only a boolean and closes the token before request dispatch. The pipe ACL also admits SYSTEM and local administrators.
- The strict `start_scan` pipe schema accepts only a scope; a lifecycle test explicitly rejects caller-supplied roots. That invariant must remain.
- The store persists scan scope and progress but no user profile roots or per-job root snapshot.
- There is no existing recurring scan scheduler. This design supplies the profile data needed by a later scheduled-scan phase; it does not add recurrence or Task Scheduler integration.

## Chosen approach

Use the existing authenticated named-pipe connection to identify the caller. During a narrowly scoped refresh operation, the service impersonates the pipe client, verifies that its SID exactly matches the installer-enrolled dashboard SID, and resolves the fixed `FOLDERID_Desktop`, `FOLDERID_Downloads`, and `FOLDERID_Startup` locations with `SHGetKnownFolderPath` and that user's token. The service always reverts to itself before dispatching other privileged work.

The design avoids accepting SIDs or filesystem paths in request JSON. It also avoids selecting a user through the active console session, which can be ambiguous when multiple or remote sessions exist. LocalSystem remains the service account so the protection service and minifilter continue to use their established privileged service boundary.

## Components and data flow

1. **Dashboard startup and scan action:** The bundled local Tauri dashboard invokes a typed `refresh_scan_profile` command at startup and immediately before Quick Scan. It sends an empty, strict payload; it never sends paths. The UI receives readiness, last successful refresh time, and folder labels, but not raw folder paths.
2. **Pipe authentication:** The pipe server captures the actual client SID from the pipe token and carries it in a trusted in-process request context. The SID is never read from JSON. Existing SYSTEM/admin authorization remains for existing management operations; only the enrolled dashboard SID may refresh its profile or request an interactive Quick Scan.
3. **Known-folder resolution:** The service opens the authenticated thread token with the rights required by the known-folder API, resolves only Desktop, Downloads, and Startup, frees returned buffers, and calls `RevertToSelf` in a `finally` path. All three lookups must succeed to publish a successful profile refresh. A failed impersonation, token lookup, SID match, hive lookup, or folder lookup leaves the last successful profile intact and reports refresh failure. No fallback to `Path.home()`, SYSTEM profile, or whole-drive scanning is allowed for Quick Scan.
4. **Persistence:** Add a per-SID scan-profile record in the existing protected SQLite store with the known-folder identifiers, canonical absolute paths, and successful refresh timestamp. Replace a profile atomically only after validation succeeds. Do not persist access tokens. Existing ProgramData ACLs continue to limit the database to SYSTEM and administrators.
5. **Scan snapshot:** When a Quick Scan starts, the service reads the enrolled profile and stores an immutable per-job snapshot of the folder identifiers and paths before starting the worker. The worker uses that snapshot, never a mutable global or a later profile refresh. The dashboard response exposes folder labels and coverage only; raw paths remain local to the service database.
6. **Dashboard state:** Show whether the enrolled user's scan profile is ready, when it was last refreshed, which known-folder labels could not be resolved, and a clear refresh error. A folder that resolved successfully but is offline or unreadable at scan time is reported as skipped and makes coverage partial. Quick Scan is disabled when there has never been a successful profile resolution or the current refresh attempt failed; System Scan remains available independently.
7. **Scheduled scans:** A later scheduler phase can use the same persisted profile and snapshot semantics. If a scheduled job runs while the dashboard user is logged off, it uses the last successfully saved roots and reports missing/inaccessible folders. The scheduler must not guess a user profile or use the LocalSystem home directory.

## Root handling and failure behavior

- Treat the Windows known-folder result as the intended root, including folders redirected to OneDrive or another configured location; do not derive a path by concatenating `Path.home()` with folder names.
- A failed refresh leaves the last successful profile intact for diagnostics and later scheduled-job reporting, but does not authorize a new interactive Quick Scan until a fresh refresh succeeds.
- If an individual folder could not be resolved by the Windows known-folder API, the refresh fails and the dashboard labels that folder as unresolved. If a previously resolved folder is offline or unreadable when a scan starts, record it as skipped with an access/missing-root error and report partial coverage. If no usable roots remain, fail the job with a clear error.
- A job's resolved roots are immutable after creation. Folder changes take effect after the next successful profile refresh and apply only to later jobs.
- Do not follow descendant directory reparse points or junctions outside the selected roots. The known-folder path itself is an authorized root even when Windows redirection maps it elsewhere. Report skipped reparse points and inaccessible roots through the scan's error accounting.
- Normalize and de-duplicate overlapping roots using Windows path semantics. Preserve root identifiers so the dashboard can explain coverage without displaying profile paths.
- A user/SID change during reinstall cannot inherit another SID's roots. Profile lookup is keyed to the enrolled SID; a missing or mismatched entry is unavailable, not a reason to broaden scanning.

## Security boundaries

- Caller identity comes from the named-pipe token, never from the request body.
- `refresh_scan_profile` and interactive Quick Scan require exact equality with the enrolled dashboard SID. SYSTEM and administrator clients cannot refresh or substitute another user's roots.
- The resolver accepts only the three compiled-in known-folder identifiers. No caller-controlled path list, environment variable, registry value, or active-session lookup may replace this allowlist.
- Impersonation is limited to SID verification and known-folder resolution. The service must check that impersonation succeeds, validate the token SID, and revert in all paths before it performs SYSTEM-level scanning or other dispatch.
- Raw paths remain within the SYSTEM/administrators-protected store and are not sent to the dashboard or Level 2 agent. Scan detection data already follows the parent design's local-only data policy.
- Profile resolution failure affects Quick Scan readiness only; it never changes the minifilter's Level 1 verdict policy or makes the dashboard claim protection is active.

## Data model and interface changes

- Add a versioned scan-profile table keyed by enrolled SID, storing fixed known-folder IDs, canonical roots, and refresh time.
- Add per-job scan-root snapshot storage linked to `scan_jobs`; snapshot creation and job creation must be atomic.
- Carry authenticated caller context as a separate internal value through the pipe server, request handler, and host dispatch. Preserve strict operation payload validation and add an empty-payload `refresh_scan_profile` operation.
- Add a typed Tauri command and frontend API for profile refresh/readiness. The dashboard must not receive raw paths.
- Add store/service methods for profile replacement, profile retrieval, and immutable root snapshots. Quick Scan must receive roots explicitly from the saved profile; remove production reliance on import-time `Path.home()` roots.
- Keep non-Windows service tests able to inject a deterministic profile/root provider without introducing a production fallback to arbitrary paths.

## Verification plan

- Store: migration from the current schema; atomic replacement; per-SID isolation; restart persistence; immutable job snapshot.
- Pipe: malformed or extra payload fields remain rejected; caller identity cannot be spoofed in JSON; enrolled SID may refresh; SYSTEM, administrator-only, and other-user callers cannot refresh or start an interactive Quick Scan.
- Resolver: expected known-folder IDs; redirected paths; missing profile hive; absent/insufficient token rights; impersonation failure; API failure; guaranteed reversion; no path fallback.
- Service: a Quick Scan enumerates only the saved snapshot; a refresh during a running scan cannot change its roots; missing roots are reported; zero valid roots fails clearly; no SYSTEM-profile fallback.
- UI: startup refresh readiness is visible; Quick Scan is gated on fresh resolution; System Scan remains independent; raw filesystem paths do not render.
- Windows VM: install for an enrolled user while the service runs LocalSystem; verify Desktop/Downloads/Startup resolution including a redirected known folder; restart the service and confirm persisted profile; run authorized and unauthorized pipe cases; confirm the service scans the expected roots and reports missing roots accurately.

## Out of scope for this phase

- Windows Task Scheduler registration, multiple schedules, System Scan scheduling, and schedule UI. The approved first scheduled Quick Scan phase is specified separately in [Windows Scheduled Quick Scan Design](2026-10-12-windows-scheduled-quick-scan-design.md).
- Changes to service account, minifilter callback behavior, antivirus provider registration, threat rules, quarantine policy, or Level 2 triage.
- Claiming production readiness, broad malware-detection coverage, or parity with Bitdefender. Driver signing, allocated altitude, isolated-VM enforcement, and independent security testing remain parent-design release gates.

## Research references

- [Microsoft: CreateService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea) — a null service start account selects LocalSystem.
- [Microsoft: SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath) — resolve known folders for a specific user's token; the user's registry hive must be mounted.
- [Microsoft: Impersonating a Named Pipe Client](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client) — use a pipe client's security context and revert after scoped work.
- [Microsoft: LocalSystem account](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account) — service account behavior and profile context.

## Self-review

- All requirements are concrete, with no unresolved items.

## Implementation status

The service resolves the three fixed folders for the authenticated enrolled SID using a token opened with the rights required by `SHGetKnownFolderPath`, publishes the complete profile atomically, snapshots roots into each Quick Scan job, avoids duplicate work for overlapping roots, and records inaccessible folders as partial coverage. The dashboard bridge and isolated Windows VM validation remain outstanding.
- Manual Quick Scan and future scheduled scans use the same enrolled profile while keeping schedule recurrence out of this phase.
- The service never trusts a caller-supplied SID or path and never silently falls back to a different profile or whole-drive scope.
- Raw path privacy, per-job snapshot consistency, pipe caller authorization, and profile-hive failure behavior are explicit.
