# Windows Scheduled Quick Scan Design

**Date:** 2026-10-12
**Status:** Service backend implemented; dashboard controls and Windows VM validation remain
**Parent designs:** [STAI Custom Windows Endpoint Protection Design](2026-10-12-stai-custom-windows-protection-design.md), [Windows Quick Scan Profile Resolution Design](2026-10-12-windows-quick-scan-profile-design.md)

## Goal

Add one durable daily or weekly Quick Scan schedule for the enrolled dashboard user. Scheduled runs use the last successfully resolved profile roots, take an immutable per-job snapshot, and report actual completion and coverage.

This is a useful scan convenience, not a claim of Bitdefender parity or real-time antivirus coverage.

## Chosen approach

Keep one schedule row keyed to the installer-enrolled dashboard SID. The authenticated named-pipe caller may read or update only that schedule when its SID exactly matches the enrolled SID. The request body may contain only `enabled`, `cadence` (`daily` or `weekly`), `local_time` (`HH:MM`), and `days_of_week` for weekly cadence. The service computes due times; callers cannot provide a SID, path, executable, recurrence expression, or next-run timestamp.

The LocalSystem protection service owns a low-frequency timer that evaluates schedules while it is running. It does not register or execute arbitrary Windows Task Scheduler commands. If the PC is off or the service is stopped at the scheduled time, the service performs at most one coalesced catch-up Quick Scan after startup, then advances to the next occurrence. If another scan is active when a scheduled occurrence becomes due, it records that occurrence as skipped and advances; it never launches concurrent scan workers or builds an unbounded backlog.

## Data flow

1. The enrolled dashboard client refreshes the fixed Desktop, Downloads, and Startup known folders through the authenticated service pipe. Refresh requires the exact enrolled SID and publishes all three roots atomically.
2. The client saves schedule settings through strict pipe operations. Enabling a schedule requires a successful saved profile for the enrolled SID.
3. On startup and periodically, the service checks the due local calendar occurrence. A unique schedule-run record prevents duplicate execution for the same local date and cadence.
4. In one database transaction, the service reads the latest successful profile, snapshots its folder IDs and paths into the new `scan_jobs` record, claims the schedule occurrence, and advances the next occurrence.
5. The scan worker uses only the immutable job snapshot. It never resolves a profile or derives roots from the LocalSystem home directory at run time.
6. The API returns cadence, enabled state, next/last run, last job state, and sanitized coverage labels. It never returns raw paths.

## Time and failure policy

- Schedule time is a local wall-clock time and follows the computer's current Windows time zone. Persist and claim a local calendar date so a repeated daylight-saving hour cannot run twice on the same date.
- A due run missed during downtime is coalesced into one run after service startup; older occurrences are not replayed individually.
- If no successful user profile exists, schedule creation or enabling fails clearly. If the profile has stale or inaccessible roots at run time, the job records skipped roots and partial coverage; no alternative roots are substituted. Zero usable roots fails the job.
- A successful profile refresh affects later jobs only. It never changes a running job's snapshot.
- Scheduled Quick Scan runs as LocalSystem and can run while the enrolled user is logged out, using only the saved roots. Offline redirected locations are recorded as skipped.
- The service-owned timer works only while the protection service is running. It checks at most once per minute and performs no filesystem enumeration while idle. Shutdown gates new schedule claims before joining the scheduler and stopping an active scan.

## Security boundaries

- Caller SID comes from the named-pipe token and must equal the enrolled SID for schedule/profile mutation and interactive Quick Scan.
- The service owns recurrence calculation, paths, schedule IDs, run IDs, and task execution. Strict schemas reject extra fields and caller-selected executable commands.
- A scheduled scan cannot broaden its scope, use SYSTEM's profile, call the agent for a verdict, or execute a remediation action beyond the existing deterministic scan policy.
- Persisted profiles, schedules, and snapshots remain in the service's protected ProgramData database. The dashboard receives labels and status only.
- The timer and schedule state do not change minifilter health or protection state.

## Interface

- `refresh_scan_profile`: empty payload; returns readiness, refresh timestamp, resolved folder labels, and sanitized error state.
- `get_scan_schedule`: empty payload; returns the schedule state for the enrolled SID.
- `set_scan_schedule`: exact payload `{enabled, cadence, local_time, days_of_week}`; disabled schedules still validate their enum fields, and non-weekly schedules require an empty days list.
- Scan-job reads include source (`interactive` or `schedule`) and per-root coverage labels/status, never paths.

## Out of scope

- Windows Task Scheduler task registration, schedules while the protection service is stopped, multiple independent schedules, scheduled System Scan, custom paths, per-folder selection, and arbitrary recurrence expressions.
- A trusted local dashboard bridge. The existing hosted desktop UI cannot receive privileged service commands; UI wiring must be delivered with the local bundled-dashboard bridge design.
- Driver callback expansion, a signature-update feed, network or memory scanning, and production antivirus claims. These remain separate parent-design phases and release gates.

## Verification plan

- Database migration preserves existing records and creates schedule/profile/snapshot storage; schedule run claim, snapshot, and next-run update are atomic and unique by local occurrence.
- Resolver publishes only all three known folders for the enrolled SID and leaves the prior profile intact after any lookup failure.
- Pipe rejects extra fields and caller-supplied paths/SIDs; only the enrolled SID can refresh, configure a schedule, or start interactive Quick Scan.
- Daily and weekly recurrence, local-time parsing, DST repeated-hour uniqueness, downtime coalescing, active-scan skip, service restart, and disabled schedule behavior are covered.
- Scheduled scans consume the saved snapshot while logged out, preserve partial coverage for inaccessible roots, and fail with zero usable roots.
- Run integration cases in an isolated Windows VM with a redirected folder and service account LocalSystem. Do not install the development driver on a daily-use workstation.

## Implementation status

The service backend now has durable daily/weekly recurrence, authenticated enrolled-SID pipe operations, atomic occurrence claims with immutable root snapshots, bounded startup catch-up, and explicit skipped/partial/covered root statuses. On service startup, pending/running jobs from an earlier process are failed with root coverage preserved; worker-start failures are also recorded. The protection host attempts to cancel and briefly join an active scan during orderly shutdown.

The schedule is not configurable from the current dashboard because its hosted UI is not connected to the privileged service pipe. Windows VM validation remains outstanding.

## Research

- [Microsoft: About Services](https://learn.microsoft.com/en-us/windows/win32/services/about-services) recommends Task Scheduler for periodic time-triggered work and describes long-running service lifecycle. This first version keeps scheduling inside the already-installed protection service so schedule state and scan-job claiming stay in the protected store; runs therefore require the service to be running, with one bounded catch-up after restart.
- [Microsoft: About the Task Scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler) documents the Windows Task Scheduler 2.0 API for a future phase that must run independently of the service lifecycle.
