# SVS-Cyber Engineering Report — 2026-10-15

Scope: `codex/mobile-phase2-tools`. Every number below was measured on this
host, not estimated. Items that could not be verified are labelled as such.

## 0. Execution note

Seven specialist subagents were dispatched in parallel. One (kernel/driver)
completed. The remaining six were killed mid-task by account quota exhaustion
(`402 Budget pool quota has been exhausted` / `403 pre-consume quota failed`),
not by defects. Two of them had already landed substantial committed work
before dying. The rest of the work was completed directly.

## 1. Root cause and fix for the deprecated-driver issue

The initial hypothesis — that `[DefaultInstall.NTamd64]` in
`windows_protection/driver/StaiProtection.inf` was the deprecated construct —
was **wrong**, and was refuted against Microsoft's documentation:
`DefaultInstall` is *required* for file-system filter drivers, and a primitive
driver package must not contain `[Manufacturer]`. Converting the INF would have
broken universal-INF validation and signing. The INF was left as-is, with a
header comment added so it is not "modernised" into a broken state later.

Two genuine causes were found:

1. **Compile-time deprecation, promoted to a hard error.**
   `windows_protection/driver/src/protection_port.c:82,84` called
   `ExAllocatePoolWithTag`, deprecated since Windows 10 version 2004. The
   project sets `WarningLevel=Level4` with `TreatWarningAsError=true`, so the
   C4996 deprecation warning became a build failure. The SDV
   `UnsafeAllocatePool` rule flags the same call as a certification gate.
   Fixed to `ExAllocatePool2(POOL_FLAG_NON_PAGED, ...)`, removing two now
   redundant `RtlZeroMemory` calls. Side benefit: legacy `NonPagedPool` is
   executable, `POOL_FLAG_NON_PAGED` is NX.

2. **Deprecated install mechanism.** `rundll32 setupapi.dll,InstallHinfSection`
   appeared in `update.ps1:67`, `CustomActions/DriverLifecycle.cs:208`, and
   `driver/README.md:47`. Replaced with `pnputil /add-driver <inf> /install`.
   This also closed a silent failure: `rundll32` always exits 0, so
   `update.ps1` was discarding INF install failures entirely.

No user-facing "deprecated driver" string exists anywhere in the repository; a
repo-wide search returned zero hits in `windows_protection/**` and
`cyber_os/protection/**`. The message originates from the toolchain, not the
application.

### Additional driver-project defects found

The `.vcxproj` could not have built at all:

- `Microsoft.Cpp.targets` was never imported, so the project had no `Build`
  target.
- `fltMgr.lib` was absent, guaranteeing unresolved `FltRegisterFilter` /
  `FltSendMessage`.
- `protection_protocol.h` was unreachable (include path lacked
  `$(ProjectDir)..\protocol`) while `driver.h:5` includes it — C1083.
- `ConfigurationType` was `DynamicLibrary` with `Keyword=Win32Proj`; corrected
  to `Driver`.
- No `<Inf Include>` item, so stampinf, InfVerif and catalog generation never
  ran.

Rebuilt against Microsoft's official `scanner.vcxproj`.

## 2. The error the user was actually seeing

The running service reported:

```
event_source:       unavailable
event_source_name:  Win32_ProcessTrace
event_source_error: Win32_ProcessStartTrace subscription failed:
                    (-2147352567, 'Exception occurred.',
                     (0, 'SWbemEventSource', 'Timed out ', None, 0, -2147209215), None)
```

Real-time process-event telemetry was dead, leaving only 1-second polling.

**Root cause** (`ui/windows_process_events.py`): the timeout check was wrong in
two independent ways.

| | In code | Actual |
|---|---|---|
| Constant | `_WMI_E_TIMED_OUT = 0x80041069` | `wbemErrTimedout = 0x80043001` |
| Field checked | `com_error.hresult` -> `0x80020009` (DISP_E_EXCEPTION) | code lives in `excepinfo[5]` |

`SWbemEventSource.NextEvent(1000)` raises a timeout every window in which no
process starts or stops — the normal case. Because the check never matched, the
first idle second was classified as a fatal subscription failure, the watcher
thread `break`s, and telemetry died permanently within seconds of startup.

**Fix:** `_is_wmi_timeout()` inspects both `hresult` and `excepinfo[5]`, accepts
both timeout codes, and falls back to the description text. A genuine failure
(e.g. `Access denied`, 0x80041003) still tears the watcher down and surfaces the
error — verified by test, so the fix cannot mask a real permission problem.

**Why the existing test missed it:** `tests/test_windows_process_events.py:97`
`test_wmi_timeout_keeps_trace_subscription_healthy` asserted the timeout path
using a synthetic flat `.hresult` carrying the same wrong constant. It passed
while the product was broken. That test still passes (both codes accepted);
`tests/test_windows_process_event_timeouts.py` adds 7 tests pinning the
exception shape a live host actually produces.

## 3. Protection-status truthfulness defects

- `cyber_os/protection/service.py` — `get_status()` defaulted
  `service_state="running"` while `ProtectionStore.get_status()` correctly
  defaulted to `"unknown"`. `/api/protection/status`
  (`ui/api_server.py:1601`) calls it with **no arguments**, so the dashboard
  reported a running protection service that nothing had probed. Changed to
  `"unknown"`. Pinned by `tests/test_protection_status_truthfulness.py`.
- `quarantine_detection()` paged `list_threats(limit=1000)` and linear-searched
  it. With `ORDER BY created_at DESC LIMIT 1000`, any detection older than the
  first page returned "detection not found" and was **permanently
  unquarantinable**. Now uses the existing `store.get_detection()`.
- A local `stat = path.stat()` shadowed the `stat` module used by
  `_iter_files`; a per-file scan exception was counted but never logged, so a
  scan failing on every file looked merely "partial".

## 4. Half-finished work completed

- `get_network_telemetry` pipe operation (`windows_service.py`) was specified by
  an untracked test file but never wired. Added to `_EMPTY_OPERATIONS` so it
  accepts **no payload** and cannot be used to smuggle an enforcement
  parameter; status derivation factored into one helper so `get_status()` and
  the pipe surface cannot disagree about whether telemetry is running. Events
  bounded by `MAX_NETWORK_TELEMETRY_EVENTS = 512` so a busy monitor cannot
  produce an oversized frame.
- `tests/test_startup_readiness.py` — all 7 tests patched
  `urllib.request.urlopen`, which a prior rewrite made dead code. They were
  making **real network calls**; the 5 "passing" ones passed only because the
  connection was refused. Repointed at `OpenerDirector.open`, plus a guard test
  that fails loudly if the seam moves again. 10 tests/10.37 s -> 12 tests/0.32 s.
- `tests/test_process_monitor_api.py` — 5 tests patched `_get_process_registry`,
  which is reached only when the protection service is unavailable. On a host
  where the service runs, the endpoints hit the real service and the tests saw
  live PIDs. They passed or failed depending on machine state. Now pinned via
  `_force_local_registry()`, matching the idiom the file's own
  provider-selection tests already used.

## 5. Threat intelligence — verified counts

A prior agent downloaded MalwareBazaar's full SHA-256 export (43 MB zip) and
ingested it. Network access works. Verified contents of the staged database:

```
integrity: ok          schema_version: 1
indicators:        1,196,211
distinct sha256:   1,153,929
by type:  sha256 1,155,399 | url 35,845 | ip 2,847 | domain 1,754 | md5 183 | sha1 183
sources:  malwarebazaar 1,153,884 | urlhaus 33,923 | threatfox 7,424
          | mb_recent 975 | feodo 5
```

**Verified unique malicious SHA-256 count: 1,153,929.** The 2,000,000 target is
not met. No hashes were fabricated to close the gap.

### Filename divergence bug

The ingestion wrote to `<repo>/.protection/threat_intel.db` (underscore), a
filename **no code reads**. Consumers are:

- `ui/api_server.py:184,201` -> `<repo>/.protection/threat-intel.db` (hyphen)
- `cyber_os/protection/windows_service.py:1375-1381` ->
  `%ProgramData%\STAI\Protection\threat-intel.db`

So 1.19M indicators sat orphaned. 400,000 rows were merged into the repo
(dev/API) database before the live file-lock stopped the merge; the complete
1,196,211-row database is verified and staged at
`.protection/threat-intel.db.staged`.

**Not verified:** the contents of the service's own
`%ProgramData%\STAI\Protection\threat-intel.db`. That directory is ACL-protected
and unreadable without elevation.

### On raising the hash count

Storing 10M rows is trivial; making them *detect* anything is not.

- MalwareBazaar's full SHA-256 export is the complete corpus at ~1.2M. There is
  no larger MalwareBazaar.
- The only free source at 10M+ scale is VirusShare, which publishes **MD5-only**
  lists.
- `cyber_os/protection/scanner.py:83` computes **SHA-256 only**; `ScanVerdict`
  carries only `sha256`; `service.py:191` looks up only
  `block_decision("sha256", ...)`.

So 10M MD5 rows today would be inert: ~6 GB of disk, slower updates, zero extra
detections. Making them count requires (a) the scanner to also compute MD5 —
cheap, same file read, (b) the lookup to query MD5, and (c) a confidence model
that treats an MD5-only match as weak evidence, since MD5 is collision-prone and
must not alone justify a block.

Separately, intel is currently **advisory by design**: `threat_intel_status()`
reports `activation: "inactive"`, and `_attach_intel_evidence()` attaches
evidence without granting a verdict, pending signed/staged feed activation. That
is correct — unsigned feed data must not be able to quarantine files — but it
means even the 1.15M SHA-256 hashes do not block yet.

## 6. Tests

| Run | Result |
|---|---|
| Baseline at session start | 5 failed, 804 passed, 2 skipped (204 s) |
| After fixes | **2 failed, 1119 passed, 6 skipped** (471 s) |
| The 2 failures re-run in isolation | **4 passed in 1.82 s** |

The two `test_messaging_service.py` failures are timing/retry tests that were
flaky under the disk contention of a concurrent 1.19M-row database merge and a
PyInstaller build. They pass alone. They are not a regression, and they are not
claimed as fixed.

New tests added this session: `tests/test_protection_status_truthfulness.py`
(5), `tests/test_windows_process_event_timeouts.py` (7), plus the readiness and
process-monitor repairs.

## 7. Capability matrix

| Capability | State |
|---|---|
| WMI process-event timeout classification | IMPLEMENTED AND VERIFIED (unit) |
| Protection-status truthfulness (no fabricated "running") | IMPLEMENTED AND VERIFIED |
| Quarantine lookup beyond the first listing page | IMPLEMENTED AND VERIFIED |
| `get_network_telemetry` read-only pipe operation | IMPLEMENTED AND VERIFIED |
| Startup-readiness probe contract | IMPLEMENTED AND VERIFIED |
| Process-monitor API host-independence | IMPLEMENTED AND VERIFIED |
| Threat-intel database (1,153,929 unique SHA-256) | IMPLEMENTED AND VERIFIED (staged) |
| Threat-intel -> blocking verdicts | PARTIALLY IMPLEMENTED (advisory by design) |
| MD5/SHA-1 indicator matching | NOT IMPLEMENTED (scanner computes SHA-256 only) |
| Driver deprecated-API and project-file repair | IMPLEMENTED BUT UNVERIFIED (no WDK) |
| Driver build / sign / load | BLOCKED BY ENVIRONMENT |
| Service executable carrying the WMI fix | IMPLEMENTED BUT NOT DEPLOYED |
| 2,000,000-hash target | NOT IMPLEMENTED (1,153,929 verified) |
| 10,000+ YARA rules | NOT VERIFIED THIS SESSION |
| Minifilter on-access blocking | BLOCKED BY ENVIRONMENT (unsigned driver) |

## 8. To make the fixes live (requires administrator)

The running service is a frozen PyInstaller binary at
`F:\STAI-Cyber\Protection\STAIProtectionService.exe`, built 2026-10-14 21:16 —
it predates every fix above. Python edits in this repo do **not** affect it.

A rebuilt executable containing the WMI fix is at
`windows_protection/installer/build/Test/dist/STAIProtectionService.exe`
(2026-10-15 10:38). Deploy with the existing script:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "D:\STAI 2\tmp\update-staiprotection.ps1"
```

To give the service the full intelligence database, copy the staged file to the
service data root with the service stopped:

```powershell
Copy-Item "D:\STAI 2\.protection\threat-intel.db.staged" `
  "$env:ProgramData\STAI\Protection\threat-intel.db" -Force
```

Afterwards confirm `event_source` is no longer `unavailable`.

## 9. Unresolved limitations

1. Driver cannot be compiled, signed or loaded here: no WDK kernel headers
   (`fltKernel.h` absent), no InfVerif, no MSBuild. `release-readiness.json`
   reports all five production gates `false`.
2. Minifilter altitude 329999 is an unallocated VM-only debug value — a release
   blocker until Microsoft allocates one.
3. The minifilter blocks synchronously for up to 5 s inside `IRP_MJ_CREATE`
   with a PID-exact recursion guard that does not cover child processes of the
   service — a stall surface requiring an async pended redesign.
4. The service's own intel database in `%ProgramData%` was not inspected
   (ACL-protected, needs elevation).
5. The remaining 796,211 rows were not merged into the repo database because
   the live process holds a write lock; the complete database is staged instead.
6. Sensor catalogue (claimed 256), YARA rule count, tool-orchestration and
   agent-swarm spawn, and UI mock-data removal were **not** audited — those four
   agents were killed by quota before reporting.
7. Scan progress reports `files_total` as "discovered so far", so a progress
   bar derived from it can never be accurate without a pre-pass.
