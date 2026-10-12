# STAI Windows Protection — Progress & Verified Research (2026-10-12)

**Status: NOT production-ready. Protection is NOT active. STAI has NOT passed any independent lab test.**
This note records verified source research and the engineering progress made on 2026-10-12, plus the blockers that remain before any protection/active/parity claim could be made.

Spec: `docs/superpowers/specs/2026-10-12-stai-custom-windows-protection-design.md`
Program plan: `docs/superpowers/plans/2026-10-12-stai-windows-protection-program.md`

---

## 1. Engineering progress this session (verified)

Environment: Windows 11, Python 3.11.9, `cryptography` 50.0.1 present, **`yara` NOT installed**, no WDK/MSVC, no Hyper-V. `import cyber_os` is slow (~20–30 s).

### Protection core (plan `2026-10-12-stai-protection-core.md`) — Tasks 1–4 verified
`python -m pytest tests/test_windows_protection_{rules,scanner,store,service,core}.py` → **28 passed, 1 skipped** (the 1 skip is a YARA-runtime test, correctly skipped because `yara` is absent). With the escalation-boundary suite added this run: **30 passed, 1 skipped**.

New tests written this session (TDD):
- `tests/test_windows_protection_store.py` (5) — count separation; blocked-requires-denied-completion + replay dedup; scan-job progress durable across store reopen; cancellation durable; Windows security reader read-only + optional.
- `tests/test_windows_protection_service.py` (7) — quarantine requires a verified move; a failed move does not count; restore rescans and refuses a still-malicious file; scope excludes the quarantine dir; symlinks are not followed outside scope (skips if the host forbids symlink creation); a running scan cancels to a durable `cancelled` state.
- `tests/test_windows_protection_core.py` (2) — signed-package → scan → durable record is reproducible; an `unknown` verdict never creates a blocked count.

### Two correctness bugs found and fixed (both security-relevant)
1. **Fabricated "Threats Blocked" count** — `ProtectionStore.get_status` counted `detections WHERE action='block'` as *blocked* and `action='allow'` as *detected*. That makes a mere block *verdict* increment Threats Blocked with **no confirmed denied I/O**, violating the spec invariant and "do not fabricate counts." Fixed: `detected` = all detections; `blocked` = `COUNT(filter_completions WHERE final_io_status='STATUS_ACCESS_DENIED')` (idempotent, dedup'd); `quarantined` = verified moves only. (`cyber_os/protection/store.py`.)
2. **Scanner failed open on every executable** — the integrity snapshot compared a path-based `os.stat` against a handle-based `os.fstat`. On Windows `os.stat(path)` synthesizes execute bits (`0o111`) for executable extensions (`.exe/.bat/.cmd/.com`) but `os.fstat(handle)` cannot, so `st_mode` always differed → spurious "file changed" → `unknown/allow` for exactly the executables an AV must scan/block. Fixed by comparing `stat.S_IFMT(st_mode)` (file-type bits only). (`cyber_os/protection/scanner.py`.) The committed test missed this because it used a `.bin` sample; a `.exe` sample exposed it.

### Dashboard API (plan `2026-10-12-stai-protection-dashboard.md`, backend portion)
`tests/test_windows_protection_api.py` → **10 passed** (`+ test_ui_api_contract.py` 23 passed, no regression). Fixed two 500-crash bugs in the real absent-service fallback (`_UnavailableService` lacked a `store` attribute; its methods closed over a dead `except … as e` variable) so an uninitialised protection service now reports `unavailable` honestly instead of crashing. Added unavailable/404 regression tests. (`ui/api_server.py` protection fallback only; counts still passed straight through.)

### Agent escalation (plan `2026-10-12-stai-agent-escalation.md`) — reviewed, mostly unimplemented
Added `tests/test_protection_escalation_boundary.py` (6 passed) pinning the generic disruptive-action **approval + audit** boundary that Phase 2 must reuse: unknown/denied/no-approver resolutions execute nothing; agent recommendation *text* never executes; approved actions are audited. Review findings in §3.

---

## 2. Verified source research (access date 2026-10-12)

Treat independent lab testing as a future release gate. Microsoft "page last updated" dates noted where captured.

### Minifilter / Filter Manager (driver design grounding only — nothing was built or signed)
- A minifilter pre-op callback **denies I/O** by returning `FLT_PREOP_COMPLETE` after setting the op's final `Data->IoStatus.Status` to a failure NTSTATUS (conventionally `STATUS_ACCESS_DENIED`). Callbacks are registered via `FLT_REGISTRATION.OperationRegistration` + `FltRegisterFilter` in `DriverEntry`. — https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-preoperation-callback-routines
- Kernel↔user comms: kernel `FltCreateCommunicationPort` + `FltSendMessage`; user-mode `FilterConnectCommunicationPort`/`FilterGetMessage`/`FilterReplyMessage`. `FilterGetMessage` has four parameters (port, message buffer, buffer size, optional `OVERLAPPED`); a driver-originated request is answered with `FilterReplyMessage`, not `FilterSendMessage`. For a C reply struct, the driver's `FltSendMessage` receive buffer must hold the entire struct (including padding); user mode should pass `sizeof(FILTER_REPLY_HEADER) + sizeof(reply payload)` to `FilterReplyMessage` per Microsoft's padding guidance. Parse using `offsetof` and validate actual received lengths. — https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsendmessage, https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filtergetmessage, https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filterreplymessage
- Antivirus load-order group is **`FSFilter Anti-Virus`, altitude range 320000–329999**. Microsoft allocates one integer altitude per product via email to **fsfcomm@microsoft.com** (allow ~30 business days; "no mechanism to request outside the process … regardless of urgency"). A dev VM may self-assign a fractional/debug value until then. — https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request and …/load-order-groups-and-altitudes-for-minifilter-drivers
- INF essentials: `ServiceType=2` (SERVICE_FILE_SYSTEM_DRIVER), **`Dependencies=FltMgr`** (mandatory), `PnpLockdown=1`, primitive driver since Win10 1903 (no `DefaultUninstall`), `LoadOrderGroup="FSFilter Anti-Virus"`, `CatalogFile` set to the WHQL AV catalog. "All drivers running on 64-bit Windows must be signed." — https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver
- **Signing gate:** test-signing is dev-VM only ("must not be used for production"). Since **Win10 1607, Windows will not load new kernel-mode drivers not signed by the Microsoft Dev Portal**; an **EV code-signing certificate** is required to open the dashboard account. Submission is **Attestation** (no HLK, client-only) or **WHQL/HLK**. ELAM is a separate early-boot AV trust path to note on the roadmap. — https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-

### Independent lab methodology (STAI has NOT been tested by these)
- **AV-TEST** (home Windows): three categories — Protection, Performance, Usability — **6 points each, 18 max**; **≥10 = Certified**, **≥17.5 = TOP PRODUCT**. Usability measures false positives on legitimate software; Performance measures everyday-task slowdown. Current displayed cycle: July–August 2026. — https://www.av-test.org/en/antivirus/home-windows/microsoft and …/about-the-institute/test-procedures/
- **AV-Comparatives Malware Protection Test:** distinguishes **detection** (recognising a file before execution) from **protection** (preventing any system change, incl. behavioural blocking). Reports Offline Detection, Online Detection, Online Protection rates. A clean set is scanned *and executed*; false positives band and **downgrade the award even with strong protection**. March-2026 test released 2026-04-15, ~10,000 samples, Windows 11 x64. — https://av-comparatives.org/tests/malware-protection-test-march-2026/

### Bitdefender Total Security capability breadth (visual/feature reference only — original STAI identity; no logos/wording reuse)
Modules a mature consumer AV ships: real-time/on-access ("Shield"), on-demand + scheduled scans, boot-sector/early-boot scan, behavioural/zero-day engine (Advanced Threat Defense), ransomware block + file restore, web/online threat prevention (anti-phishing, unsafe-download), vulnerability scan, firewall, quarantine, PUA/script/archive scan toggles. The support pages do **not** state kernel-vs-user-mode implementation — any minifilter attribution to Bitdefender would be inference, not sourced. — https://www.bitdefender.com/consumer/support/answer/121668/ and …/13450/

---

## 3. Remaining blockers & roadmap (for the next engineer)

**Hard blockers (cannot be done on this host):**
- Kernel minifilter **build/sign/load/VM enforcement** — needs a WDK/MSVC machine + an isolated test-signed Windows VM. Production needs Microsoft Dev-Portal signing + an EV cert + a Microsoft-allocated altitude (320000–329999). None exist yet.

**YARA verification update (2026-10-12):** The workspace's default Python lacks YARA, but the packaged Windows Test build environment includes YARA 4.5.4. Running `tests/test_windows_protection_scanner.py` and `tests/test_windows_protection_service.py` with that runtime on `PYTHONPATH` produced **13 passed**, including the YARA rule timeout/match paths. This verifies the Python YARA integration; it does not replace an installed-driver VM test.

**Initial review on 2026-10-12 found the Level 2 path unimplemented.** The continuation below supersedes that status: `triage.py` now redacts detection context, uses a bounded worker, and stores triage separately from Level 1 verdicts. The legacy `record_detection` upsert remains a write-integrity risk for any future caller; Level 2 must continue using only `protection_triage` and related tables.

**Capability roadmap (researched; not yet built):** behavioural/ransomware protection, web/download protection, vulnerability scan, scheduled scans, boot/early-boot (ELAM) scanning. Each needs its own Windows-API + operational-risk research before implementation, and must not be shown as "active" while only planned.

**Release gates (must all be true before any "active"/"protected"/parity claim):** driver + service + verified rule package all healthy; Microsoft-signed driver; supported-Windows VM end-to-end validation; and — for any comparative claim — actual independent lab results. None are met today.

---

## 4. Windows packaging follow-up (2026-10-12)

### Implemented source

- The `windows_protection/installer` tree now contains a WiX v4 per-machine MSI project, a DTF custom-action project, a package builder, a staged updater, and a deliberately blocked release-readiness JSON.
- The MSI lifecycle installs the user-mode service first, runs the minifilter's INF `DefaultInstall`, loads the filter, and accepts activation only after the local service pipe reports `state=active`, a running driver/service, and a concrete verified rules version. Rollback removes owned service/driver state. Uninstall leaves ProgramData database and quarantine contents in place.
- Installer ACLs restrict protection data to SYSTEM and administrators. The named pipe still authorizes the installed dashboard SID, SYSTEM, and administrators.
- Install rollback stores its recovery marker and a protected PowerShell recovery helper in ProgramData, with a SYSTEM AtStartup task registered before service/driver changes. If the minifilter cannot be confirmed unloaded, rollback retains its service/driver registration, driver image, marker, and task; it disables automatic starts and retries cleanup on a later boot. A committed marker makes recovery disarm itself without removing the healthy installation.
- `service_entry.py --stai-verify-rules <manifest> <signature>` verifies a staged rules package with the public key embedded in the executable. The private signing key is never bundled.
- The INF now configures the minifilter for automatic loading so the filter can resume after reboot; this behavior has not been verified in a VM.
- The managed DTF custom-action assembly was compiled successfully with .NET SDK 8.0.401 and DTF 4.0.6. No MSI build or install was performed in this follow-up.
- The updater registers a SYSTEM startup recovery task after writing its transaction journal and before stopping protection. It restarts the unchanged prior service if the filter cannot unload before file replacement; after replacement starts, rollback restores backups and leaves the journal/task in place if restoration fails. MSI uninstall holds the update lock and refuses while a transaction journal remains.
- Release gates pin the approved service/MSI publisher thumbprint, require code-signing and Microsoft hardware-driver EKUs, run SignTool kernel-policy checks against the catalog and package members, compare altitude values numerically, and require reviewed Microsoft Hardware Dev Center altitude evidence. Both checked-in readiness and signer policy remain blocked until real approvals/evidence exist.

### Implementation grounding

- WiX's built-in service-install authoring does not model kernel-driver services, so the MSI uses a deferred, non-impersonated custom action for the driver INF/Filter Manager lifecycle. WiX rollback custom actions are designed to undo deferred system changes. — https://docs.firegiant.com/wix/schema/wxs/serviceinstall/, https://docs.firegiant.com/wix/schema/wxs/customaction/
- A minifilter can be explicitly loaded through `FilterLoad`; dynamically loading it requires the `SeLoadDriverPrivilege`. `InstallHinfSection` processes the INF's install sections. — https://learn.microsoft.com/en-us/windows/win32/api/fltuser/nf-fltuser-filterload, https://learn.microsoft.com/en-us/windows/win32/setupapi/installing-from-an-inf-file
- Microsoft documents validating returned driver-package signatures by inspecting the signing certificate's Enhanced Key Usage; the Windows Hardware Driver Verification OID distinguishes attestation signing from the non-attestation variant. SignTool `/kp` applies kernel-mode signing policy plus PnP installation policy, and `/c` can verify that a package member is covered by its catalog. The Release builder now uses these checks and no longer treats a signer-name substring as proof. — https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-validate, https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/signtool
- DTF managed custom actions are packaged into an MSI-loadable native wrapper and should target a specific .NET Framework version. — https://docs.firegiant.com/wix/tools/dtf/

### Validation state

- The custom-action source compiles. The WiX MSI build has not been validated because no WDK-built `.sys`/`.cat` driver package or signed rules package is supplied. The MSI's deferred actions, rollback, service startup, and uninstall have not run in an isolated Windows VM.
- `build-installer.ps1` marks Test packages non-production and requires external Release evidence for the Microsoft-signed driver catalog, non-debug allocated altitude, clean Windows VM validation, and signed release artifacts. `release-readiness.json` and `release-policy.json` are blocked.
- `update.ps1` records backups, verifies rules with both service binaries, checks health before commit, and schedules startup recovery. Update/rollback behavior has not been run against an installed Windows VM.

## 5. Level 2 provider continuation (2026-10-12)

- `cyber_os/protection/ai_provider.py` now implements an optional, tool-free Gemini `generateContent` adapter and `create_default_host()` injects it into the existing triage provider interface. No API key or cloud consent means `unavailable`; provider status is local-only and does not probe the network.
- Cloud triage requires an explicit admin-run consent prompt plus a key encrypted with Windows LocalMachine DPAPI and stored under the SYSTEM/Administrators-protected `%ProgramData%\STAI\Protection\ai` directory. `Set-ProtectionAiCredential.ps1 -Disable` removes the marker and encrypted key. The setup helper is included in the MSI payload.
- Network requests use a fixed HTTPS Google host, key in `x-goog-api-key`, reject redirects, cap response size and model output, send only the coarse allowlist from `ProtectionTriage`, omit tools, and keep model text separate from Level 1 enforcement. Follow-up chat uses the bounded triage worker pool; the desktop polls the local message history instead of holding the named-pipe request open.
- The AI Agent UI now discloses that opted-in cloud analysis sends minimized metadata, user questions, and up to eight bounded recent turns to Google. The setup instructions document opt-in, revocation, and data handling.
- Verification on this host: protection core + triage + provider + escalation boundary + API suite: **56 passed, 1 skipped**. Dashboard TypeScript check and production Vite build succeeded; the DTF C# project build succeeded; the setup PowerShell parser check succeeded. No live Gemini key/provider request, MSI install, WDK driver build, or isolated Windows VM test was performed.
- Research links: Google [generateContent API](https://ai.google.dev/api/generate-content) and [API key guidance](https://ai.google.dev/gemini-api/docs/api-key); Microsoft [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).

## 6. Detection-to-response continuation (2026-10-12)

- The protection service now exposes the durable detection ID alongside the minifilter verdict. After the detection transaction commits, the host enqueues Level 2 triage; callback failures cannot change the Level 1 result.
- The filter client correlates high-confidence block detections with driver request IDs. It records blocked only on a matching `STATUS_ACCESS_DENIED` completion, then attempts quarantine using the same detection and verdict. Quarantine revalidates the path, rule, version, and SHA-256 before the verified move; it does not rescan and create a duplicate detection row.
- Pending block correlations are bounded to 1,024 entries and cleared when the filter client closes. Completion database keys include a per-client-session nonce because the driver request counter resets on driver load.
- Verification with the packaged YARA 4.5.4 runtime: focused protection suite **97 passed** (9 existing FastAPI/Starlette deprecation warnings). Tests cover durable triage callback ordering/failure isolation, denial-only quarantine, completion correlation and duplicate handling, and detection/verdict binding.
- This remains source-level/user-mode verification. Completion telemetry is best effort in the driver, and no WDK build, signed driver package, or isolated Windows VM enforcement test has been performed. Release gates in §3 remain blocked.
