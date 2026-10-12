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
- Kernel↔user comms: kernel `FltCreateCommunicationPort` + `FltSendMessage`; user-mode `FilterConnectCommunicationPort`/`FilterGetMessage`/`FilterReplyMessage`. Size reply buffers as `sizeof(whole struct)` to avoid `STATUS_BUFFER_OVERFLOW`. — https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsendmessage
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
- **YARA engine** not installed here, so YARA-rule detection is unverified end-to-end; SHA-256 detection is verified. `requirements-windows-protection.txt` pins `yara-python` but its install was not completed/verified.

**Agent-escalation Phase 2 is largely unimplemented** (review this run): no `triage.py`/`agent_triage.py`, no redaction of detection records before the agent sees them (`DetectionRecord` carries full `file_path`), `triage_enqueued` is never set True, and the triage endpoints are `501`/placeholder. Roadmap: build a redacted `ProtectionTriageContext.from_detection` (allowlist fields; exclude path/user/cmdline/contents), a dedup'd enqueue keyed on `detection_id`, and a bounded agent worker whose results are stored **write-separately** from the Level-1 detection row.
- **Latent integrity risk:** `ProtectionStore.record_detection` uses `INSERT OR REPLACE` keyed on `detection_id` (`store.py`). A future triage/agent writer that reuses an id could overwrite a Level-1 verdict. Store triage results in a separate table; never let the agent path rewrite the detection row.

**Capability roadmap (researched; not yet built):** behavioural/ransomware protection, web/download protection, vulnerability scan, scheduled scans, boot/early-boot (ELAM) scanning. Each needs its own Windows-API + operational-risk research before implementation, and must not be shown as "active" while only planned.

**Release gates (must all be true before any "active"/"protected"/parity claim):** driver + service + verified rule package all healthy; Microsoft-signed driver; supported-Windows VM end-to-end validation; and — for any comparative claim — actual independent lab results. None are met today.
