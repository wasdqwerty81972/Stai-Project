# STAI Windows Protection Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package the trusted local dashboard, protection service, and testable driver lifecycle into a Windows installer with explicit rollback and release-signing gates.

**Architecture:** Bundle the Python protection service as a Windows service executable and the static protection dashboard as local Tauri assets. Use an elevated Windows installer for service and driver lifecycle; keep Tauri UI updates separate from kernel-driver installation. Production readiness is blocked until the signed driver and end-to-end VM evidence exist.

**Tech Stack:** PyInstaller, pywin32, Tauri 2, WiX Toolset v4 MSI, WDK, SignTool, Windows 10/11 x64 VM.

**Spec:** `docs/superpowers/specs/2026-10-12-stai-custom-windows-protection-design.md`

## Global Constraints

- The Windows installer owns elevated service/driver installation and lifecycle.
- Updates are staged and rollback-capable.
- Production x64 driver release requires Microsoft Hardware Dev Center signing and validation.
- Production minifilter installation requires its unique Microsoft-allocated altitude.
- A release cannot claim active STAI protection unless the driver, service, and verified rules are healthy.
- Driver installation testing uses isolated Windows VMs with test signing.

## Review Focus

- Fresh install without elevation: fail clearly without partial service/driver state; test in Task 2.
- Driver load or service start fails: roll back and report unavailable; test in Task 2.
- Update interrupted during staging: restore prior known-good service, driver, and rules; test in Task 3.
- Unsigned test package: permit only VM test mode and label the package non-production; test in Task 1.
- Uninstall with pending quarantine data: preserve user data unless the user explicitly selects removal; test in Task 2.

## Progress (2026-10-12 follow-up)

- Task 1 is implemented. The Windows service host and local dashboard bundle were built and smoke-checked in the prior work session; the test build has no trusted rules key and therefore truthfully remains unavailable.
- Task 2 implementation source is present: WiX v4 MSI, DTF lifecycle custom actions, interactive dashboard SID capture, SYSTEM/admin-only ProgramData ACLs, signed rule package staging, service-first driver activation, bounded health handshake, rollback, and data-preserving uninstall. A SYSTEM startup task consumes the protected ProgramData rollback marker; incomplete rollback retains the task/marker and disables auto-start while recovery retries. The managed custom-action assembly builds successfully.
- Task 2 MSI build and VM assertions remain blocked: this environment has no WDK-built `.sys`/`.cat` package, no isolated STAI test VM, and no supplied signed test rules package. Do not count the preflight gate as a passing VM suite.
- Task 3 staged updater, SYSTEM startup recovery task, uninstall/update exclusion, and blocked release policy/readiness manifests are implemented. Production signing checks pin a publisher, validate required EKUs and driver kernel-signing policy, normalize altitude comparisons, and require reviewed Microsoft allocation evidence. Update and rollback execution have not been run against a Windows VM.
- Full-stack acceptance and production readiness remain incomplete. The release gate must stay blocked until the actual driver package, allocated production altitude, Microsoft signing evidence, and end-to-end VM results exist.

---

### Task 1: Service executable and local dashboard bundle

**Files:**
- Create: `cyber_os/protection/windows_service.py`
- Create: `windows_protection/installer/pyinstaller.spec`
- Create: `windows_protection/installer/build-service.ps1`
- Modify: `ui/hackerai/packages/desktop/src-tauri/tauri.conf.json`
- Modify: `ui/hackerai/packages/desktop/scripts/build.js` or replace its hosted URL rewrite with the local dashboard build
- Test: `tests/test_windows_protection_service_lifecycle.py`

**Interfaces:**
- Service owns the named pipe `\\.\pipe\STAI.Protection.v1` and minifilter port `\STAIProtectionPort`.
- `get_protection_status` reports driver, service, rule package, and database health independently.
- Service configuration and rule-signing public key are read-only at runtime; the build accepts an Ed25519 public-key PEM and embeds only its raw public bytes. Signing private keys are not shipped.

- [x] **Step 1: Write failing lifecycle tests** named `test_service_status_is_unavailable_before_driver_and_rules_are_ready`, `test_service_startup_does_not_claim_active_on_filter_failure`, and `test_pipe_acl_rejects_untrusted_client`. Assert no `Active` state unless the driver, service, and signed rule package are all healthy; a pipe client outside the installed service SID/current-user policy cannot read or issue requests.
- [x] **Step 2: Run** `python -m pytest -q tests/test_windows_protection_service_lifecycle.py`; initial failures exposed missing service host and pipe behavior, then passed after implementation.
- [x] **Step 3: Implement** Windows service entry/stop handlers, startup health gating, restrictive named-pipe ACLs, and a repeatable PyInstaller build that excludes development keys.
- [x] **Step 4: Build** with `powershell -ExecutionPolicy Bypass -File windows_protection/installer/build-service.ps1 -Configuration Test`; Test executable and valid dependency manifest built and smoke-checked. No public key was supplied, so the executable truthfully reports protection unavailable.

### Task 2: Elevated installer and uninstall

**Files:**
- Create: `windows_protection/installer/StaiProtection.wixproj`
- Create: `windows_protection/installer/Product.wxs`
- Create: `windows_protection/installer/CustomActions/DriverLifecycle.cs`
- Create: `windows_protection/installer/tests/Invoke-InstallerVmTests.ps1`

- [ ] **Step 1: Add VM assertions** named `test_install_requires_elevation`, `test_install_registers_service_and_filter`, `test_failed_driver_start_rolls_back_service`, `test_uninstall_preserves_quarantine`, and `test_test_signed_build_is_marked_nonproduction`.
- [x] **Step 2: Implement** an elevated MSI that stages service and signed driver files, starts the service before attaching the filter, validates all health checks, and rolls back on failure. Uninstall preserves quarantine unless an explicit removal option is selected.
- [ ] **Step 3: Build** with `dotnet build windows_protection/installer/StaiProtection.wixproj -c Release`; expect an MSI and no signing secrets in generated artifacts.
- [ ] **Step 4: Run** `powershell -ExecutionPolicy Bypass -File windows_protection/installer/tests/Invoke-InstallerVmTests.ps1 -VmName STAI-AV-Test`; expect all five VM assertions to pass.

### Task 3: Staged update, rollback, and release gate

**Files:**
- Create: `windows_protection/installer/update.ps1`
- Create: `windows_protection/installer/release-readiness.json`
- Create: `windows_protection/installer/tests/Invoke-UpdateRollbackVmTests.ps1`

- [ ] **Step 1: Write failing VM assertions** named `test_interrupted_update_keeps_prior_version`, `test_invalid_rule_signature_rolls_back_package`, `test_new_driver_health_failure_restores_previous_driver`, and `test_release_gate_rejects_test_signature`.
- [x] **Step 2: Implement** staged update payloads, health-checked activation, rollback metadata, and a release gate requiring Microsoft signing evidence, supported Windows VM results, and clean installer tests.
- [ ] **Step 3: Run** `powershell -ExecutionPolicy Bypass -File windows_protection/installer/tests/Invoke-UpdateRollbackVmTests.ps1 -VmName STAI-AV-Test`; expect all four assertions to pass.
- [ ] **Step 4: Report** production signing and altitude allocation as pending unless the organization has supplied both; do not label the test package production-ready.

## Full-stack acceptance

- [ ] Run the core pytest commands in `2026-10-12-stai-protection-core.md`.
- [ ] Build and run the minifilter VM suite in `2026-10-12-stai-minifilter.md`.
- [ ] Run agent/API tests and the dark dashboard unit/type checks in their plans.
- [ ] Install on a clean Windows 10/11 x64 VM; verify the inert signed marker fixture is denied before image mapping, a benign fixture launches, scan progress persists, quarantine/restore outcomes are verified, and the dashboard reports truthful health and counts.
- [ ] Verify a production release is blocked until Microsoft driver-signing evidence and end-to-end validation records are present.
