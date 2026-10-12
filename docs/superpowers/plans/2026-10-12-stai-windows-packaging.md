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
- Service configuration and rule-signing public key are read-only at runtime; signing private keys are not shipped.

- [ ] **Step 1: Write failing lifecycle tests** named `test_service_status_is_unavailable_before_driver_and_rules_are_ready`, `test_service_startup_does_not_claim_active_on_filter_failure`, and `test_pipe_acl_rejects_untrusted_client`. Assert no `Active` state unless the driver, service, and signed rule package are all healthy; a pipe client outside the installed service SID/current-user policy cannot read or issue requests.
- [ ] **Step 2: Run** `python -m pytest -q tests/test_windows_protection_service_lifecycle.py`; expect missing Windows service adapter.
- [ ] **Step 3: Implement** Windows service entry/stop handlers, startup health gating, restrictive named-pipe ACLs, and a repeatable PyInstaller build that excludes development keys.
- [ ] **Step 4: Build** with `powershell -ExecutionPolicy Bypass -File windows_protection/installer/build-service.ps1 -Configuration Test`; expect an executable and a dependency manifest with no private key material.

### Task 2: Elevated installer and uninstall

**Files:**
- Create: `windows_protection/installer/StaiProtection.wixproj`
- Create: `windows_protection/installer/Product.wxs`
- Create: `windows_protection/installer/CustomActions/DriverLifecycle.cs`
- Create: `windows_protection/installer/tests/Invoke-InstallerVmTests.ps1`

- [ ] **Step 1: Add VM assertions** named `test_install_requires_elevation`, `test_install_registers_service_and_filter`, `test_failed_driver_start_rolls_back_service`, `test_uninstall_preserves_quarantine`, and `test_test_signed_build_is_marked_nonproduction`.
- [ ] **Step 2: Implement** an elevated MSI that stages service and signed driver files, starts the service before attaching the filter, validates all health checks, and rolls back on failure. Uninstall preserves quarantine unless an explicit removal option is selected.
- [ ] **Step 3: Build** with `dotnet build windows_protection/installer/StaiProtection.wixproj -c Release`; expect an MSI and no signing secrets in generated artifacts.
- [ ] **Step 4: Run** `powershell -ExecutionPolicy Bypass -File windows_protection/installer/tests/Invoke-InstallerVmTests.ps1 -VmName STAI-AV-Test`; expect all five VM assertions to pass.

### Task 3: Staged update, rollback, and release gate

**Files:**
- Create: `windows_protection/installer/update.ps1`
- Create: `windows_protection/installer/release-readiness.json`
- Create: `windows_protection/installer/tests/Invoke-UpdateRollbackVmTests.ps1`

- [ ] **Step 1: Write failing VM assertions** named `test_interrupted_update_keeps_prior_version`, `test_invalid_rule_signature_rolls_back_package`, `test_new_driver_health_failure_restores_previous_driver`, and `test_release_gate_rejects_test_signature`.
- [ ] **Step 2: Implement** staged version directories, health-checked activation, rollback metadata, and a release gate requiring Microsoft signing evidence, supported Windows VM results, and clean installer tests.
- [ ] **Step 3: Run** `powershell -ExecutionPolicy Bypass -File windows_protection/installer/tests/Invoke-UpdateRollbackVmTests.ps1 -VmName STAI-AV-Test`; expect all four assertions to pass.
- [ ] **Step 4: Report** production signing and altitude allocation as pending unless the organization has supplied both; do not label the test package production-ready.

## Full-stack acceptance

- [ ] Run the core pytest commands in `2026-10-12-stai-protection-core.md`.
- [ ] Build and run the minifilter VM suite in `2026-10-12-stai-minifilter.md`.
- [ ] Run agent/API tests and the dark dashboard unit/type checks in their plans.
- [ ] Install on a clean Windows 10/11 x64 VM; verify the inert signed marker fixture is denied before image mapping, a benign fixture launches, scan progress persists, quarantine/restore outcomes are verified, and the dashboard reports truthful health and counts.
- [ ] Verify a production release is blocked until Microsoft driver-signing evidence and end-to-end validation records are present.
