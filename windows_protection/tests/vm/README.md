# VM Integration Tests for STAI Minifilter

## Overview

This directory contains the isolated Windows VM integration tests for the STAI Minifilter Driver. Tests are run in a disposable Windows 10/11 x64 VM with test signing enabled.

## Prerequisites

1. **Hyper-V VM** named `STAI-AV-Test` with:
   - Windows 10/11 x64 (build 19041+)
   - Test signing enabled: `bcdedit /set testsigning on` (reboot required)
   - Visual Studio 2022 Build Tools or Community with C++ workload
   - PowerShell Remoting enabled: `Enable-PSRemoting -Force`
   - CredSSP authentication configured for remote commands

2. **Host Machine**:
   - Elevated PowerShell
   - Hyper-V module available
   - Built driver package (`StaiProtection.sys`, `StaiProtection.inf`)

## Test Package Preparation

Build the driver first:

```cmd
msbuild windows_protection\driver\StaiProtection.vcxproj /p:Configuration=Debug /p:Platform=x64
```

Build the benign test fixture:

```cmd
cd windows_protection\tests\vm
build-benign-marker.bat
```

## Running Tests

From an elevated PowerShell on the host:

```powershell
powershell -ExecutionPolicy Bypass -File windows_protection\tests\vm\Invoke-ProtectionMinifilterTests.ps1 -VmName STAI-AV-Test
```

## Test Assertions

| Test | Description |
|------|-------------|
| `test_signed_block_rule_prevents_image_mapping` | Verified block rule with high confidence denies image mapping |
| `test_benign_fixture_starts` | Benign executable not in block list launches successfully |
| `test_observe_rule_allows_image_mapping` | Observe rule matches but allows execution |
| `test_service_timeout_passes_through_and_marks_degraded` | Service unavailable = fail-open, UI reports degraded |
| `test_service_process_does_not_recurse` | Service PID excluded from scanning, not filename |
| `test_unload_with_pending_request_completes_cleanly` | Filter unload drains/cancels outstanding requests safely |

## Expected Results

All six assertions must pass. The VM should return to its clean snapshot after tests complete.

## Reporting

Record in test report:
- WDK version used for build
- Windows build number in VM
- Test signing state
- Debug attachment value (altitude 370000)
- Test log path
- Production signing and altitude allocation: **PENDING**

## Cleanup

Tests automatically unload filter and uninstall driver. Use `-SkipCleanup` to preserve state for debugging.

## Troubleshooting

- **VM not found**: Verify VM name matches exactly
- **Access denied**: Run PowerShell as Administrator
- **CredSSP errors**: Run `Enable-WSManCredSSP -Role Client -DelegateComputer "*"` on host
- **Driver load fails**: Verify test signing is enabled in VM (`bcdedit`)
- **Port connection fails**: Verify service is running and port ACL allows service SID