# STAI Minifilter Driver

## Overview

This is the Windows Filter Manager minifilter source for the STAI protection system. A built or signed `.sys`/`.cat` package is not included in the repository. The driver is intended for isolated development VMs until Microsoft signing, a unique altitude, and end-to-end validation are complete. It intercepts file operations (IRP_MJ_CREATE for read/execute opens and IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION for image mappings) and communicates with the user-mode protection service for deterministic file verdicts.

## Architecture

- **Kernel Mode**: Minimal driver that intercepts operations and forwards file paths to user-mode service
- **User Mode**: Protection service evaluates files against signed rule packages and returns verdicts
- **Communication**: Filter Manager communication port (`\STAIProtectionPort`) with versioned protocol. The user-mode API connects using this same fully qualified port name.

## Security Model

- Only verified high-confidence `block` rules can deny access
- `observe` rules and `unknown` verdicts always allow
- Service process is excluded from recursive scanning by PID, not filename
- If service is unavailable/timed out, operations pass through (fail-open)
- The driver caps synchronous requests at 32 in flight; excess requests pass through.
- Request/reply waits are bounded to five seconds. Completion telemetry is sent without waiting.
- The driver accepts policy decisions from the trusted local service. The service must verify signed rules before it can produce a blocking verdict.
- The development port ACL permits SYSTEM and administrators. The packaged service runs as LocalSystem; the installer restricts its named pipe to SYSTEM, administrators, and the captured dashboard user's SID.

## Build Requirements

- Windows Driver Kit (WDK) 10.0.22621 or later
- Visual Studio 2022 with Windows Kernel Mode Driver template
- Test signing certificate for development
- Minimum target OS is Windows 10, version 2004: the driver calls
  `ExAllocatePool2`, which replaced the deprecated `ExAllocatePoolWithTag`. To
  support anything earlier, switch to the `ExAllocatePoolZero` wrapper, define
  `POOL_ZERO_DOWN_LEVEL_SUPPORT`, and call `ExInitializeDriverRuntime` from
  `DriverEntry`.

## Build Instructions

From an x64 Native Tools Command Prompt for VS 2022:

```cmd
msbuild windows_protection\driver\StaiProtection.vcxproj /p:Configuration=Debug /p:Platform=x64
```

Output: `x64\Debug\StaiProtection.sys` and the staged INF/catalog package.

## Installation (isolated VM only)

```cmd
# Enable test signing
bcdedit /set testsigning on
# Reboot required

# The INF is an architecture-decorated DefaultInstall package, which is the
# documented layout for a non-PnP file system filter. Install it as a primitive
# driver package with pnputil (NOT the legacy
# "rundll32 setupapi.dll,InstallHinfSection DefaultInstall 132" path, which
# Microsoft recommends replacing and which always exits 0 even on failure):
pnputil /add-driver StaiProtection.inf /install

# In an isolated test-signing VM, use the STAI MSI so it also installs the
# service, signed rules, dashboard SID ACL, health check, and rollback action.
# Then load the filter explicitly:
fltmc load StaiProtectionFilter

# To remove the staged package again (oem#.inf is the published name reported
# by "pnputil /enum-drivers"):
pnputil /delete-driver oem#.inf /uninstall
```

## Minifilter Instance

The INF declares the `StaiProtection Instance` default instance at altitude `329999`, consistent with the driver package. This unallocated VM-development value may conflict with another filter and is not a production altitude. Production requires a unique Microsoft allocation and a signed driver package.

## Protocol Version

Current protocol version: 1 (see `..\protocol\protection_protocol.h`)

## Limitations

- Source only: no WDK-built `.sys` or `.cat` package is included
- VM-only: requires isolated Windows 10/11 x64 VM with test signing enabled
- The Windows service host, local pipe, and packaging sources are implemented. The MSI has not been built or exercised because this environment has no WDK-built driver package or isolated VM.
- No end-to-end signed-rule block test has run; a matching signed rule package and runnable VM test host are still required.
- A minifilter provides file-operation coverage only. It does not establish parity with Bitdefender or another full antivirus suite.
- No Microsoft driver signing, altitude allocation, or independent lab validation is completed.
