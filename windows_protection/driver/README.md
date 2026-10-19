# STAI Minifilter Driver

## Overview

This is the Windows Filter Manager minifilter source for the STAI protection system. A local WDK Release build is present under `x64\Release`; its `.sys` and catalog are unsigned development artifacts. The driver remains restricted to isolated development VMs until Microsoft signing, a unique altitude, and end-to-end validation are complete. It registers create, write, and image-mapping callbacks and sends normalized paths plus originating process/thread IDs to the user-mode protection service.

## Architecture

- **Kernel Mode**: FltMgr callbacks for create, write, and image-mapping operations
- **User Mode**: Protection service evaluates files against signed rule packages and returns verdicts
- **Communication**: Version 2 Filter Manager port protocol (`\STAIProtectionPort`) with request ID, operation, path, PID, and TID. A bounded deferred-I/O work queue keeps user-mode waits out of filesystem callback threads.

## Security Model

- Only verified high-confidence `block` rules can deny access
- `observe` rules and `unknown` verdicts always allow
- Service process is excluded from recursive scanning by PID, not filename
- If service is unavailable/timed out, operations pass through (fail-open)
- The driver caps queued and active requests at 32; overflow and unsafe-to-defer operations pass through.
- Worker replies are bounded to one second. Timeouts, disconnects, malformed replies, and queue saturation fail open. Completion telemetry is best effort.
- The driver accepts policy decisions from the trusted local service. The service must verify signed rules before it can produce a blocking verdict.
- The communication port ACL grants connect access only to LocalSystem. The packaged protection service runs as LocalSystem.

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

Output: `x64\Debug\StaiProtection.sys` and the staged INF/catalog package. The project compiles `src\filter.c`, `src\callbacks.c`, and `src\communication.c` using the Microsoft WDK MSBuild toolset.

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

Current protocol version: 2 (see `..\protocol\protection_protocol.h`). The driver and service must be updated together because version 2 adds process/thread metadata and the write operation.

## Limitations

- The pre-write verdict currently scans the path before the write occurs; it does not transmit the write buffer. It cannot detect malicious bytes newly introduced by that write, so this callback is not complete write-content enforcement.
- The locally built `.sys` and catalog are unsigned; Windows will not load them under normal driver-signing policy.
- VM-only: requires isolated Windows 10/11 x64 VM with test signing enabled
- The Windows service host, local pipe, and packaging sources are implemented. The MSI has not been built or exercised because this environment has no isolated VM or signed driver package.
- No end-to-end signed-rule block test has run; a matching signed rule package and runnable VM test host are still required.
- A minifilter provides file-operation coverage only. It does not establish parity with Bitdefender or another full antivirus suite.
- No Microsoft driver signing, altitude allocation, or independent lab validation is completed.
