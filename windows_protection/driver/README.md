# STAI Minifilter Driver

## Overview

This is a test-signed Windows Filter Manager Kernel Minifilter Driver for the STAI protection system. It intercepts file operations (IRP_MJ_CREATE for read/execute opens and IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION for image mappings) and communicates with a user-mode protection service for deterministic file verdicts.

## Architecture

- **Kernel Mode**: Minimal driver that intercepts operations and forwards file paths to user-mode service
- **User Mode**: Protection service evaluates files against signed rule packages and returns verdicts
- **Communication**: Filter Manager communication port (`\STAIProtectionPort`) with versioned protocol

## Security Model

- Only verified high-confidence `block` rules can deny access
- `observe` rules and `unknown` verdicts always allow
- Service process is excluded from recursive scanning by PID, not filename
- If service is unavailable/timed out, operations pass through (fail-open)

## Build Requirements

- Windows Driver Kit (WDK) 10.0.22621 or later
- Visual Studio 2022 with Windows Kernel Mode Driver template
- Test signing certificate for development

## Build Instructions

From an x64 Native Tools Command Prompt for VS 2022:

```cmd
msbuild windows_protection\driver\StaiProtection.vcxproj /p:Configuration=Debug /p:Platform=x64
```

Output: `x64\Debug\StaiProtection.sys` and `x64\Debug\StaiProtection.inf`

## Installation (VM Only)

```cmd
# Enable test signing
bcdedit /set testsigning on
# Reboot required

# Install driver
pnputil.exe /add-driver StaiProtection.inf /install

# Start service
fltmc load StaiProtection
```

## Debug Attachment Value

The driver uses altitude `370000` for VM debug attachment only. Production requires a unique Microsoft-allocated altitude.

## Protocol Version

Current protocol version: 1 (see `..\protocol\protection_protocol.h`)

## Limitations

- Test-signed only: not suitable for production distribution
- VM-only: requires isolated Windows 10/11 x64 VM with test signing enabled
- No Microsoft driver signing or validation completed