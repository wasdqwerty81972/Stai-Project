# STAI Minifilter VM Integration Gate

This directory contains a harmless executable fixture and a preflight gate. It does **not** yet contain a runnable end-to-end minifilter test suite. The Windows service host and installer source now exist, but no WDK-built driver package, signed test rules, or VM test host is available. The preflight does not install anything or claim enforcement results.

## Current status

`Invoke-ProtectionMinifilterTests.ps1` checks for a built driver package, service package, signed test-rule package, test host, and benign fixture. It always exits with status `2` and reports **BLOCKED** until all artifacts and a real VM harness are supplied. It performs no VM actions and does not report passes.

## Existing fixture

Build the inert executable from an x64 Native Tools Command Prompt for Visual Studio:

```cmd
cd windows_protection\tests\vm
build-benign-marker.bat
```

The output is `benign-marker.exe` in this directory. Do not use it to claim a block test; a verified signed test rule package and a service that loads it are also required.

## Driver build and release gates

The driver requires the Windows Driver Kit and an isolated Windows 10/11 x64 VM with test signing enabled. Neither a WDK build nor a driver load has been verified in this development environment. The INF uses the unallocated development altitude `329999`; a production release needs a Microsoft-allocated altitude and a properly signed driver package.

Before implementing the real VM suite, provide:

- A built and test-signed driver package (`.sys`, `.inf`, and `.cat`).
- A Windows protection service executable built with the public key for the supplied signed rules package.
- A signed test rule package containing a harmless fixture hash with an explicit high-confidence `block` rule, plus any observe rule used in tests.
- A VM test host that installs/uninstalls the package, launches and monitors the service, runs each assertion, and verifies driver completion evidence for denied operations.

The intended acceptance tests—signed block, benign allow, observe allow, service unavailable fail-open, service-process recursion prevention, and unload during outstanding I/O—remain unexecuted until those components exist.
