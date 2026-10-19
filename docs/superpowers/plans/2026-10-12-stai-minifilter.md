# STAI Windows Minifilter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a test-signed Windows Filter Manager Kernel Minifilter Driver that asks the local service for deterministic file verdicts and denies only verified high-confidence matches.

**Architecture:** The Kernel Minifilter Driver runs in the Windows kernel and intercepts the specified file operations; keep its code small and move detection policy to the user-mode protection service. Use a versioned, bounded Filter Manager communication protocol and a dedicated service client. The driver and service are exercised only in an isolated Windows VM; local unit tests cover protocol validation without loading kernel code.

**Tech Stack:** Windows Driver Kit, C, Windows Filter Manager, Python `ctypes`/FltLib client, Windows 10/11 x64 VM tests, pytest.

**Spec:** `docs/superpowers/specs/2026-10-12-stai-custom-windows-protection-design.md`

## Global Constraints

- Initial target is Windows 10/11 x64.
- The driver remains small; it does not run an AI model or complex file analysis in kernel mode.
- Only a verified hash match or a signed rule explicitly marked `block` with high confidence can deny access.
- If the service is unavailable, unresolved operations pass through and the UI reports degraded protection.
- Driver development and testing occur in an isolated Windows VM with test signing.
- Production x64 distribution is not release-ready until Microsoft driver signing and validation are complete.
- A production filter needs a unique Microsoft-allocated altitude; use only a VM debug attachment value during development.

## Review Focus

- Malformed or oversized IPC data: reject safely without kernel memory overrun; test in Task 1.
- Service unavailable or timed out: pass through and report degraded; test in Tasks 1 and 3.
- Observe or low-confidence verdict: allow the operation; test in Tasks 2 and 3.
- Driver recursively scans its own service reads: skip the trusted service process without skipping other callers; test in Task 2.
- Filter unload during outstanding requests: drain or cancel safely; test in VM Task 3.

---

### Task 1: Versioned Filter Manager protocol

**Files:**
- Create: `windows_protection/protocol/protection_protocol.h`
- Create: `cyber_os/protection/filter_protocol.py`
- Create: `cyber_os/protection/filter_client.py`
- Test: `tests/test_windows_protection_filter_protocol.py`

**Interfaces:**
- Protocol V1 request: `size`, `version`, `request_id`, `operation`, bounded UTF-16 path length and path.
- Protocol V1 reply: `size`, `version`, `request_id`, verdict (`allow`, `block`, `unknown`), `rule_id`, and `rule_version`.
- Protocol V1 completion: `request_id` and final I/O status, sent by the callback path that applies `STATUS_ACCESS_DENIED` before returning `FLT_PREOP_COMPLETE`; the service records blocked only from that completion.
- `decode_filter_request(payload: bytes) -> FilterRequest` rejects wrong version, mismatched length, invalid operation, and payloads over 64 KiB.
- `FilterClient.connect() -> bool`, `FilterClient.receive() -> FilterRequest`, `FilterClient.reply(request_id: int, verdict: ScanVerdict) -> None`, `FilterClient.close() -> None`.

- [ ] **Step 1: Write failing tests** named `test_protocol_round_trip_preserves_request_id`, `test_protocol_rejects_wrong_version_and_length`, `test_protocol_rejects_payload_over_64_kib`, `test_unknown_verdict_serializes_as_allow`, and `test_completion_frame_carries_final_io_status`. Assert malformed frames raise `ProtocolError`, `unknown` maps to `allow`, and a completion preserves the request ID and exact final I/O status.
- [ ] **Step 2: Run** `python -m pytest -q tests/test_windows_protection_filter_protocol.py`; expect missing protocol imports.
- [ ] **Step 3: Implement** explicit little-endian field encoding/decoding and a FltLib wrapper using the Windows Filter Manager communication-port API. Keep the native wrapper injectable so Linux and Windows unit runs do not attempt driver connections. Forward the callback completion frame to `ProtectionStore.record_filter_completion`; do not increment `blocked` on a verdict reply alone.
- [ ] **Step 4: Run** the same pytest command; expect all five protocol tests to pass.

### Task 2: Minifilter enforcement callbacks

**Files:**
- Create: `windows_protection/driver/StaiProtection.vcxproj`
- Create: `windows_protection/driver/StaiProtection.inf`
- Create: `windows_protection/driver/src/driver.c`
- Create: `windows_protection/driver/src/callbacks.c`
- Create: `windows_protection/driver/src/protection_port.c`
- Create: `windows_protection/driver/README.md`

**Interfaces:**
- Register pre-operation callbacks for `IRP_MJ_CREATE` read/execute opens and `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` image mappings.
- Create a Filter Manager communication port at `\STAIProtectionPort`, ACL-restricted to the installed protection service identity.
- Deny only when the matching request ID returns a verified `block` verdict; treat `allow`, `unknown`, timeout, and disconnected service as pass-through.
- Exclude the registered service process from recursive scanning; never exclude by filename alone.

- [ ] **Step 1: Add VM test fixture** `windows_protection/tests/vm/benign-marker.exe` built from a harmless fixture program whose SHA-256 is present in a test-only signed block package; no malware is executed.
- [ ] **Step 2: Implement** the minimal WDK driver callbacks and unload-safe communication lifecycle. Do not add detection policy or AI behavior to the driver.
- [ ] **Step 3: Build** from an x64 Native Tools/WDK prompt with `msbuild windows_protection/driver/StaiProtection.vcxproj /p:Configuration=Debug /p:Platform=x64`; expect a test-signed `.sys` and `.inf` package configured for a VM-only debug attachment value.
- [ ] **Step 4: Review** the callback paths for bounded waits, correct pre-operation completion status, service recursion, and cleanup of outstanding requests before proceeding to VM tests.

### Task 3: Isolated VM integration tests

**Files:**
- Create: `windows_protection/tests/vm/Invoke-ProtectionMinifilterTests.ps1`
- Create: `windows_protection/tests/vm/README.md`

- [ ] **Step 1: Write VM assertions** for `test_signed_block_rule_prevents_image_mapping`, `test_benign_fixture_starts`, `test_observe_rule_allows_image_mapping`, `test_service_timeout_passes_through_and_marks_degraded`, `test_service_process_does_not_recurse`, and `test_unload_with_pending_request_completes_cleanly`.
- [ ] **Step 2: Implement** a VM runner that installs only the test-signed package in a named disposable Windows 10/11 x64 VM, captures service/driver event logs, and uninstalls the filter in `finally`.
- [ ] **Step 3: Run** `powershell -ExecutionPolicy Bypass -File windows_protection/tests/vm/Invoke-ProtectionMinifilterTests.ps1 -VmName STAI-AV-Test`; expect all six assertions to pass and the VM to return to its clean snapshot.
- [ ] **Step 4: Record** the WDK version, Windows build, test-signing state, debug attachment value, and test log path in the VM test report. Mark production signing and altitude allocation as pending until both are actually obtained.

## Handoff

The agent plan consumes durable `DetectionRecord` values from the core and service events from this filter path; it cannot alter filter verdicts.
