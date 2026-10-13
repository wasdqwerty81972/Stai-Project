# SVS Cyber Real Protection Demo Design

## Goal

Make the real protection features that can run in this checkout reliable and usable for tomorrow's presentation. Launch must open a dashboard that can actually call the local protection API and perform scans. The UI must accurately distinguish the user-mode scanner and its rule trust from the Windows service and kernel driver. Do not simulate a threat event or imply protection that is unavailable.

## Current constraints and evidence

- `cyber_main.py` defaults to Tauri on Windows. There is no Cargo command or release executable here. A recent debug executable exists, but the launch flow ignores it.
- The local dashboard is a Vite app. In browser context, its current protection client uses Tauri `invoke`, so it cannot call the API from browser mode.
- `/health` only reports API liveness. It does not initialize the scanner or establish that rules are available.
- The API looks for a manifest, signature, and public key under `.protection`. Those files are absent here, so it creates an empty ruleset and reports degraded protection. The repository has a signed EICAR hash demo package and a pinned public key under `cyber_os/protection/resources`; that package detects only the EICAR test file and is not a production threat database.
- The scanner runs SHA-256 rules and optional YARA. Current code already preserves a matching high-confidence SHA-256 block when YARA fails, and `tests/test_windows_protection_scanner.py` contains a regression test for that case.
- The Windows protection service is not installed on this host, and no driver package is available for installation. Source-level or user-mode tests cannot establish kernel enforcement.

## Approaches considered

1. Require a signed native release, installed service, and loaded minifilter before opening the app. This gives the intended deployment path but cannot be assembled and validated on this host by tomorrow.
2. Open the existing native debug app and leave its Tauri-only IPC unchanged. This gives a desktop window, but with no installed service its protection actions cannot reach a working scanner.
3. Recommended: keep the Tauri Windows app as the preferred shell, let its protection client use the named pipe when available and fall back to the real local user-mode scanner API when the pipe is absent, and let browser mode use that same HTTP adapter. Load the repository's signed EICAR test rule through a pinned trust root when no installed rules are present, and show user-mode/service/driver states separately. Use browser mode only when no native app can run.

## Design

### Dashboard access to protection

The protection client selects Tauri IPC in the native app and HTTP requests to the loopback API in browser mode. If the native protection pipe is unavailable, the Tauri client falls back to that local API and exposes the local scanner's limited status; it must not label local API operation as Windows service or kernel protection. Both adapters implement the same typed client contract for status, scans, threats, triage, quarantine, and restore. HTTP calls stay on loopback, allow only the dashboard's exact local origins (including the Tauri origin), and use the API's existing validation and response models. Scheduled scans remain unavailable in local API mode unless the Windows service is reachable; the page must report that state clearly. Browser startup uses the installed local Vite package directly, avoiding dependence on a global pnpm shim.

### Launcher and readiness

`cyber_main.py` starts the API and prefers the native Tauri app when a release executable, a usable existing debug executable, or complete Tauri development prerequisites are available. When no native app can run, it starts the browser dashboard through the local Vite dependencies and HTTP adapter. The launcher announces the selected mode and names missing prerequisites if no mode can start. API liveness and protection readiness remain distinct; a degraded scanner does not prevent the dashboard from opening, and API liveness is never reported as AV readiness.

### Trusted rules and accurate status

When all installed rule-package files are absent, load the repository's signed EICAR test manifest and verify it against the pinned `trusted-rules.pub`. Mark its scope as test-only/limited; it is not a general malware database and cannot justify a green production-protected state. Do not treat an editable public key beside an editable manifest as a trust root. A partial or invalid installed package stays degraded and includes a useful reason rather than silently falling back.

Protection status reports local scanner availability, rules version/trust/scope separately from the installed Windows service and minifilter driver. Local user-mode scanning must not be represented as Windows service or kernel protection. The dashboard exposes the current limitation without showing a green protected state when the service or driver is missing.

### Scanner regression coverage

Keep the existing scanner contract: a matching high-confidence SHA-256 block remains a block if optional YARA fails, and a file without a deterministic match reports `unknown` when YARA cannot run. Run these regression tests with the API and end-to-end checks; do not rewrite this already-correct behavior.

### Safe validation

Use tests with a harmless inert marker and an explicit test ruleset to exercise the real user-mode scanner, quarantine, persistence, API responses, and browser client refresh. Do not put this test-only signature in the trusted bundled rules or add a synthetic detection button to the user-facing app. The signed bundled EICAR test rule remains limited to that standard test file; it is not a production threat database. Never install or execute malware for the demonstration.

## Failure handling

The UI and launcher distinguish API unavailable, scanner unavailable, rules absent/invalid, Windows service unavailable, and driver unavailable. Scan failures remain visible and do not become a clean result. Existing quarantine and scan history are not cleared at startup. A test result demonstrates the tested user-mode path only; it does not establish live service or kernel enforcement.

## Verification and acceptance criteria

- Launcher tests prove the selected mode for a usable native app, complete Tauri dev prerequisites, browser fallback, and no runnable UI; `/health` alone cannot mark protection ready.
- API tests prove pinned signed-rule fallback, rejection of partial/invalid installed packages, test-only rule scope, and separate scanner/service/driver status.
- Existing scanner regression tests pass for YARA failure with a matching SHA-256 block and for unmatched files when YARA is unavailable.
- Integration tests with a harmless inert marker verify detection, quarantine, persistence, and API/browser-visible refresh using the actual scanner and test-only rule.
- Frontend tests prove browser-mode HTTP and native-mode Tauri clients satisfy the same operations and report errors without mislabeling detections.
- On the target Windows machine, `python cyber_main.py` opens a usable dashboard. A scan and quarantine workflow completes through the actual local scanner. The status page accurately reports whether the Windows service and driver are installed/loaded.
- Report automated test evidence separately from live Windows service/driver evidence. Do not claim equivalence to Bitdefender or production readiness while signing, deployment, and kernel validation gates remain unmet.

## Out of scope

- Sigma ingestion, broad third-party threat-intelligence feeds, or expansion of the trusted production ruleset.
- Installing or executing real malware.
- Building, signing, or installing the minifilter driver, allocating a production altitude, or changing driver fail-open behavior.
- Adding a synthetic threat event or demo-only detection button to the product UI.
- Unrelated dashboard redesign or new network/process monitoring features.

## Follow-up requested

After this protection hardening, connect the dashboard's AI Agent sidebar action to the existing `StaiChatWorkspace` inside the SVS Cyber Tauri experience. Keep this as a separate design/implementation task because the existing chat workspace is part of the Next.js app while the protection dashboard is a Vite/Tauri app; this plan does not change the AI Agent navigation.
