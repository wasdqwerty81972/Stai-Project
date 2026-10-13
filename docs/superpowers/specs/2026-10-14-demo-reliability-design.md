# SVS Cyber Real Protection Demo Design

## Goal

Make the real protection features that can run in this checkout reliable and usable for tomorrow's presentation. Launch must open a dashboard that can actually call the local protection API and perform scans. The UI must accurately distinguish the user-mode scanner and its rule trust from the Windows service and kernel driver. Do not simulate a threat event or imply protection that is unavailable.

## Current constraints and evidence

- `cyber_main.py` defaults to Tauri on Windows. There is no Cargo command or release executable here. A recent debug executable exists, but the launch flow ignores it.
- The local dashboard is a Vite app. In browser context, its current protection client uses Tauri `invoke`, so it cannot call the API from browser mode.
- `/health` only reports API liveness. It does not initialize the scanner or establish that rules are available.
- The API looks for a manifest, signature, and public key under `.protection`. Those files are absent here, so it creates an empty ruleset and reports degraded protection. The repository has a signed EICAR hash demo package and a pinned public key under `cyber_os/protection/resources`.
- The scanner runs SHA-256 rules and optional YARA. Inspection found YARA runtime/compile/match failure can return `unknown/allow` before a matching SHA-256 block rule is evaluated.
- The Windows protection service is not installed on this host, and no driver package is available for installation. Source-level or user-mode tests cannot establish kernel enforcement.

## Approaches considered

1. Require a signed native release, installed service, and loaded minifilter before opening the app. This gives the intended deployment path but cannot be assembled and validated on this host by tomorrow.
2. Open the existing native debug app and leave its Tauri-only IPC unchanged. This gives a desktop window, but with no installed service its protection actions cannot reach a working scanner.
3. Recommended: connect browser mode to the real local API, load the repository's signed rules through a pinned trust root when no installed rules are present, fix scanner verdict precedence, and show user-mode/service/driver states separately. Keep native launch when it is operational; use the browser UI as a functional fallback.

## Design

### Dashboard access to protection

The protection client selects Tauri IPC in the native app and HTTP requests to the loopback API in browser mode. Both adapters implement the same typed client contract for status, scans, threats, quarantine, and restore. HTTP calls stay on loopback and use the API's existing validation and response models. Browser startup uses the installed local Vite package directly, avoiding dependence on a global pnpm shim.

### Launcher and readiness

`cyber_main.py` starts the API and selects a dashboard path that can reach protection operations. Use the native Tauri app only when its local protection service pipe is reachable; otherwise start the browser dashboard through the local Vite dependencies and its HTTP adapter to the local scanner API. The launcher announces the selected mode and names missing prerequisites if no mode can start. API liveness and protection readiness remain distinct; a degraded scanner does not prevent the dashboard from opening, and API liveness is never reported as AV readiness.

### Trusted rules and accurate status

When no installed rule package exists, load the repository's signed rule manifest and verify it against the pinned `trusted-rules.pub`. Do not treat an editable public key beside an editable manifest as a trust root. Missing or invalid rules stay degraded and include a useful reason.

Protection status reports scanner availability and rules version/trust separately from the installed Windows service and minifilter driver. Local user-mode scanning must not be represented as service or kernel protection. The dashboard exposes the current limitation without showing a green protected state when the service or driver is missing.

### Scanner verdict handling

Evaluate trusted SHA-256 matches independently of optional YARA execution. If YARA is unavailable, invalid, or times out but a trusted hash block rule matches, preserve the block verdict and record the YARA limitation. If no deterministic rule matches and YARA cannot run, report `unknown` rather than `clean`. Keep current timeouts and quarantine policy; do not broaden signature semantics in this change.

### Safe validation

Use tests with a harmless inert marker and an explicit test ruleset to exercise the real scanner, quarantine, persistence, API responses, and browser client refresh. Do not put this test-only signature in the trusted production rules or add a synthetic detection button to the user-facing app. The signed bundled EICAR rule remains the only production demo signature until a separately signed rule update is available. Never install or execute malware for the demonstration.

## Failure handling

The UI and launcher distinguish API unavailable, scanner unavailable, rules absent/invalid, Windows service unavailable, and driver unavailable. Scan failures remain visible and do not become a clean result. Existing quarantine and scan history are not cleared at startup. A test result demonstrates the tested user-mode path only; it does not establish live service or kernel enforcement.

## Verification and acceptance criteria

- Launcher tests prove the selected mode for a usable native app, complete Tauri dev prerequisites, browser fallback, and no runnable UI; `/health` alone cannot mark protection ready.
- API tests prove pinned signed-rule fallback, rejection of invalid/untrusted packages, and separate scanner/service/driver status.
- Scanner tests first reproduce the YARA-failure plus matching SHA-256 case, then prove the block verdict remains; unmatched files with unavailable YARA remain unknown.
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
