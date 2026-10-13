# Mobile Phase 2 Local Tools Implementation Plan

> **For agentic workers:** Implement the independent tasks below with the TDD workflow. Do not change files outside the task's file list without coordinating with the root agent.

**Goal:** Add bounded, user-initiated local artifact inspection, URL structure checks, and visible-app permission posture analysis to the independent Android mobile app.

**Architecture:** Android SAF supplies only a user-selected URI to a bounded native inspector; it never executes selected content or requests broad storage access. URL checks and permission posture analysis run locally in Dart and produce review signals rather than malware verdicts. The root agent integrates the independent services with existing tools, navigation, and mobile-only registries.

**Tech Stack:** Flutter/Dart, Kotlin, Android Storage Access Framework, Android PackageManager, Flutter MethodChannel, Flutter tests.

**Spec:** User-provided revised mobile architecture and implementation specification at `C:\Users\user\.codex\attachments\e613bdfb-d344-4fd0-a0d8-00f56b1e703e\Pasted text.txt`, sections 8, 12, 14, 15, and 16.

## Global Constraints

- Keep all product code under `mobile/`; do not import or call desktop runtime components.
- Minimum Android SDK is 29; target and compile SDK are 36.
- User-selected files are inert input: do not execute, install, or upload them.
- Do not request broad storage or `QUERY_ALL_PACKAGES` permissions.
- URL checks are local-only and must not resolve, fetch, open, or redirect the submitted URL.
- Heuristic outputs are review signals, not claims that an app, file, or URL is malicious or safe.
- Local functionality must not depend on an AI key or network access.
- Do not add automatic device-changing actions; AI remains advisory and cannot execute actions.
- Bound input size, work duration, and item counts; report truncation or unsupported content explicitly.

## Review Focus

- A selected URI is cancelled, revoked, inaccessible, or points to an empty/oversized file; show a bounded error and leave prior results intact.
- A malformed or polyglot APK is parsed only as inert data; parser failures do not crash the app or claim a clean result.
- A selected archive/file contains hostile names or unusually large entries; do not extract paths or exceed configured resource limits.
- A URL contains credentials, Unicode/punycode, IP literals, a non-HTTP scheme, an unusual port, or excessive length; explain the observed signals without network access or a malicious verdict.
- Permission metadata is truncated or grant state is unavailable; preserve unknown state and never convert it to denied or safe.

---

### Task 1: Selected APK and File Inspection

**Files:**
- Create: `mobile/android/app/src/main/kotlin/com/svscyber/mobile/AndroidSelectedFileInspector.kt`
- Modify: `mobile/android/app/src/main/kotlin/com/svscyber/mobile/MainActivity.kt`
- Modify: `mobile/android/app/src/main/kotlin/com/svscyber/mobile/MobilePlatformChannels.kt`
- Create/modify: `mobile/lib/core/files/selected_file_inspection.dart`
- Modify: `mobile/lib/core/platform/mobile_platform_client.dart`
- Test: `mobile/test/platform/mobile_platform_client_test.dart`
- Test: `mobile/test/core/files/selected_file_inspection_test.dart`
- Native test coverage: document if unavailable; do not invent a successful Android runtime test.

**Interfaces:**
- Consumes: Existing versioned platform channel and Android `MainActivity` lifecycle.
- Produces: `selectAndInspectFile({required bool apk}) -> Future<SelectedFileInspection?>`; `null` means user cancellation. Response includes content type, byte size, SHA-256, bounded completion status, and APK metadata/signature summary when APK parsing succeeds. Unsupported or incomplete metadata remains unknown.

- [x] Write Dart contract tests for valid bounded results, cancellation, malformed payloads, unsupported APK metadata, and over-limit results.
- [ ] Verify the new tests fail because the method/model are not implemented. (Flutter/Dart unavailable; red run unverified.)
- [x] Implement Android document selection using `ACTION_OPEN_DOCUMENT` and a temporary read grant; request no storage permission and do not persist the URI grant.
- [x] Stream selected content through a bounded reader, compute SHA-256, and for APKs use public PackageManager parsing on a temporary cache copy; delete the temporary file in `finally` after processing returns.
- [x] Return a versioned, size-bounded result without raw file bytes, persist only a compact local observation if the existing event contract supports it, and map cancellation separately from errors.
- [ ] Run targeted Flutter tests and Android build/lint. Flutter, Dart, Gradle, and adb are absent; wrapper launchers are also absent.

### Task 2: Local URL Structure Check

**Files:**
- Create: `mobile/lib/core/links/mobile_url_local_check.dart`
- Test: `mobile/test/core/links/mobile_url_local_check_test.dart`

**Interfaces:**
- Produces: `MobileUrlLocalCheck.analyze(String raw) -> MobileUrlCheckResult`; result contains normalized safe-to-display fields and a list of specific structural signals. It performs no DNS, network, WebView, or browser calls.

- [x] Write tests for HTTP/HTTPS parsing, whitespace/length limits, credentials, non-web schemes, IP literals, non-default ports, Unicode/punycode hostnames, and malformed inputs.
- [ ] Verify the tests fail before implementation. (Flutter/Dart unavailable; red run unverified.)
- [x] Implement deterministic parsing and explanations with explicit limits and no binary good/bad verdict. The normalized field is origin-only to avoid retaining path/query/fragment data.
- [ ] Run targeted Flutter tests. Flutter/Dart are absent.

### Task 3: Visible-App Permission Posture Analysis

**Files:**
- Create: `mobile/lib/core/apps/application_permission_analyzer.dart`
- Test: `mobile/test/core/apps/application_permission_analyzer_test.dart`

**Interfaces:**
- Consumes: `VisibleApplication` and `VisibleApplicationCollection`.
- Produces: Local, deterministic per-app review signals for selected permission groups. Keep `permissionGrantStateAvailable`, package visibility, and truncation caveats explicit; null installer data is unknown, not evidence of sideloading.

- [x] Write tests for sensitive permission groups, empty declarations, unknown grant state, special app access, truncation, and non-verdict copy.
- [ ] Verify the tests fail before implementation. (Flutter/Dart unavailable; red run unverified.)
- [x] Implement a deterministic, explainable analyzer with rule IDs/versions and no malicious/safe label.
- [ ] Run targeted Flutter tests. Flutter/Dart are absent.

### Task 4: Root-Agent Integration

**Files:**
- Modify: `mobile/lib/core/tools/mobile_tool_registry.dart`
- Modify: `mobile/lib/core/workflows/investigator_workflow_registry.dart`
- Modify: `mobile/lib/features/tools/mobile_tools_page.dart`
- Modify: `mobile/test/features/tools/mobile_tools_page_test.dart`
- Modify: `mobile/README.md`
- Modify: `mobile/android/README.md`

**Interfaces:**
- Consumes: Tasks 1–3 service interfaces.
- Produces: Explicit user-triggered mobile workflows with accurate local-only labels, cancellation/error/truncation states, and no automatic navigation to scanned content.

- [x] Integrate the separate tools without changing their platform boundaries: explicit SAF file/APK selection, in-memory visible-app permission review, and local URL structure analysis.
- [x] Add widget coverage for user-triggered selection, permission review, URL redaction/clearing, and small-screen scrolling; execution remains unavailable.
- [ ] Run Flutter analyze/tests and Android builds/lint. Toolchains and Gradle wrapper launchers are unavailable; report unrun checks accurately.
