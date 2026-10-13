# Mobile Phase 2 Findings and Investigation Plan

> **For agentic workers:** Implement the isolated tasks below. Keep product edits inside `/mobile` except for this plan and its progress ledger. Do not change the desktop product.

**Goal:** Extend the Android-first mobile MVP from local posture checks to explainable application-permission findings and a user-driven local investigation view.

**Architecture:** Add a deterministic permission-combination detector that consumes the explicit visible-app snapshot and emits evidence-linked review findings without a malicious/safe verdict. Add a local investigation service that assembles selected findings and their source events with provenance; the UI remains offline and the future AI request flow stays separate and opt-in.

**Tech Stack:** Flutter/Dart, existing `Finding` and `MobileEvent` models, existing `MobileSecuritySession`.

**Spec:** `C:\Users\user\.codex\attachments\e613bdfb-d344-4fd0-a0d8-00f56b1e703e\Pasted text.txt`, sections 7–9 and Phase 2 in section 14.

## Global Constraints

- All application source changes remain under `mobile/`.
- Findings must retain source event IDs, capability IDs, rule IDs, rule versions, observed times, explanations, limitations, and user-recommended next steps.
- Permission declarations are observations, not evidence of use, maliciousness, or safety.
- Missing, filtered, stale, and truncated data remain explicit unknowns/caveats.
- Local detections and investigations work offline and without AI credentials.
- AI output remains advisory and has no device-action executor.
- No VPN, background polling, package-visibility expansion, or device-changing action is introduced in this phase.

## Review Focus

- A permission combination is common for legitimate apps; emit a low-confidence review prompt with clear limitations, not a malware verdict.
- Package visibility or permission metadata is truncated; preserve the scope caveat and avoid interpreting omitted data as absent.
- A finding references an unavailable or expired event; show the evidence gap rather than fabricate a value.
- Findings from unrelated packages or event subjects are not correlated.
- Selecting no findings produces an honest empty investigation state and no provider request.

---

### Task 1: Application Permission Combination Detection

**Files:**
- Create: `mobile/lib/core/apps/application_permission_detection.dart`
- Test: `mobile/test/core/apps/application_permission_detection_test.dart`

**Interfaces:**
- Consumes: `VisibleApplicationCollection` and the package inventory event from that same snapshot.
- Produces: deterministic review candidates with rule IDs/versions and evidence references into the exact `AND-012` package snapshot; the snapshot also carries summary events `AND-025`/`AND-026`.
- Rule candidate must be explicitly framed as a review signal, preserve visible-scope/truncation caveats, and use a restrained severity/confidence.

### Task 2: Local Finding Investigator

**Files:**
- Create: `mobile/lib/core/detection/local_finding_investigator.dart`
- Test: `mobile/test/detection/local_finding_investigator_test.dart`

**Interfaces:**
- Consumes: selected `Finding` IDs plus the current local `MobileEvent` collection.
- Produces: a provenance-first investigation bundle with exact evidence values where available, missing-reference notes, related-event links only when a deterministic relationship exists, and clearly labeled hypotheses.
- Makes no network, provider, or Android calls.

### Task 3: Root Integration

**Files:**
- Modify: `mobile/lib/core/platform/mobile_security_session.dart`
- Modify: `mobile/lib/app/shell.dart`
- Modify: `mobile/lib/core/workflows/investigator_workflow_registry.dart`
- Modify: `mobile/test/app/mobile_shell_test.dart` and/or focused session/widget tests
- Modify: `mobile/README.md`

**Interfaces:**
- Recompute application permission findings only from an explicitly collected snapshot.
- Show investigation selection, evidence provenance, and empty/missing states.
- Keep the external AI action disabled/unimplemented until its exact provider, secure-key-use, evidence-preview, network-consent, cancellation, and redaction contract is designed and implemented.

---

### Parallel Research: Phase 3 VPN Feasibility (Read Only)

**Output:** A short feasibility note under `docs/superpowers/research/` covering Android `VpnService`, user consent, foreground-service rules, Android 10–17 compatibility assumptions, IPv4/IPv6 forwarding, failure behavior, and distribution-policy questions. Use official Android documentation and distinguish verified platform facts from design recommendations. Do not modify product code or declare VPN support implemented.

## Execution Notes

- The user authorized continuing the approved mobile roadmap and parallel sub-agent work.
- Existing Flutter/Dart/Gradle/adb tools are absent in this workspace. Agents may author focused tests, but must report them as unrun; no build or device verification can be claimed.
- Complete Phase 2 implementation in source before starting VPN product code; Phase 3 may be researched concurrently.

## Progress — 2026-10-13

- Implemented the deterministic application permission-combination detector and local finding-investigation service with focused tests authored. Tests remain unrun because Flutter/Dart are unavailable.
- Integrated permission detections into the local session, added acknowledge/resolve/suppress/reopen review actions, and replaced the Investigate placeholder with user-selected, local evidence-reference review and correlation hypotheses. Review actions remain in-memory and are not restored across launches.
- Added a read-only Phase 3 VPN feasibility note at `docs/superpowers/research/2026-10-13-android-vpn-phase3-feasibility.md`. No VPN product code was started.
- Source review and `git diff --check` are the available verification. Phase 2 remains unverified until a Flutter build/test run is possible; external AI preview/consent and provider invocation remain unimplemented and gated.
