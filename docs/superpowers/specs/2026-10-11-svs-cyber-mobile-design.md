# SVS-Cyber Mobile Design

**Status:** Approved design direction; pending written-spec review
**Date:** 2026-10-11

## Goal

Create a mobile edition of SVS-Cyber as a self-contained Android product. It will have a phone-first interface, mobile-specific security capabilities, tools, key management, storage, and local detection. It will not depend on or integrate with the desktop SVS-Cyber application.

The supplied Android proposal defines 136 logical monitoring capabilities: 128 intended for personal phones and 8 that require Android Enterprise management. These are a product catalogue, not a promise that every capability can be collected on every phone or a requirement to run 136 services.

## Product and project boundary

- Place the application in a top-level `mobile/` folder in this repository.
- Make it an independently buildable Flutter application with its own dependencies, configuration, assets, tests, and release process.
- Keep mobile source, runtime state, provider credentials, tools, capability definitions, and findings independent of desktop modules. Do not import desktop Python code or call desktop-only routes.
- Preserve SVS-Cyber's product identity while designing mobile navigation, screen density, setup, and permission flows for phones.
- Target Android for the first release. An iOS edition is a later project and will need separate native integrations and a platform-specific capability review.

## Architecture

### Flutter application

The Dart application owns mobile navigation and screens, domain models, the capability registry, mobile tool registry, local detection and orchestration, provider adapters, and application state. Features should communicate through small interfaces so a platform collector can be replaced or unavailable without breaking the rest of the app.

The principal user areas are:

- **Security home:** device posture, current protection state, recent findings, and collection health.
- **Capabilities:** catalogue grouped by category, with support, permission, and implementation states explained in plain language.
- **Findings:** locally stored detections and their evidence, source, and time.
- **Tools:** mobile-specific scans and checks with clear input, output, and permission needs.
- **Privacy and settings:** permission setup, provider configuration, data retention, and local data controls.

### Android platform layer

Use Kotlin platform integrations behind Flutter platform channels for Android APIs that require native services or lifecycle handling. Keep Android-specific work behind collector interfaces; Dart features must not assume a collector can always run.

Native integrations may include package metadata, usage access, notification access, selected-file access, and `VpnService`, but only where the user has enabled the corresponding feature and the OS and distribution rules permit it. VPN collection must be an explicit opt-in foreground feature. Enterprise logging is outside the personal-phone release and requires valid managed-device provisioning.

### Capability registry

Represent each `AND-001` through `AND-136` capability as metadata and a link to its collector, detector, or derived calculation. A capability record should identify its category, purpose, source API, access class, permission prerequisites, supported Android conditions, collection mode, expected battery impact, data sensitivity, and known limitations.

Track two distinct state dimensions:

1. **Implementation:** planned, partial, or implemented.
2. **Runtime availability:** available, consent required, permission denied or revoked, enterprise provisioning required, unsupported on this device, or temporarily unavailable.

The UI must distinguish “not implemented” from “implemented but unavailable here.” Derived capabilities may use evidence from multiple collectors. Registry entries do not create independent background services.

### Mobile tools

Maintain a mobile-only tool registry separate from the capability registry. Tools perform bounded actions such as examining an accessible APK, checking a user-submitted URL, or summarizing local findings. A tool declares its inputs, outputs, required capabilities or permissions, network behavior, and whether it can change device state. Initial tools are read-only. Any future protective action must be explicit, policy-controlled, and reviewable by the user.

## Data flow and privacy

1. A user enables a capability from an explanation screen.
2. The Flutter registry checks platform support and permission state, then requests access only when needed.
3. A Kotlin collector reads an allowed Android signal and sends a normalized, timestamped event to the Dart event interface.
4. Local rules and mobile tools analyze the event. Findings retain provenance and capability identifiers.
5. Findings are stored locally in encrypted application storage and displayed in the mobile UI.
6. When online AI analysis is configured, the user chooses the evidence to submit. The app sends only that selected evidence directly to the configured provider; it does not upload telemetry or findings automatically.

The mobile `key_manager` is independent from the desktop key manager. It should keep user-configured provider credentials in Android-backed secure storage, never in source code or bundled configuration. Provider calls must go through this manager, expose provider failures clearly, and leave local detections operational when keys, quota, or network access are unavailable.

No mobile cloud backend is required for the initial release. If a server-side mobile service is added later, it must have its own API, identity and enrollment model, retention rules, and consent flow; it must not reuse desktop state or credentials implicitly.

## Permission and platform constraints

- Explain the reason and effect before opening Android's permission or special-access flow.
- Request only access needed for a capability the user enables.
- Handle denial, revocation, unsupported APIs, background limits, and collector failure as normal states.
- Do not claim access to another application's private files, memory, or unrestricted processes.
- Treat VPN flow attribution and visibility into encrypted traffic as limited and device-dependent.
- Broad package visibility and network-monitoring distribution requirements must be checked for the selected release channel before those capabilities are advertised as supported.
- Use minimum necessary evidence, especially for notification content and AI submissions.

## Delivery phases

### Phase 1: Foundation and device baseline

Create the independent Flutter app, mobile design system and navigation, first-run explanations, capability registry and status UI, local encrypted event/findings storage, and health reporting. Implement a small read-only Android device and OS baseline after confirming API and distribution feasibility. Do not enable VPN monitoring by default.

### Phase 2: Consumer security checks

Add feasible app inventory and application-risk checks, permission posture, user-selected APK and file inspection, and link checks. Add local findings and user-controlled provider analysis using the mobile key manager.

### Phase 3: Network protection

Implement consent-driven VPN and DNS or connection metadata capabilities with explicit foreground-service behavior, battery and connectivity messaging, and clear limits on attribution and encrypted content. This phase must account for VPN exclusivity and device-specific behavior.

### Phase 4: Managed-device capabilities

Treat `AND-129` through `AND-136` as a separate enterprise track. Require Android Enterprise provisioning and test coverage for the applicable device-owner or profile-owner mode before marking any such capability available.

## Success criteria

- The app builds and runs independently from the desktop application.
- The phone UI communicates coverage and permission state without implying full device visibility.
- Each capability has an honest implementation and runtime state, including unsupported and revoked-access cases.
- Local collection and baseline detections continue without network access or AI-provider quota.
- Provider credentials and local findings are not included in automatic telemetry uploads.
- Each collector can fail or be unavailable without preventing unrelated mobile capabilities from working.

## Decisions before implementation

The implementation plan must select a supported Android API range and distribution route, since both affect package visibility and background behavior. It must also define the first concrete tool set and the AI providers supported by the mobile `key_manager`. These are release configuration decisions; they do not change the isolation boundary or the architecture above.
