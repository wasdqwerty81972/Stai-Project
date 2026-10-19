# Mobile Phase 3 VPN Consent Scaffold

**Goal:** Start the isolated Android VPN prototype with a truthful, internal-only consent and status flow, while leaving network routing disabled until a tested packet-forwarding engine exists.

**Scope decision:** The approved mobile architecture specifies an independently signed internal-testing APK first. This milestone uses a local-only design assumption for the internal prototype; it does not configure a tunnel, inspect packets, forward traffic, block threats, or start a foreground service. The `play` flavor receives no VPN service declaration until the Google Play local-only policy question is resolved.

## Contract

Extend the Android platform channel v1 additively with `getVpnStatus` and `requestVpnConsent`.

Both methods return a map with:

- `contractVersion: 1`
- `enabledForBuild: bool`
- `consentGranted: bool`
- `tunnelActive: false`
- `monitoringActive: false`
- `state: unavailable | consent_required | consent_granted`
- optional `reasonCode: user_denied | consent_unavailable`

The internal build may present Android's system VPN consent after an explicit user action. The play build always reports `unavailable`. Granting consent never starts the service or claims monitoring is active. `VpnService.prepare()` is checked on every status/request operation.

## Tasks

### 1. Dart bridge

- Add `MobileVpnConsentClient` and immutable `MobileVpnConsentStatus` in `mobile/lib/core/platform/mobile_vpn_consent_client.dart`.
- Add method-channel mapping and contract tests only if the user requests verification in a later turn.

### 2. Android consent bridge

- Add an internal-flavor-only manifest declaration for a non-exported `VpnService` with `BIND_VPN_SERVICE`, required action, and always-on disabled.
- Add a consent-only service that immediately stops if started; no code path starts it in this milestone.
- Add Activity-owned `VpnService.prepare()` consent handling to `MainActivity`; preserve SAF callback behavior and handle denial/activity teardown.
- Extend `MobilePlatformChannels` with the two additive status/consent methods. Return unavailable for the play flavor and never start a service.
- Keep packet data, hostnames, and event logging out of this milestone.

### 3. Flutter prototype page and documentation

- Add a dedicated network-protection prototype page reachable from Settings.
- Display build availability, system consent state, and a persistent notice that no tunnel, traffic monitoring, or blocking is active.
- Let the user request Android consent only in the internal build. Never auto-prompt on app launch.
- Update mobile and Android README status and list the next gate: packet-forwarding design plus API 29/API 36 connectivity, revocation, and battery testing.

## Verification

- Tests and build commands are out of scope for this request. This workspace currently lacks Flutter, Dart, Android SDK, Gradle launchers, and a Kotlin compiler; do not claim those checks passed.
- Static review must verify that the service is declared only in the internal flavor, that consent is rechecked each time, and that no service start, TUN establishment, default route, or foreground-service type is added.

## Follow-on gate

Do not enable Phase 3 traffic monitoring until the local packet-forwarding architecture is selected and tested. Do not advertise support in the Play flavor until its VpnService declaration, encrypted-tunnel policy interpretation, foreground-service type, user disclosures, and distribution requirements are confirmed.

## Execution progress — 2026-10-13

- Ruling: implement the consent/status scaffold in the internal flavor only; do not create or establish a TUN or foreground service in this milestone. This advances Phase 3 without risking user connectivity or representing consent as monitoring. If the user intended end-to-end traffic forwarding immediately, this milestone costs a follow-up data-plane implementation step.
- Native bridge, Flutter client/page, Settings entry, and mobile README updates are implemented. An integration review found and corrected an inconsistent busy-Activity status response; review confirmed the VPN declaration and availability flag remain internal-flavor only, with no TUN, route, traffic handling, foreground-service start, or internet permission in this scaffold.
- Builds and device behavior remain unverified because the Flutter/Dart/Android toolchain is unavailable. No tests were added or run.
