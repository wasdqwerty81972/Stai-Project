# SVS-Cyber Mobile

This is an independent Android-first Flutter application. Its source, runtime state, tools, capabilities, key manager, and Android integrations live under this directory. It does not import or call the desktop product.

## Current implementation slice

- Phone-first Flutter shell with Home, Findings, Investigate, Tools, Capabilities, and Settings destinations.
- First-launch privacy setup explains the local-only default and is saved in Android app-private preferences; it requests no permissions and starts no collectors.
- Capability and tool metadata are maintained in separate registries.
- Android-native platform APIs are accessed through versioned channels.
- Phase 1 starts with local device-baseline checks and a durable app-private event journal.
- Eight capability entries have partial one-shot baseline support, and five entries have partial visible-launcher app metadata/permission snapshot support. Local secure-lock posture and versioned permission-combination rules can create evidence-linked review findings. These rules describe observed posture or declared permissions; neither produces a malware or safety verdict. Other catalogue entries remain planned.
- Visible app inventory requires an explicit in-app review and covers only launcher packages returned through Android's declared package-visibility query; it does not use `QUERY_ALL_PACKAGES`.
- The Tools destination provides explicit local permission-posture review for the current visible-app snapshot, a URL structure check, bounded file hashing, and bounded static APK metadata inspection. The Findings destination shows local rules; Investigate lets users select findings and locally verify their source references and deterministic same-subject nearby events. Missing or changed evidence is shown as a gap, and correlations are labeled as hypotheses. The URL tool displays only its origin; it makes no network request or safety verdict. The file picker grants access only to the selected document; a cloud-backed document provider may download that content. SVS-Cyber does not upload it, and APKs are never installed or executed.
- VPN consent scaffold: Settings includes an internal prototype page that reads build availability and Android system consent state, and can request consent only after an explicit tap when the build reports consent as available. It never prompts at launch. Consent does not start a service: there is no Tor engine, DNS relay, tunnel, traffic inspection, monitoring, forwarding, or blocking. The play build and unavailable states stay disabled. The selected routing design sends supported TCP through a loopback Tor SOCKS bridge, resolves supported DNS through Tor, and blocks unsupported UDP/QUIC without a direct fallback while active. This data plane is not implemented yet. Routing remains gated pending engine integration and API 29/API 36 connectivity, DNS leakage, revocation, and battery testing. The feasibility review is documented in `docs/superpowers/research/2026-10-13-android-vpn-phase3-feasibility.md`, and the Tor design/implementation sequence in `docs/superpowers/plans/2026-10-13-mobile-phase3-tor-routing.md`.
- Enterprise controls, broad package inspection, and external AI submission remain gated features; none is represented as active by this shell.

## Platform truthfulness

Capability metadata does not mean a collector is running. Runtime status must come from a real collector result, explicit permission state, and evidence freshness. Empty findings and unavailable integrations are shown as empty/unavailable states, never as fabricated detections or active protection.

Finding review actions and their review history currently live in memory for the active app session. Restoring the event journal reconstructs detections from stored events but does not restore prior acknowledge, resolve, or suppress actions.

External AI is optional. Evidence may only be sent after a user chooses it and reviews the provider and submission. AI output is advisory and cannot invoke device-changing operations.

## Build prerequisites

The mobile build uses Flutter 3.47.7, JDK 17, Android SDK Platform 36, and Android Build Tools 35.0.0 or newer. Gradle and Android Gradle Plugin versions are pinned in `android/gradle/wrapper/gradle-wrapper.properties` and `android/settings.gradle`. Install those prerequisites, then configure the machine-specific `android/local.properties` with `flutter.sdk` and `sdk.dir` paths. Do not commit that file.

From this directory, run `flutter pub get` followed by `flutter build apk --debug --flavor internal`. The expected installable debug APK is `build/app/outputs/flutter-apk/app-internal-debug.apk`. The `internal` flavor uses application ID `com.svscyber.mobile.internal`; this is a debug build for direct device testing, not a release-signed distribution build.

The VPN screen is currently a consent and status scaffold. VPN consent does not start a tunnel; Tor, DNS handling, traffic routing/inspection, and data-plane protection are not implemented. The app does not route or protect network traffic at this stage.
