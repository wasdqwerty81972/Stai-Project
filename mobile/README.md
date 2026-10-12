# SVS-Cyber Mobile

This is an independent Android-first Flutter application. Its source, runtime state, tools, capabilities, key manager, and Android integrations live under this directory. It does not import or call the desktop product.

## Current implementation slice

- Phone-first Flutter shell with Home, Findings, Investigate, Tools, Capabilities, and Settings destinations.
- First-launch privacy setup explains the local-only default and is saved in Android app-private preferences; it requests no permissions and starts no collectors.
- Capability and tool metadata are maintained in separate registries.
- Android-native platform APIs are accessed through versioned channels.
- Phase 1 starts with local device-baseline checks and a durable app-private event journal.
- Eight capability entries have partial one-shot baseline support; one local secure-lock posture rule can create an evidence-linked finding. Other catalogue entries remain planned.
- VPN, enterprise controls, broad package inspection, and external AI submission are gated features; none is represented as active by this shell.

## Platform truthfulness

Capability metadata does not mean a collector is running. Runtime status must come from a real collector result, explicit permission state, and evidence freshness. Empty findings and unavailable integrations are shown as empty/unavailable states, never as fabricated detections or active protection.

External AI is optional. Evidence may only be sent after a user chooses it and reviews the provider and submission. AI output is advisory and cannot invoke device-changing operations.

## Build prerequisites

Install Flutter 3.35 or newer, Android SDK Platform 36, and JDK 17 or newer. The repository environment currently has no Flutter/Android SDK toolchain on PATH and has JDK 8, so a local Android build cannot be verified until that toolchain is installed.
