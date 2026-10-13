# Mobile Phase 3: Tor-backed Android VPN

**Goal:** Route explicitly opted-in Android device traffic through Tor without creating a direct-network fallback or claiming coverage the app has not verified.

**Chosen design:** An internal-build `VpnService` owns the TUN interface. A maintained tun2socks bridge sends TCP streams to a loopback-only Tor SOCKS listener. The Tor process's upstream sockets must be protected from the TUN to prevent a routing loop. DNS is handled by a local stub which sends supported A/AAAA/PTR lookups through Tor; it must never fall back to the Android resolver. Unsupported UDP (including QUIC/HTTP/3), ICMP, and other non-TCP traffic are blocked and clearly reported. This is privacy routing, not HTTPS inspection or autonomous threat defense.

## Implementation sequence

1. **Dependency and native engine foundation**
   - Select and pin Tor Android, tun2socks, and DNS components from maintained upstreams.
   - Record source URLs, exact versions, licenses, native ABIs, transitive dependencies, and redistribution notices before packaging.
   - Keep dependencies and the VPN service declaration in the `internal` flavor only until the Play declaration and disclosure review is complete.
   - Add a native state model for Tor bootstrap, bridge readiness, VPN consent, tunnel state, and failure reason. Never infer protection from consent alone.

2. **Tor runtime and bridge integration**
   - Bind Tor only to loopback and wait for a verified SOCKS-ready/bootstrap state.
   - Protect Tor's upstream sockets from the VPN interface.
   - Connect the TUN descriptor to tun2socks only after the bridge and Tor are ready.
   - Implement bounded DNS handling with Tor remote resolution and no default-resolver fallback.
   - Do not add routes or start the VPN while any forwarding component is unavailable.

3. **Lifecycle and UI**
   - Start only after the user taps an explicit Start control and grants Android VPN consent.
   - Implement foreground notification/lifecycle, stop, revoke, process death, network changes, and another-VPN conflict handling.
   - Keep the UI honest about Tor bootstrap, TCP-only coverage, unsupported UDP/QUIC, DNS limits, and inactive/degraded states.
   - Never report `protected` until Tor, TUN, IPv4/IPv6, DNS handling, and no-direct-fallback checks have been verified on target devices.

## Hard gates

- Do not establish a default route before Tor, tun2socks, and DNS handling are all integrated and operational; otherwise connectivity can be blackholed.
- Do not silently bypass the tunnel for unsupported traffic. Unsupported protocols fail closed while the VPN is active.
- Before enabling routes, perform device validation across minimum API 29 and target API 36: TCP/Tor exit, DNS leak checks, IPv4/IPv6, UDP/QUIC blocking, Tor and bridge failure, consent revocation, stop/restart, Wi-Fi/cellular changes, VPN conflicts, Android Private DNS modes, and battery/background behavior.
- Public distribution additionally needs current Google Play `VpnService` declaration/disclosure review and complete third-party notices.

## Progress

- Implemented: internal-only Android VPN consent/status scaffold and Flutter Settings page. It does not start a service, create a TUN, or route/inspect/block traffic.
- Architecture selected after user direction: Tor-backed, TCP-only routing with DNS through Tor and unsupported UDP blocked; no fallback.
- Not yet implemented: Tor runtime, native packet bridge, DNS stub, active VPN lifecycle, or any traffic routing.
- Environment limitation: Flutter, Dart, Android SDK, Gradle, and Kotlin compiler are not available in this workspace; no build or device behavior has been verified.

## Research sources

- Tor SOCKS extensions: https://spec.torproject.org/socks-extensions
- Tor Android integration: https://github.com/guardianproject/tor-android
- Orbot Android reference implementation: https://github.com/guardianproject/orbot-android
- Android `VpnService`: https://developer.android.com/reference/android/net/VpnService
- Android `VpnService.Builder`: https://developer.android.com/reference/android/net/VpnService.Builder
- Google Play `VpnService` policy: https://support.google.com/googleplay/android-developer/answer/12564964
