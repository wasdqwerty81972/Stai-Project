# Android VPN Phase 3 Feasibility

**Date:** 2026-10-13  
**Scope:** Read-only feasibility review for the mobile design's Phase 3: opt-in VPN and DNS/connection metadata monitoring. This note does not implement or claim a VPN.

## Summary

Phase 3 is technically feasible with Android `VpnService`, but it is a substantial native networking component rather than a sensor toggle. Android provides a consent flow and a virtual network interface; the application must own packet processing, tunnel lifecycle, DNS behavior, reconnection, and failure reporting. The system permits only one active VPN per Android user/profile, so a competing VPN replaces or prevents this product's VPN. A local VPN can inspect some IP/port and DNS metadata, but it cannot generally see payloads protected by TLS, QUIC, DoT, or DoH.

The approved mobile design's explicit opt-in and visible foreground operation fit the platform model. A Google Play release needs a separate policy review: Play names device security as a permitted `VpnService` use case, but it also calls for a VPN declaration, in-app disclosure and affirmative consent, store-listing documentation, and encryption from device to VPN tunnel endpoint. Whether a local-only filtering/monitoring VPN with no remote endpoint satisfies that last requirement is an open release-policy question, not a platform guarantee.

## Verified Android behavior

### Consent and exclusivity

- A service extends `VpnService` and declares the `android.net.VpnService` service action protected by `android.permission.BIND_VPN_SERVICE`.
- The app calls `VpnService.prepare()` before connecting. Android returns a system consent intent if the app is not the currently prepared VPN; the user must approve it. Call `prepare()` on each connect attempt because another VPN may have become current since the previous check.
- Only one VPN service can be active for an Android user/profile. Replacing it interrupts the prior service. VPN state is scoped to the user/profile, not globally to every profile on the device.
- Android calls `onRevoke()` when the VPN permission is revoked or the user disconnects/forgets it in Settings; the call may not be on the main thread. The service must close the TUN descriptor and its tunnel sockets safely and update UI state.
- A VPN app can protect its upstream tunnel socket with `VpnService.protect()` to keep its own transport out of the VPN interface and avoid a routing loop.

Sources: [Android VPN guide](https://developer.android.com/develop/connectivity/vpn), [`VpnService` API](https://developer.android.com/reference/android/net/VpnService).

### Foreground service and target SDK 36

- Android's VPN guide says VPN apps on Android 8.0/API 26 or newer need to transition the service to the foreground because of background execution limits. A user-visible persistent notification is therefore part of the active-monitoring experience.
- Apps targeting Android 14/API 34 or newer must declare an appropriate foreground-service type and its associated permission. Android documents `systemExempted` as available to VPN apps configured through Settings > Network & Internet > VPN, but eligibility depends on actually meeting the listed conditions. Do not select `specialUse` or `systemExempted` by guesswork; verify the precise manifest/type path against the implemented service and release channel.
- Android 16/API 36 adds foreground-service-related behavior changes, including job runtime quotas that also apply to jobs started from a foreground service. The current Android 16 change documentation does not describe a new VPN-specific exemption from foreground-service rules.
- Starting the VPN from an explicit user action, promptly entering foreground state, keeping the notification accurate, and handling start failures visibly are the conservative design assumptions. Boot/always-on starts and background restarts need separate review against current foreground-service start restrictions.

Sources: [VPN guide](https://developer.android.com/develop/connectivity/vpn), [foreground-service types](https://developer.android.com/develop/background-work/services/fgs/service-types), [foreground-service changes](https://developer.android.com/develop/background-work/services/fgs/changes).

### IPv4, IPv6, routes, and DNS

- `VpnService.Builder` creates a TUN interface. The app must assign at least one interface address before `establish()` succeeds, then read outgoing packets from its file descriptor and process/forward them. Android does not implement the user's packet engine or remote tunnel protocol.
- Both IPv4 and IPv6 interface addresses and routes are supported. A route or DNS server for one address family implicitly enables that family. If no address, route, or DNS server for a family is configured, Android blocks outgoing traffic for that family by default; `allowFamily()` can explicitly allow it to fall through to the underlying network.
- `addDnsServer()` configures DNS servers for the VPN network. If none is specified, the default network's DNS servers are used. A DNS server also implicitly enables its address family. DNS queries sent to configured resolvers can be observed by an implementation that actually parses them; the API itself does not provide a DNS event feed.
- Route coverage must be intentional. Incomplete IPv6 routes can create a leak or a connectivity failure depending on configuration. A “VPN active” state alone does not prove all app traffic is captured or forwarded.
- Android supports always-on VPN from API 24 for apps targeting API 24+, and user Settings can optionally enable lockdown so apps cannot bypass the VPN. The system owns always-on service lifecycle/restart; the app remains responsible for successfully reconnecting its tunnel. A disconnect in lockdown can leave the device without network connectivity.

Sources: [`VpnService.Builder`](https://developer.android.com/reference/android/net/VpnService.Builder), [VPN guide](https://developer.android.com/develop/connectivity/vpn), [`VpnService` API](https://developer.android.com/reference/android/net/VpnService).

### Attribution and encrypted traffic limits

- The VPN interface receives IP packets, not a guaranteed mapping from every packet to an app identity. `VpnService.Builder` can route only selected installed apps through the VPN using `addAllowedApplication()` or exclude selected apps using `addDisallowedApplication()`; these are routing controls, not a universal per-flow attribution API. Visibility into package names may also depend on package visibility and Android version.
- IP addresses, ports, protocol, packet sizes/timing, and unencrypted DNS can be available to a local packet processor, subject to the routes and protocol support it implements. TLS/QUIC-encrypted application data is not readable as HTTP content merely because it passes through a VPN. Apps can use their own DoH/DoT resolver, so domain names may be unavailable even when ordinary DNS would be routed to the VPN resolver. Android's system Private DNS also affects resolver behavior; test it rather than claiming universal DNS visibility.
- Never describe this phase as seeing all visited domains, URLs, message contents, app processes, or decrypted traffic. Do not add TLS interception/certificate installation as an assumed feature; it is outside the approved design and would need separate security, UX, and distribution review.

Sources: [`VpnService.Builder`](https://developer.android.com/reference/android/net/VpnService.Builder), [VPN guide](https://developer.android.com/develop/connectivity/vpn), [Android DNS security guidance](https://developer.android.com/privacy-and-security/risks/bad-dns), [Android 9 DNS privacy behavior](https://developer.android.com/about/versions/pie/android-9.0-changes-28).

### Compatibility facts

- `VpnService` and `VpnService.Builder` date to API 14; per-app allow/disallow routing is API 21; always-on is API 24; `protect()` is API 14. The mobile architecture still needs to select its own min SDK and verify supported OS/device coverage.
- For the existing mobile project's proposed Android 10/API 29 minimum and API 36 target, the VPN primitives exist throughout the stated OS range. That does not guarantee identical OEM lifecycle, network handover, DNS, or battery behavior. Android 14+ foreground-service type requirements and API 36 behavior need explicit target-SDK validation.

Sources: [`VpnService` API](https://developer.android.com/reference/android/net/VpnService), [foreground-service types](https://developer.android.com/develop/background-work/services/fgs/service-types), [Android 16 behavior changes](https://developer.android.com/about/versions/16/behavior-changes-all).

## Recommendations (not platform guarantees)

1. Implement the VPN as a dedicated Kotlin service behind a narrow Flutter control/status interface. Keep packet parsing and forwarding out of UI code; isolate lifecycle state, route configuration, and event summaries.
2. Start only from an explicit connect action after a separate in-app disclosure, then invoke `prepare()` and show the Android consent screen. Explain that connecting replaces another active VPN and that Settings can stop or replace this service.
3. Begin with an explicitly scoped profile: selected address families, documented routes, and only the metadata needed for the advertised local protections. Do not silently enable always-on or lockdown. If later offered, label lockdown as a user-controlled OS setting with a clear no-network-on-tunnel-failure consequence.
4. Use a foreground notification that names the active protection mode and provides a direct stop action. On every error, revocation, network change, missing IPv4/IPv6 path, or tunnel failure, report “protection interrupted” rather than implying coverage.
5. Maintain explicit states such as `disconnected`, `consent_required`, `connecting`, `connected_limited`, `interrupted`, and `revoked`. Capability availability should depend on actual route/DNS configuration and collector health, not just service existence.
6. Keep detection local by default; aggregate limited flow metadata, avoid payload retention, put strict bounds on logs, and make any provider submission a separate per-evidence user action.
7. Do not claim autonomous blocking until there is a narrowly specified policy engine, false-positive controls, route-level drop tests, and a user-visible rule/action audit. Phase 3 feasibility does not authorize destructive or arbitrary AI-driven device actions.

## Suggested test matrix

Test on emulators and physical devices from more than one manufacturer, including Android 10/API 29, 12/API 31, 13/API 33, 14/API 34, 15/API 35, and 16/API 36. For each, cover:

- First connection consent accepted, declined, and re-requested after another VPN is selected; disconnect from app and from Settings; permission revoked/revocation callback.
- Existing third-party VPN and per-user/profile scope; always-on and lockdown left off for baseline, then separately enabled through Settings for qualification tests.
- Wi-Fi, cellular, Wi-Fi-to-cellular handoff, airplane mode, captive portal, loss/recovery of underlying network, app/process kill, reboot, low memory, battery saver, and user force-stop.
- IPv4-only, IPv6-only, and dual-stack networks; verify route coverage, DNS, and no unintended family fallback/leak. Include unreachable upstream, DNS server failure, MTU/fragmentation, and tunnel reconnect behavior.
- Android Private DNS strict/automatic/off; app-provided DoH/DoT; TCP/TLS, UDP/QUIC, and ordinary DNS; verify UI and findings never infer unavailable domains or content.
- Notification visibility/stop action; FGS start and manifest checks on API 34+; target API 36 job/worker behavior; sustained battery and throughput measurement.
- Network protection should fail closed only when the user deliberately enables OS lockdown; otherwise display interruption and accurately reflect the system's actual routing state. Validate that no device-wide connectivity state is left misleading after a crash or revoke.

## Google Play release questions

The current Google Play help article identifies device security (including antivirus/firewall) as an allowed VpnService use category when VPN is not the app's core function. It also says VpnService use must be documented in the Play listing, all data from device to VPN tunnel endpoint must be encrypted, and apps accessing/collecting sensitive data through the service need an in-app prominent standalone disclosure with affirmative consent. The declaration process previews functionality/data questions and asks for short videos showing VPN usage and disclosure/consent.

Before implementation is advertised or submitted, decide and document:

- Is this release distributed on Google Play, privately, or both? Each route has its own review obligations.
- Is the product being submitted as device security, and does its user-facing core behavior clearly fit that category?
- Does a local-only VPN with no remote tunnel endpoint satisfy Play's encryption requirement, or must the design use an encrypted remote endpoint? Obtain a policy answer before locking architecture; the help text alone does not settle this specific local-only case.
- Exactly which data is inspected, retained, shared, or submitted to AI; how do store listing, in-app disclosure, Data safety answers, privacy policy, and Play Console VPN declaration align?
- Which foreground-service type and manifest permissions does the chosen VPN service require on Android 14+ and for target 36? Confirm with current Android and Play review guidance for the exact service design.
- Is always-on/lockdown included in the release? If yes, provide separate disclosure and test/support plan for loss of connectivity during tunnel outage.

Sources: [Google Play VpnService policy overview and declaration questions](https://support.google.com/googleplay/android-developer/answer/12564964), [Android foreground-service types](https://developer.android.com/develop/background-work/services/fgs/service-types).

## Open release decisions

The architecture document already leaves minimum Android version and distribution route for later selection. Phase 3 additionally needs a concrete answer on local-only vs encrypted remote forwarding, supported traffic families/routes, whether lockdown is excluded, service type, metadata retention, and what “network protection” guarantees during outages. Until those are decided and validated on devices, Phase 3 should remain planned/experimental in the capability registry.
