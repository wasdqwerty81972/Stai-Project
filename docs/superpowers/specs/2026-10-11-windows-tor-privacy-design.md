# Windows Tor Privacy Mode Design

**Status:** Draft for review
**Date:** 2026-10-11

## Goal

Give STAI users an explicit, whole-Windows-device privacy mode that routes supported internet traffic through the Tor network and blocks direct internet egress while enabled. The AI can explain and report the mode; it cannot silently enable or disable system networking changes.

This feature reduces disclosure of the device's public IP to destination services and reduces destination visibility to the local network. It does not promise anonymity: account logins, application behavior, browser fingerprinting, malware, and global traffic correlation can still identify or link activity.

## User intent and defaults

- Target: Windows 10/11 host networking, not only STAI's own requests.
- Activation: user-initiated each time; no automatic activation at boot in the first release.
- Failure behavior: fail closed while enabled. Loss of Tor or the tunnel leaves non-Tor internet egress blocked until recovery or an explicit user disable action.
- Privacy layering: use Tor's normal circuit selection and relay path. Tor already uses multiple relays; do not add arbitrary Tor chaining or a VPN by default.
- Agent actions: status is read-only. Enabling and disabling require an explicit user action, administrator privileges, and the existing approval/audit path.

## Architecture

```text
Windows applications
        |
        v
Windows TUN interface + strict route / persistent kill switch
        |
        v
Pinned, signature-verified user-space traffic adapter (sing-box candidate)
        |  TCP and DNS only; unsupported protocols fail closed
        v
Tor SOCKS listener on loopback (Tor Expert Bundle client)
        |
        v
Tor-selected guard -> middle -> exit -> destination
```

### Components

1. **`skills/tor-privacy/SKILL.md`** — explains enable/status/disable workflows, the exact coverage claim, recovery, and limits. Skills guide the agent; they do not enforce routing.
2. **`cyber_os/privacy/tor_manager.py`** — owns dependency validation, process identity, startup sequencing, state reporting, watchdog behavior, and recovery. It must operate only on its own tagged resources.
3. **Windows traffic adapter** — use a maintained TUN data plane (sing-box is the current candidate) with a Tor SOCKS outbound and strict routing. Pin the release and verify provenance, license, and configuration behavior before packaging. Do not write a custom kernel driver for the first release.
4. **Tor client** — use the Tor Project's Windows Expert Bundle as a client only, with a loopback-only SOCKS endpoint. Do not configure an exit relay or let user applications connect directly to Tor's SOCKS endpoint as a substitute for host routing.
5. **Independent kill switch** — install a uniquely identified Windows Filtering Platform policy before changing routes. While active, only loopback, required link-management traffic, and the Tor process's connections to the Tor network are exempt. The policy must persist through adapter or manager failure and be removed only by a verified disable/recovery flow.
6. **STAI tools** — `tor_privacy_status` is `READ_ONLY`; `tor_privacy_enable` and `tor_privacy_disable` are `MODIFIES_SYSTEM`, admin-gated, approved, and audited. The AI must not describe a requested state as active until live state checks confirm it.

### Traffic and DNS policy

- All host IPv4 and IPv6 internet routes go through the TUN path while enabled; there is no ordinary direct route fallback.
- DNS requests are intercepted and resolved through Tor. Direct DNS on physical interfaces is blocked. The adapter configuration must be proven not to use a direct DNS resolver before the UI can report **Protected**.
- Tor carries TCP streams, not arbitrary IP packets. UDP, QUIC, ICMP, inbound unsolicited connections, and unsupported traffic are blocked while the mode is active. Local device discovery and LAN services are unavailable by default; required link management such as DHCP is narrowly exempted.
- WSL, virtual machines, containers, mobile hotspots, and other virtual interfaces require separate coverage verification. The first release reports them as unsupported until tests prove they cannot bypass the route.

## State model and user experience
**Where users control it:** Add a persistent **Network Privacy** status control in the SVS workspace header, using the existing shield area. Clicking it opens a dedicated Network & Privacy panel with the verified state, coverage, limitations, and explicit **Enable Tor protection** / **Disable Tor protection** actions. This is separate from the existing Communications settings. Add matching status and enable/disable/recovery actions to the STAI Windows system-tray menu so users can turn protection off or recover even when the main window is closed. Both entry points call the same service and approval flow. A chat request may open the panel or request an action, but cannot silently toggle networking.

- **Off** — no STAI-owned routes or filters are active.
- **Preparing** — administrator check, binary signature/version checks, and Tor bootstrap run before traffic is released.
- **Protected** — Tor is bootstrapped; adapter routing and DNS checks pass; persistent kill-switch rules are present.
- **Degraded / blocked** — Tor, adapter, DNS, or policy checks fail. Direct egress remains blocked and the UI states that internet access may be unavailable.
- **Recovery required** — owned filter/route state is inconsistent. Offer a local elevated recovery workflow that can remove only STAI-owned policy after restoring normal routing.

Enabling order is fail-closed: establish the kill switch first, start and verify Tor, start the TUN adapter, verify route and DNS behavior, then show **Protected**. Disabling is explicit: keep the kill switch until the adapter is stopped and the original route state is verified, then remove only STAI-owned filters. Never reset all firewall policy or overwrite unrelated VPN/proxy configuration.

## Privacy model and limitations

- Standard Tor circuits provide multiple relays; STAI will not promise that extra hops or VPN chaining improve anonymity.
- Tor Browser's anti-fingerprinting and identity protections do not apply to ordinary Windows applications merely because their packets use Tor. For high-anonymity browsing, recommend Tor Browser; for an operating system designed to route all traffic through Tor, point users to Tails.
- Signing into a personal account still identifies the user to that service. Tor does not protect against malware already running on the device.
- The local network can observe a connection to Tor, although not the destination through normal Tor operation. Bridges are a future, separately reviewed feature for users who need to conceal Tor use.
- Unsupported traffic fails instead of falling back directly. This can break updates, calls, games, local devices, and other services while enabled.

## Failure handling and recovery

- Missing, modified, expired, or untrusted binaries: refuse activation and keep network policy unchanged unless the kill switch has already been engaged; if engaged, remain blocked and offer recovery.
- Tor bootstrap failure or listener collision: show a clear error; never connect an application directly as fallback.
- Adapter or manager crash: persistent kill-switch policy remains active; report **Degraded / blocked** and provide a local recovery action.
- Partial enable/disable: compare current state with a recorded, minimal snapshot and reconcile only STAI-owned routes, adapter, and WFP filters. Do not terminate processes not created/owned by this service.
- Reboot during protection: first release does not auto-enable. Persist only enough recovery metadata to remove/reconcile stale STAI-owned policy safely.
- Recovery is local and does not require internet. It requires administrator confirmation and explains that restoring connectivity disables protection.

## Verification plan

Before implementation can claim full-device protection, a Windows proof of concept must demonstrate:

1. Normal TCP requests from multiple unrelated applications exit through Tor.
2. DNS queries do not reach a configured public resolver directly.
3. IPv4, IPv6, DoH, UDP, QUIC, and Tor-bootstrap failures cannot create direct application egress; unsupported paths fail closed.
4. Killing the adapter, Tor process, or manager leaves non-Tor egress blocked.
5. Reboot, network change, UAC denial, concurrent VPN, and partial cleanup have a recoverable state.
6. Disable restores connectivity without deleting or changing unrelated firewall, route, proxy, or VPN settings.
7. WSL and virtual interfaces are either covered by the same test evidence or visibly labeled unsupported.

Project tests should cover manager state transitions, dependency verification, tool risk/approval contracts, policy ownership, crash recovery, and no-direct-fallback behavior. Do not report a green unit suite as proof of packet-level privacy; network-level leak tests are required.

## Scope and rollout

- Initial platform: Windows 10/11 only.
- Initial delivery: design and feasibility validation, then a narrowly scoped Windows implementation behind an explicit experimental privacy-mode control until packet-level tests pass.
- Excludes: macOS/Linux, downstream devices, Tor relay operation, browser fingerprinting protections, application identity cleanup, custom bridges, VPN chaining, and automatic startup activation.
- Do not silently download or install privileged drivers. Any redistributable dependency must have provenance, signature, license, version pinning, and update/rollback review.

## Acceptance criteria

- Users can understand the exact coverage, limitations, and connectivity impact before enabling.
- The UI reports **Protected** only after Tor, DNS, routing, and kill-switch verification succeeds.
- There is no direct egress fallback while enabled, including on Tor or adapter failure.
- Disable and offline recovery touch only STAI-owned network state and restore the user's prior connectivity.
- The AI's skill and tools state what the system verified and never claim anonymity or full coverage without evidence.

## References

- Tor network and three-relay design: https://support.torproject.org/about-tor/tor-browser/
- Tor SOCKS support, remote name resolution, and lack of UDP ASSOCIATE: https://spec.torproject.org/socks-extensions.html
- Tor Expert Bundle for Windows: https://www.torproject.org/download/tor/
- Tor guidance on application safety and Tor Browser: https://support.torproject.org/about-tor/using-and-sharing/torifying/
- Tor recommendation for all-device traffic via Tails: https://support.torproject.org/tor-browser/features/managing-identities/
- sing-box TUN, DNS hijacking, strict routing, and Windows behavior: https://sing-box.sagernet.org/configuration/inbound/tun/
- Windows Filtering Platform: https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform

