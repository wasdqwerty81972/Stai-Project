# System-Wide Tor Privacy Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit, fail-closed Windows privacy mode that routes supported whole-host internet traffic through Tor and reports only coverage verified from live system state.

**Architecture:** Use a pinned Tor Expert Bundle and a maintained Windows TUN data plane (sing-box candidate) with a Tor SOCKS outbound. A separately elevated, narrowly scoped Windows helper owns persistent WFP kill-switch policy and exposes a local authenticated IPC contract; the Python agent, UI, and Tauri tray use the same lifecycle manager. No app-level proxy setting is treated as proof of whole-host coverage.

**Tech Stack:** Python 3.11+, pytest, Windows 10/11, Rust/Tauri 2, Windows Filtering Platform, Tor Expert Bundle, sing-box TUN, Wintun-compatible adapter, React/Next.js.

**Spec:** `docs/superpowers/specs/2026-10-11-windows-tor-privacy-design.md`

## Global Constraints

- Windows 10/11 only; WSL, VMs, containers, and other virtual interfaces remain unsupported until separately verified.
- Activation is manual; the first release does not auto-enable protection at boot.
- While active, failure is fail-closed: no direct internet fallback for application traffic.
- Route supported TCP and DNS through Tor; block UDP, QUIC, ICMP, unsolicited inbound, and unsupported traffic.
- Tor SOCKS is bound to loopback and used by the tunnel adapter, not exposed to arbitrary local clients.
- Only loopback, narrowly required link-management traffic, and the Tor process's relay connections may bypass the application tunnel.
- All routes, filters, processes, and state changed by STAI must be uniquely identifiable and owned; never reset unrelated firewall, route, proxy, or VPN configuration.
- Do not report **Protected** until Tor bootstrap, IPv4/IPv6 routing, DNS handling, and kill-switch presence are verified.
- Enabling/disabling requires a user action, administrator elevation, and the existing approval/audit path; chat cannot silently change routes.
- Do not package or install a dependency until its version, signature/provenance, license, and rollback path are reviewed.
- Do not claim anonymity; Tor's normal relay path is sufficient, and the feature does not add VPN/Tor chaining.

## Review Focus

- **Elevation denied or wrong OS:** enabling must refuse without changing existing routes or firewall policy; test platform and privilege gates.
- **Missing or tampered runtime binary:** activation must fail validation before changing policy; test version, hash/signature, and license-manifest failures.
- **Tor bootstrap failure, listener collision, or DNS failure:** keep egress blocked if protection has begun; test degraded state and no direct fallback.
- **Adapter/manager crash or reboot while active:** non-Tor egress must remain blocked and local recovery must work; test each process failure and stale owned policy.
- **Existing VPN, network change, or unsupported virtual interface:** do not overwrite third-party settings and do not claim unverified coverage; test conflict detection and unsupported-interface reporting.

## Execution Gate

- Product integration tasks 2–6 are blocked until Task 1 passes in a disposable, revertible Windows 10/11 VM and its evidence artifact is reviewed. Without that evidence, do not add a route-changing enable path or show a Protected state. Pure models, validation, and disabled/unavailable UI may be developed separately, but cannot be represented as device protection.
- The current development host is Windows 11 Home, the agent process is not elevated, and no Rust/Cargo compiler or disposable Windows VM tooling is installed. WSL is not an acceptable substitute for host-level WFP and packet-capture verification. Therefore, the implementation cannot currently pass the gate on this host.
- Before the gate can pass, the VM must capture traffic on every relevant egress interface and prove IPv4, IPv6, DNS (including TCP fallback), unsupported UDP/QUIC/ICMP blocking, Tor/TUN/broker crash behavior, reboot behavior, UAC denial, VPN/network-change handling, and restoration. Preserve the captures, initial/final route and DNS state, WFP policy inventory, and recovery result in the evidence artifact.
- Specify and test persistent WFP provider/sublayer/filter/session semantics, compartments and interfaces, and crash/reboot behavior. The Tor process bypass must be narrowly constrained and validated; an application-wide Tor executable exception is not sufficient evidence. Validate driver signature, provenance, supported Windows versions, install/update/rollback lifecycle, and licenses before packaging.
- The elevated broker must use protected pipe creation, reject remote clients, impersonate and validate caller identity for every request, use bounded framing/timeouts, and never accept caller-supplied paths, executables, interfaces, routes, or exemptions. UAC at broker launch alone is not consent for later state changes. Recovery snapshots and partial install/remove behavior must be durable and crash-safe.

---

## File Structure

- Create `cyber_os/privacy/__init__.py` — public privacy-mode types and manager export.
- Create `cyber_os/privacy/models.py` — state enum, status/coverage dataclasses, and validated IPC request/result types.
- Create `cyber_os/privacy/runtime.py` — locate and verify pinned Tor/sing-box resources; build exact runtime configs without executing them.
- Create `cyber_os/privacy/manager.py` — idempotent enable/disable/recover state machine and broker client.
- Create `cyber_os/privacy/windows_ipc.py` — bounded named-pipe client with per-user authentication and timeout handling.
- Create `ui/hackerai/packages/desktop/src-tauri/src/tor_privacy.rs` — Tauri commands and tray menu integration; call only the broker's fixed operation set.
- Create `ui/hackerai/packages/desktop/src-tauri/src/bin/tor_privacy_broker.rs` — elevated Windows broker entry point; accept only schema-validated status/enable/disable/recover requests over a per-user ACL-protected pipe.
- Create `ui/hackerai/packages/desktop/src-tauri/src/tor_privacy/wfp.rs` — uniquely owned WFP provider/sublayer/filter lifecycle and restore logic.
- Create `Tools_cyber/tor_privacy_status.py`, `Tools_cyber/tor_privacy_enable.py`, and `Tools_cyber/tor_privacy_disable.py` — read-only status and explicitly modifying agent tools.
- Create `skills/tor-privacy/SKILL.md` — agent usage, exact verified coverage, failure, and recovery guidance.
- Create `ui/hackerai/app/components/svs/NetworkPrivacyPanel.tsx` — status, coverage, limitations, and manual controls.
- Modify `ui/hackerai/app/components/svs/SvsWorkspaceHeader.tsx` — make the shield/status area open Network & Privacy.
- Modify `ui/hackerai/app/components/StaiChatWorkspace.tsx` — mount the panel and connect its current state.
- Modify `ui/hackerai/packages/desktop/src-tauri/Cargo.toml` and `src-tauri/src/lib.rs` — register the broker binary, tray support, and Tauri commands.
- Modify `ui/hackerai/packages/desktop/src-tauri/tauri.conf.json` — bundle only verified privacy runtime resources and broker artifacts.
- Modify `cyber_os/assets/skills.py` only if discovery tests show the canonical `skills/` directory does not already auto-discover the new skill; expected change is none.
- Create focused Python, Rust, and React tests alongside the existing `tests/`, `src-tauri`, and `app/components/svs` conventions.

## Task 1: Prove the Windows Tor Data Plane Before Product Integration

**Files:**
- Create: `scripts/tor_privacy_poc.ps1`
- Create: `docs/superpowers/plans/2026-10-12-tor-privacy-poc-results.md`
- Test: isolated disposable Windows 10/11 VM only; never run the route-changing POC on the developer workstation.

**Interfaces:**
- Produces: pinned Tor and sing-box candidate versions, license/provenance notes, a checked configuration, and packet-level evidence for TCP, IPv4/IPv6, DNS, UDP/QUIC rejection, Tor loss, and adapter loss.
- Gate: do not proceed to enable a host route in STAI unless all no-direct-fallback and recovery checks pass in the disposable VM.

- [ ] **Step 1: Write executable VM acceptance assertions** — implement packet-capture assertions for expected Tor exit, DNS, IPv4/IPv6, unsupported-protocol, Tor-down, adapter-down, reboot, and restoration observations; record results in `2026-10-12-tor-privacy-poc-results.md`. A written checklist or unit test alone does not satisfy this gate.
- [ ] **Step 2: Verify current upstream releases** — record official release URLs, exact versions, signatures/checksums, licenses, and update channels for Tor Expert Bundle and the selected TUN runtime; reject unverified artifacts.
- [ ] **Step 3: Build the disposable-VM POC** — configure a loopback-only Tor SOCKS listener, TUN inbound, Tor-only SOCKS outbound, strict route, and a separately applied default-deny WFP policy with only explicit exceptions.
- [ ] **Step 4: Run leak and failure checks in the VM** — prove actual process traffic reaches a Tor exit, DNS is not sent to a direct resolver, unsupported UDP/QUIC is dropped, and killing either runtime leaves direct egress blocked.
- [ ] **Step 5: Verify restoration** — confirm an explicit stop restores the VM's captured original connectivity without removing unrelated rules.
- [ ] **Step 6: Record and review decision** — mark each check pass/fail with packet capture and state evidence; if any critical check fails or evidence is incomplete, revise the design and stop before product integration.

## Task 2: Model Privacy State and Validate Runtime Configuration

**Files:**
- Create: `cyber_os/privacy/__init__.py`
- Create: `cyber_os/privacy/models.py`
- Create: `cyber_os/privacy/runtime.py`
- Create: `tests/test_tor_privacy_models.py`
- Create: `tests/test_tor_privacy_runtime.py`

**Interfaces:**
- Produces `PrivacyState`: `unknown | off | preparing | protected | degraded_blocked | recovery_required | unsupported`.
- Produces `PrivacyStatus`: state, host platform, Tor bootstrap, adapter, IPv4, IPv6, DNS, kill-switch, unsupported interfaces, and sanitized error fields.
- Produces `RuntimePaths.discover(root: Path) -> RuntimePaths` and `build_runtime_config(paths: RuntimePaths) -> dict[str, object]`.
- Runtime discovery must be read-only; no download, install, route, or firewall change occurs here.

- [x] **Step 1: Write failing state-model tests** — assert valid state values, defaults, JSON serialization, sanitized errors, and unsupported-platform status.
- [x] **Step 2: Run the focused tests and confirm failure** — `pytest tests/test_tor_privacy_models.py -q` must fail because the types do not exist.
- [x] **Step 3: Implement the models** — use immutable dataclasses and a `str, Enum` state enum; do not represent unknown coverage as true.
- [ ] **Step 4: Write failing runtime validation tests** — cover missing runtime, wrong executable names, checksum mismatch, signature failure, unsupported versions, unsafe config paths, and loopback-only SOCKS binding.
- [ ] **Step 5: Implement read-only discovery/config generation** — use pinned manifest values from Task 1; reject path traversal, unverified binaries, direct DNS, direct application outbounds, non-loopback SOCKS binds, and unrecognized config fields.
- [ ] **Step 6: Run focused tests** — `pytest tests/test_tor_privacy_models.py tests/test_tor_privacy_runtime.py -q` must pass.

## Task 3: Add a Narrow, Elevated Windows Policy Broker

**Files:**
- Create: `ui/hackerai/packages/desktop/src-tauri/src/bin/tor_privacy_broker.rs`
- Create: `ui/hackerai/packages/desktop/src-tauri/src/tor_privacy/wfp.rs`
- Modify: `ui/hackerai/packages/desktop/src-tauri/Cargo.toml`
- Test: `ui/hackerai/packages/desktop/src-tauri/src/tor_privacy/wfp_tests.rs`

**Interfaces:**
- Named pipe protocol: one bounded JSON request per connection, with `op` restricted to `status | enable | disable | recover`; no shell command, arbitrary path, IP, or firewall-rule inputs from callers.
- `WfpPolicy::install(owner_id: &str, tor_app_id: &[u8]) -> Result<PolicyStatus, PolicyError>`.
- `WfpPolicy::remove_owned(owner_id: &str) -> Result<PolicyStatus, PolicyError>`.
- `WfpPolicy::status(owner_id: &str) -> Result<PolicyStatus, PolicyError>`.
- The broker accepts only the current interactive user's ACL-protected pipe and validates caller identity; all changes are tagged to a stable STAI provider/sublayer GUID.

- [ ] **Step 1: Write failing broker protocol tests** — assert unknown fields/operations, oversized requests, wrong-user access, replayed sequence numbers, and arbitrary command/path values are rejected.
- [ ] **Step 2: Write failing WFP ownership tests** — assert install is idempotent, status distinguishes missing/partial/full policy, and removal deletes only the STAI provider's objects.
- [ ] **Step 3: Run Rust tests and confirm failure** — `cargo test --manifest-path ui/hackerai/packages/desktop/src-tauri/Cargo.toml tor_privacy` must fail before implementation.
- [ ] **Step 4: Implement the broker transport and policy module** — use Windows Filtering Platform management APIs; add only narrowly scoped default-deny filters and Tor-process/link-management exceptions; no custom kernel callout driver.
- [ ] **Step 5: Add broker elevation/launch plumbing** — launch only the bundled broker with the Windows UAC `runas` prompt; verify its executable provenance and pipe identity before accepting commands.
- [ ] **Step 6: Run Rust tests and Windows VM policy checks** — unit tests pass, then confirm persistent policy survives broker termination and removes only owned filters in the Task 1 VM.

## Task 4: Implement the Lifecycle Manager and Agent Tools

**Files:**
- Create: `cyber_os/privacy/manager.py`
- Create: `cyber_os/privacy/windows_ipc.py`
- Create: `Tools_cyber/tor_privacy_status.py`
- Create: `Tools_cyber/tor_privacy_enable.py`
- Create: `Tools_cyber/tor_privacy_disable.py`
- Create: `skills/tor-privacy/SKILL.md`
- Create: `tests/test_tor_privacy_manager.py`
- Create: `tests/test_tor_privacy_tools.py`

**Interfaces:**
- `TorPrivacyManager.status() -> PrivacyStatus`.
- `TorPrivacyManager.enable() -> PrivacyStatus`.
- `TorPrivacyManager.disable() -> PrivacyStatus`.
- `TorPrivacyManager.recover() -> PrivacyStatus`.
- Manager sequence: install kill switch; start and verify Tor; start TUN runtime; verify IPv4/IPv6/DNS; report `protected` only when every required check passes. On partial failure, retain default-deny and return `degraded_blocked` or `recovery_required`.
- Status plugin is `READ_ONLY`; enable/disable plugins are `MODIFIES_SYSTEM`, `requires_admin = True`, and declare `native_windows` only.

- [ ] **Step 1: Write failing lifecycle tests** — cover operation order, repeated enable/disable, busy/concurrent operations, bootstrap timeout, listener collision, runtime crash, DNS failure, and no-direct-fallback invariant.
- [ ] **Step 2: Run focused tests and confirm failure** — `pytest tests/test_tor_privacy_manager.py -q` must fail before implementation.
- [ ] **Step 3: Implement authenticated IPC and manager state transitions** — use the broker contract from Task 3, bounded timeouts, process ownership tracking, and atomic state snapshots.
- [ ] **Step 4: Write failing plugin approval/metadata tests** — assert status is read-only, modifying calls use `MODIFIES_SYSTEM`, admin is required, unsupported OS returns an unavailable result, and results never claim protection on partial coverage.
- [ ] **Step 5: Implement the three plugins and skill bundle** — register the operations through existing `Tools_cyber` discovery and document exact state meanings, limitations, and recovery.
- [ ] **Step 6: Run focused tests** — `pytest tests/test_tor_privacy_manager.py tests/test_tor_privacy_tools.py -q` and the existing tool-registry contract tests pass.

## Task 5: Expose UI Controls and Persistent Tray Status

**Files:**
- Create: `ui/hackerai/app/components/svs/NetworkPrivacyPanel.tsx`
- Create: `ui/hackerai/app/components/svs/NetworkPrivacyPanel.test.tsx`
- Create: `ui/hackerai/packages/desktop/src-tauri/src/tor_privacy.rs`
- Modify: `ui/hackerai/app/components/svs/SvsWorkspaceHeader.tsx`
- Modify: `ui/hackerai/app/components/StaiChatWorkspace.tsx`
- Modify: `ui/hackerai/packages/desktop/src-tauri/Cargo.toml`
- Modify: `ui/hackerai/packages/desktop/src-tauri/src/lib.rs`
- Modify: `ui/hackerai/packages/desktop/src-tauri/tauri.conf.json`

**Interfaces:**
- Tauri commands: `tor_privacy_status() -> Result<PrivacyStatusDto, String>`, `tor_privacy_enable() -> Result<PrivacyStatusDto, String>`, `tor_privacy_disable() -> Result<PrivacyStatusDto, String>`, `tor_privacy_recover() -> Result<PrivacyStatusDto, String>`.
- Header opens a dedicated panel; panel actions call only those typed Tauri commands. The Windows tray menu presents status, open panel, disable, and recovery; both UI entry points use the same manager/broker and never launch arbitrary commands.
- Non-Tauri web builds show status if available but disable host-changing controls with a clear “use the STAI Windows desktop app” message.

- [ ] **Step 1: Write failing React component tests** — cover all five state labels, exact coverage warnings, enable/disable button visibility, elevation denial, error states, and no success banner before verified `protected` status.
- [ ] **Step 2: Add failing Rust Tauri command/tray tests** — verify commands accept no caller-supplied route/executable data and tray disable/recovery uses the same typed broker operations.
- [ ] **Step 3: Implement Tauri command bridge and tray menu** — add Tauri's tray feature, create the tray at startup, keep the process available while the window is hidden, and preserve an explicit exit path.
- [ ] **Step 4: Implement the panel and header control** — use live status polling with bounded intervals, disable conflicting actions during transitions, and show what will stop working before activation.
- [ ] **Step 5: Run focused UI/Rust tests** — `pnpm --dir ui/hackerai test -- --runInBand app/components/svs/NetworkPrivacyPanel.test.tsx` and `cargo test --manifest-path ui/hackerai/packages/desktop/src-tauri/Cargo.toml tor_privacy` pass.

## Task 6: Package Verified Runtime and Complete End-to-End Verification

**Files:**
- Create: `scripts/fetch_tor_privacy_runtime.ps1`
- Create: `tests/test_tor_privacy_packaging.py`
- Modify: `ui/hackerai/packages/desktop/src-tauri/tauri.conf.json`
- Modify: `docs/superpowers/specs/2026-10-11-windows-tor-privacy-design.md`

**Interfaces:**
- Runtime fetcher takes no arbitrary URL input; it uses the exact approved URLs and digests from Task 1, verifies signatures/checksums/licenses, and writes only under the designated runtime directory.
- Release bundle reports exact Tor, sing-box, Wintun/TUN, and broker versions and license notices.

- [ ] **Step 1: Write failing packaging tests** — reject changed digest, invalid signature, changed version, unexpected archive paths, missing license notices, and writes outside the designated runtime directory.
- [ ] **Step 2: Implement pinned dependency fetch/verification** — never run downloaded executables during verification; refuse to replace an existing validated runtime on a failed update.
- [ ] **Step 3: Build and install the Windows desktop bundle** — confirm only verified binaries and the required tray/broker artifacts are packaged.
- [ ] **Step 4: Run the full privacy VM matrix** — test app TCP, DNS, IPv4, IPv6, UDP/QUIC, Tor/adapter/broker crashes, reboot recovery, UAC denial, network change, concurrent VPN, and clean disable.
- [ ] **Step 5: Run project tests** — Python privacy and tool tests; Tauri `cargo test`; focused React tests; existing tool registry, API contract, and desktop build checks.
- [ ] **Step 6: Obtain security review** — use the repository security-reviewer role for the broker, WFP rules, runtime verification, IPC ACLs, and UI/API action boundary; resolve findings before claiming the feature complete.
- [ ] **Step 7: Update the spec with verified coverage and limitations** — no “whole-device protected” claim unless the complete Windows VM matrix passes. List WSL/VM/container exclusions explicitly.

## Implementation Notes

- The repository currently has fragmented egress through `requests`, `urllib`, `dnspython`, raw sockets, Playwright/Chromium, subprocess tools, and provider SDKs. Do not patch these independently; the Windows TUN/WFP enforcement is the coverage boundary.
- `cyber_tools.py` dynamically loads plugins from `Tools_cyber/`; skill discovery already scans `skills/<name>/SKILL.md`.
- The local FastAPI process and UI are not elevated. Keep privileged policy mutation inside the Tauri-launched broker; do not expose a privileged unauthenticated localhost HTTP endpoint.
- The current Tauri desktop application has no system tray menu yet; add its tray controls without changing the existing communications settings behavior.
- Do not activate the route on the development workstation as a test. Network-level verification belongs in a disposable Windows VM with a known recovery path.
