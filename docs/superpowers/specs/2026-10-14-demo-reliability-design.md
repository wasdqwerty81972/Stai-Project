# SVS Cyber Demo Reliability Design

## Goal

Make tomorrow's Windows demonstration start consistently and show an honest, repeatable protection workflow. The dashboard must open even when this machine lacks the native build toolchain, and it must distinguish an available API from active protection. The demo must use a harmless marker and must not require installing malware.

## Current constraints

- `cyber_main.py` defaults to the native Windows dashboard. This checkout has no release executable or Cargo command; it does have a recent debug executable, which the launcher currently ignores.
- The launcher treats `/health` as ready even though that endpoint does not initialize or inspect the protection service.
- The API currently looks for `.protection/manifest.json`, `.protection/manifest.sig`, and `.protection/public.key`. They are absent, so the local service uses an empty ruleset and reports degraded status.
- The repository has a signed demo manifest and pinned public key, containing one exact SHA-256 rule for EICAR. That known sample can be removed by host security software before SVS Cyber sees it.
- The installed Windows service and kernel driver are not available on this host. A user-mode demo result cannot be described as proof of minifilter enforcement or production-grade protection.

## Approaches considered

1. Require installation/build of the native app, service, and driver before the demo. This matches the intended product deployment but cannot be completed and validated reliably on this machine by tomorrow.
2. Keep the current launch flow and rely on `/health`. This opens a dashboard when the API answers, but can show an empty protection engine as ready.
3. Recommended: select an available dashboard launch mode, surface the real protection status, and add a safe demo path using an explicitly labeled inert marker. Keep the kernel service and driver status visible as unavailable where they are not installed.

## Design

### Launcher

`cyber_main.py` starts the API, then selects the native dashboard when a release app exists, when a complete Tauri development toolchain is available, or when the existing debug app is present. If no native app can run but the local Vite dashboard is available, it starts that through the local Node/Vite installation and opens the browser. Startup errors must name the missing component. The launcher continues to supervise child processes and shuts down children on exit.

The launcher probes both API liveness and protection status. A protection-degraded result is not a launch failure: the dashboard should still open, while its status remains visibly degraded. The launcher must not print that protection is ready merely because `/health` returns 200.

### Protection status and rules

The API reports ruleset version, trust state, scanner availability, Windows service state, and driver state through its existing protection status contract. Demo rules are loaded from the repository's signed manifest and verified against the pinned `trusted-rules.pub`; an editable key next to an editable manifest cannot establish trust. A missing or invalid bundle remains degraded and reports a concrete reason rather than silently acting like a healthy AV engine.

### Safe demonstration path

Add an explicitly labeled demo workflow based on an inert marker and a demo-only rule. It must exercise the real user-mode scanner, quarantine storage, event persistence, and dashboard refresh. The UI labels the result as a demo detection and states that it validates the user-mode path only. It must not claim that an unsigned demo rule is trusted or that a driver blocked the file. The fixture is generated in a temporary demo location and removed during cleanup; it must not resemble an executable payload or run code.

### Failure handling and observability

Startup errors and dashboard states distinguish API unavailable, rules missing/invalid, scanner unavailable, service unavailable, and driver unavailable. The launcher gives a concise fallback instruction when a mode cannot start. Existing scan and quarantine state is not deleted or reset by demo startup.

## Verification and acceptance criteria

- Unit tests cover mode selection with native app present, development toolchain present, and browser fallback; backend health alone cannot mark protection ready.
- API tests cover missing, invalid, and pinned demo rule packages and verify the resulting status/trust fields.
- An integration test with an inert marker proves scan detection, quarantine, durable event history, and dashboard-visible status without a malware payload.
- On the target Windows machine, `python cyber_main.py` opens a dashboard; protection status accurately identifies missing service/driver; and the safe demo workflow completes. If no native app or native build prerequisites are available, browser fallback is automatic and clearly announced.
- Results must distinguish automated/source-level checks from live Windows service or driver enforcement. No claim of production-grade equivalence to Bitdefender is made by this demo hardening.

## Out of scope

- Adding Sigma ingestion or a broad third-party threat intelligence database.
- Installing or executing real malware for a demonstration.
- Building/signing/installing a Windows minifilter driver or claiming production readiness without the required publisher, altitude, signing, and clean-machine validation.
- Replacing the existing dashboard design or adding unrelated AV features.
