# V4 P2A — Exact-Hash Intelligence Evidence Verification

Date: 2026-10-14

## Implemented

- `ProtectionService` now looks up an exact SHA-256 indicator only after the scanner has hashed the file.
- A match is attached to the scan verdict and persisted with source, verification, confidence, severity, feed version, first/last seen, freshness, corroborations, and the store's eligibility reason.
- The scanner's original verdict remains authoritative. A clean file remains `clean`/`allow`; hash intelligence cannot block or quarantine in P2A. Existing signed-rule blocks retain their behavior.
- Protection storage schema v8 adds a bounded evidence JSON field. Existing v7 detections migrate with null evidence; malformed evidence is ignored with a warning rather than breaking detection history.
- The local API and Windows service composition own separate local intelligence databases. Health reports `advisory`, `degraded`, or `unavailable`; activation is always `inactive` in this phase.
- Integrity and eligibility health checks are cached for 60 seconds so dashboard refreshes do not repeatedly run whole-database checks. Scan-time hash lookups remain indexed.
- Threat Activity identifies exact-hash matches as advisory and shows provenance, freshness, and digest. System Status shows intelligence health and potential eligibility count.

## Verification

| Command | Result |
|---|---|
| `python -m pytest -q tests/test_windows_protection_scanner.py tests/test_windows_protection_service.py tests/test_windows_protection_store.py tests/test_windows_protection_api.py tests/test_windows_protection_service_lifecycle.py tests/test_process_scan_api.py tests/test_threat_intel_store.py tests/test_windows_protection_triage.py` | **156 passed, 17 warnings in 121.45s** |
| `python -m pytest -q tests/test_windows_protection_service.py tests/test_windows_protection_api.py tests/test_windows_protection_service_lifecycle.py` after adding health caching | **60 passed, 17 warnings in 100.02s** |
| `ui/hackerai/node_modules/.bin/jest.cmd packages/protection-dashboard/src/__tests__/DetectionRow.test.tsx packages/protection-dashboard/src/__tests__/SystemStatus.test.tsx --runInBand` | **2 suites passed, 4 tests passed** |
| `ui/hackerai/node_modules/.bin/tsc.cmd --noEmit -p packages/protection-dashboard/tsconfig.json` | **Exited 0** |

The 17 backend warnings are existing FastAPI `on_event`/Starlette deprecations in `ui/api_server.py` and the installed test client; they are unrelated to the new intelligence integration and remain for a separate lifecycle cleanup.

Coverage includes fresh confirmed and block-eligible exact matches remaining advisory, signed-rule precedence, corrupt database behavior, evidence persistence/readback, v7 migration, malformed evidence recovery, API and pipe serialization, and UI states for advisory, retracted/expired, and unavailable data.

## Protection boundary

The local intelligence database is not populated or activated by this change. A readable SQLite database is not proof of an authenticated feed. Feed ingestion, signature verification, staged activation, rollback, and any future intel-based blocking require a separate implementation and verification phase. The current bundled EICAR rule remains test-only. This work does not load or validate the kernel minifilter and does not make SVS-Cyber production-equivalent to Bitdefender.
