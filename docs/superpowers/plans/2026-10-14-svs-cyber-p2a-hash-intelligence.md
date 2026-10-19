# SVS-Cyber P2A: Exact-Hash Intelligence Evidence Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Connect the existing indexed threat-intelligence database to file scan evidence so exact SHA-256 matches are visible and safely classified by provenance, trust, freshness, and retraction state.

**Architecture:** Keep file hashing and signed YARA evaluation in `scan_path`. After a stable SHA-256 is produced, `ProtectionService` consults the existing `ThreatIntelStore.block_decision` and attaches structured evidence to the scan result and durable detection. Until a separate signed-feed activation plan establishes a trusted active database, all database matches remain advisory and cannot independently cause a block. The current EICAR rules remain test-only.

**Tech Stack:** Python, SQLite, FastAPI, React/TypeScript, pytest, Jest.

**Spec:** `docs/superpowers/specs/2026-10-14-svs-cyber-antivirus-v4-design.md` (P2)

## Global Constraints

- Only fresh, non-retracted, sufficiently trusted/corroborated exact-file indicators may produce a high-confidence block.
- IP, domain, and URL reputation never becomes a file verdict.
- Preserve source/provenance, confidence, first/last seen, expiry, and retraction evidence in detections.
- Keep the EICAR package explicitly test-only.
- Keep file hashing/YARA/database work outside high-frequency process telemetry and kernel callbacks.
- Never call an unsigned, incomplete, or integrity-failing database production-active.
- Do not change installed service startup state or load the experimental driver on the development host.

## Review Focus

- Expired, retracted, synthetic, low-confidence, or below-threshold exact-hash records must never block; test each rejection path.
- A corrupt, missing, or unverified intelligence database must leave signed-rule scanning available and report intelligence as unavailable; test startup and scan behavior.
- A signed high-confidence rule block must not be weakened by an intelligence miss or weak record; test conflicting evidence precedence.
- A network IOC match must not create a file detection; test hash-only scanner integration.
- Duplicate scans and database migrations must preserve one durable detection with the same evidence; test restart/readback and repeated scans.

---

### Task 1: Add typed intelligence evidence and deterministic verdict precedence

**Files:**
- Modify: `cyber_os/protection/models.py`
- Modify: `cyber_os/protection/service.py`
- Test: `tests/test_windows_protection_scanner.py`
- Test: `tests/test_windows_protection_service.py`

**Interfaces:**
- Add immutable `ThreatIntelEvidence` with `indicator_type`, `indicator_value`, `source`, `verification`, `confidence`, `severity`, `feed_version`, `first_seen`, `last_seen`, `freshness`, and `corroborations`.
- Add optional `intel_evidence: ThreatIntelEvidence | None` to `ScanVerdict`.
- Add optional `threat_intel_store: ThreatIntelStore | None` to `ProtectionConfig`.
- Apply `block_decision("sha256", verdict.sha256)` only after a stable digest exists to record the store's eligibility assessment. In this P2A slice, every intelligence match remains advisory, including records that would otherwise be block-eligible. Signed high-confidence rule blocks retain their existing behavior; intelligence cannot create or weaken a file verdict until the separately reviewed signed-feed activation phase.

- [x] **Step 1: Add failing evidence tests** for fresh confirmed intel, fresh corroborated intel above the configured confidence floor, expired/retracted/synthetic/below-floor records, signed-rule block precedence, YARA unavailable with a known digest, and a network IOC that must not affect a file verdict. Assert that intelligence evidence is advisory and never independently blocks in this phase.
- [x] **Step 2: Run the focused scanner/service tests and confirm failures** are caused by missing intel integration/evidence.
- [x] **Step 3: Implement `ThreatIntelEvidence` and the service-side exact-hash evidence adapter.** Do not import the SQLite store into the per-file hashing loop; the service owns the optional store. Preserve the existing signed-rule block behavior and keep intelligence advisory in this phase.
- [x] **Step 4: Run the focused tests** and verify every evidence and precedence case passes.

### Task 2: Persist evidence with detections and expose it through existing APIs

**Files:**
- Modify: `cyber_os/protection/store.py`
- Modify: `cyber_os/protection/service.py`
- Modify: `ui/api_server.py`
- Test: `tests/test_windows_protection_store.py`
- Test: `tests/test_process_scan_api.py`

**Interfaces:**
- Add an optional serialized `threat_intel_evidence` field to `DetectionRecord` and a backward-compatible SQLite migration for existing detection databases.
- Detection read/list responses include the structured evidence when present; existing records with no evidence continue to load with `null` evidence.

- [x] **Step 1: Add failing migration/readback/API tests** for an intel-backed detection, an existing pre-migration detection, and a repeated scan that preserves the originating evidence.
- [x] **Step 2: Run the focused tests and confirm the schema/readback assertions fail.**
- [x] **Step 3: Add the bounded JSON evidence column and migration.** Validate evidence values on write and decode malformed legacy values as absent with a diagnostic rather than failing all detections.
- [x] **Step 4: Return the evidence from existing detection endpoints and preserve response compatibility.**
- [x] **Step 5: Run store and scan API regression tests.**

### Task 3: Wire intelligence-store health and ownership into service/API composition

**Files:**
- Modify: `cyber_os/protection/windows_service.py`
- Modify: `ui/api_server.py`
- Modify: `cyber_os/protection/service.py`
- Test: `tests/test_windows_protection_service_lifecycle.py`
- Test: `tests/test_windows_protection_api.py`
- Test: `tests/test_windows_protection_service.py`

**Interfaces:**
- The installed service owns the `ThreatIntelStore` under its existing protected data root; local API mode owns a separate local store.
- Status reports `threat_intel_state` as `advisory`, `unavailable`, or `degraded`, with integrity result and potential block-eligible record count. This phase never reports the threat database as production-trusted merely because the SQLite file opens.
- The exact-hash scanner receives the same store whose health was reported; no database lookup runs in process metric sampling or kernel callback code.

- [x] **Step 1: Add failing composition/status tests** for a readable advisory database, absent database, corrupt database, and unverified database; ensure signed EICAR scanning remains available in each case and intel matches remain advisory.
- [x] **Step 2: Run the focused tests and confirm status/composition failures.**
- [x] **Step 3: Construct, integrity-check, and lifecycle-manage the store in the service and local API compositions.** Mark readable data advisory; keep missing, corrupt, or unverified intelligence unavailable/degraded and non-blocking.
- [x] **Step 4: Run service lifecycle, API, scanner, and store regression tests.**

### Task 4: Surface real evidence and document the protection boundary

**Files:**
- Modify: `ui/hackerai/app/components/svs/protection/ProcessMonitorView.tsx` and its existing detection detail component as required.
- Modify: the existing protection status TypeScript types.
- Test: colocated process-monitor/detection component tests.
- Modify: `docs/security/antivirus-audit.md`
- Create: `docs/verification/v4-p2a-hash-intelligence.md`

- [x] **Step 1: Add failing UI tests** for verified intel block evidence, advisory-only evidence, expired/retracted evidence, and intelligence unavailable state.
- [x] **Step 2: Run the focused tests and verify they fail for the missing evidence/status UI.**
- [x] **Step 3: Display source, verification, confidence, first/last seen, freshness, and the exact SHA-256 from API evidence.** Keep EICAR labelled test-only and never imply the intelligence database alone covers all malware.
- [x] **Step 4: Run focused UI tests and typecheck.**
- [x] **Step 5: Run the full applicable backend tests and dashboard verification; record exact outputs and whether a signed active feed/database was available on this host.**

## Scope boundary

This plan connects and reports existing exact-hash intelligence in advisory mode. It does not claim broader antivirus coverage or make feed-derived detections block files. A separate P2 plan must implement authenticated feed ingestion and signed/staged update activation before trusted intelligence may block. Licensed YARA rule tiers, safe archive/PE coverage, WFP enforcement, and isolated-VM minifilter loading remain separate P2/P3 plans.

## Self-review

- **Spec coverage:** Implements the first P2 slice: exact-hash lookup, evidence preservation, and honest status. Authenticated feed update activation is required before intelligence can block and remains a follow-up plan; licensed YARA sources and safe archive/PE analysis also remain separate follow-ups.
- **Step scan:** Each task has named tests, expected failure reasons, exact owning files, and a test command boundary.
- **Type consistency:** `ThreatIntelEvidence` is carried by `ScanVerdict`, persisted by `DetectionRecord`, returned by existing APIs, and rendered by existing UI details.
- **Review focus:** All five high-risk conditions above are assigned to tests in Tasks 1–3. P2A tests must assert that no intelligence record independently blocks a file.
- **Proportion:** This is a first vertical slice of P2; external feed trust and new file formats are excluded until their own authentication/licensing and performance plans are approved.
