# STAI Windows Protection Program Plan

**Goal:** Build the approved Windows endpoint-protection design in testable stages, culminating in a dark local dashboard backed by the deterministic protection engine and a test-signed Kernel Minifilter Driver.

**Spec:** `docs/superpowers/specs/2026-10-12-stai-custom-windows-protection-design.md`

## Plan set and dependency order

1. [Protection core](2026-10-12-stai-protection-core.md) — signed hash/YARA rules, file scanning, durable scan jobs, and verified quarantine.
2. [Windows minifilter](2026-10-12-stai-minifilter.md) — bounded driver/service IPC and VM-only on-access enforcement using the core verdict contract.
3. [Agent escalation](2026-10-12-stai-agent-escalation.md) — redacted asynchronous Level 2 triage, existing CyberOS correlation, and approval-gated typed responses.
4. [Dark protection dashboard](2026-10-12-stai-protection-dashboard.md) — local typed Tauri bridge and dashboard pages for status, scans, detections, quarantine, and AI Agent.
5. [Windows packaging](2026-10-12-stai-windows-packaging.md) — local UI/service bundle, elevated installer, rollback, and release gates.

The current host check did not find MSBuild, the WDK compiler/tools, or standard Windows Kits roots, and the Hyper-V `Get-VM` cmdlet is unavailable. Driver source/protocol work can proceed after plan approval, but the kernel build and end-to-end enforcement checks require a WDK-equipped machine and an isolated Windows test VM.

The core is the shared dependency. Agent escalation and the minifilter can use its durable detection/verdict contracts. The dashboard can be implemented after those contracts are fixed. Packaging is last because it depends on the driver, service, bridge, and UI artifacts.

## Shared execution constraints

- Preserve the current dirty checkout; inspect each target file before editing and do not reset, broadly format, or commit unrelated user changes.
- Follow the project `AGENTS.md`: use the existing code patterns and the TDD Guide when implementing logic.
- Run the Python and frontend tests named in the subsystem plans. Run kernel/installer checks only in the named disposable Windows VM.
- Use a managed isolated worktree only after the user chooses that execution setup; current uncommitted repository data must not be discarded or silently omitted.
- Do not report the product as production-ready until Microsoft driver signing and end-to-end supported-Windows VM validation have been completed.

## User-visible release checks

- The app reports `Active` only when the driver, service, and verified rule package are healthy; otherwise it reports `Degraded` or `Unavailable`.
- Detection, blocked operation, and quarantine totals stay distinct and match durable evidence.
- Quick/System scans, quarantine restore, agent triage, and each dashboard route have explicit loading, error, empty, and completed states.
- The Tauri protection commands are available only to its bundled local dashboard, not the hosted web page.
- Production driver signing and Microsoft altitude allocation remain release prerequisites; test-signed VM builds are labeled non-production.
