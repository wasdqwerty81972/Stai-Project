# STAI Protection Agent Escalation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Escalate verified local detections to STAI for asynchronous, evidence-based triage while keeping Level 1 verdicts and disruptive actions outside the agent’s control.

**Architecture:** Convert durable protection detections into a small redacted triage contract and enqueue it after the deterministic decision has been recorded. The agent returns explanation and recommendations only; a separate typed approval flow handles any supported disruptive action.

**Tech Stack:** Existing Python CyberOS engine, STAI agent runtime, event bus, pytest.

**Spec:** `docs/superpowers/specs/2026-10-12-stai-custom-windows-protection-design.md`

## Global Constraints

- The AI path never delays the Level 1 block.
- The agent cannot change the allow/block verdict, update signatures, or issue kernel commands.
- Structured evidence is redacted before agent triage.
- Disruptive follow-up uses a typed request and the existing human approval path.
- Every proposed and completed action is audited with its target and outcome.

## Review Focus

- Agent unavailable or slow: preserve detection and Level 1 outcome; test in Task 2.
- Path, command line, username, or file contents in source event: exclude unless explicitly approved by the triage schema; test in Task 1.
- Agent output asks to allow or unblock: treat as text only; test in Task 2.
- Unknown approval ID or missing approver: execute no action; test in Task 3.
- Duplicate detection event: do not create duplicate triage; test in Task 1.

---

### Task 1: Redacted triage contract and durable enqueue

**Files:**
- Create: `cyber_os/protection/triage.py`
- Modify: `cyber_os/engine.py` at `CyberOSEngine._handle_sensor_event` integration boundary
- Test: `tests/test_windows_protection_triage.py`

**Interfaces:**
- `ProtectionTriageContext.from_detection(record: DetectionRecord, related_events: Sequence[SecurityEvent]) -> ProtectionTriageContext`
- Context fields: `detection_id`, `sha256`, `rule_id`, `rule_version`, `action`, `confidence`, `severity`, `file_type`, `size_bytes`, and bounded event summaries. No raw content, full path, username, or command line.
- `ProtectionTriageCoordinator.enqueue(context: ProtectionTriageContext) -> bool` persists a bounded pending job, deduplicates by `detection_id`, and never performs scanning or changes a verdict.

- [ ] **Step 1: Write failing tests** named `test_triage_context_excludes_paths_users_commands_and_contents`, `test_related_sensor_events_are_bounded_and_redacted`, `test_duplicate_detection_is_enqueued_once`, and `test_detection_is_recorded_before_triage_enqueue`. Assert `"C:\\Users\\alice\\file.exe" not in json.dumps(context)`, `"secret-command" not in json.dumps(context)`, `len(context.related_events) <= 10`, duplicate enqueue returns `False`, and the synchronous protection callback completes while the injected runner is blocked.
- [ ] **Step 2: Run** `python -m pytest -q tests/test_windows_protection_triage.py`; expect missing triage symbols.
- [ ] **Step 3: Implement** strict dataclass-to-dictionary serialization, bounded related-event selection, event-bus publication, and a bounded SQLite-backed triage queue that survives service restarts.
- [ ] **Step 4: Run** the same pytest command; expect all three tests to pass.

### Task 2: Asynchronous agent analysis

**Files:**
- Create: `cyber_os/protection/agent_triage.py`
- Modify: `cyber_agent.py` to wire the coordinator to the existing agent runtime
- Test: `tests/test_windows_protection_agent_triage.py`

**Interfaces:**
- `ProtectionAgentTriage(runner: Callable[[ProtectionTriageContext], str]).submit(context: ProtectionTriageContext) -> str` queues one bounded task and returns its triage ID immediately.
- A completed result contains `triage_id`, `detection_id`, `summary`, `recommendations`, and `completed_at`; it has no executable policy or allow/block field.

- [ ] **Step 1: Write failing tests** named `test_slow_agent_does_not_delay_detection_callback`, `test_agent_output_is_advice_only`, `test_failed_agent_run_keeps_detection_visible`, and `test_triage_queue_is_bounded`.
- [ ] **Step 2: Run** `python -m pytest -q tests/test_windows_protection_agent_triage.py`; expect missing worker/coordinator behavior.
- [ ] **Step 3: Implement** a bounded background worker with safe shutdown and an agent prompt that asks for evidence-based explanation and recommended next steps only. Store the result separately from the Level 1 decision.
- [ ] **Step 4: Run** the same pytest command; expect all four tests to pass.

### Task 3: Typed approval and audit boundary

**Files:**
- Modify: `cyber_os/engine.py` response approval path
- Modify: `ui/api_server.py` approval response contract only if the existing route needs an explicit protection-action discriminator
- Test: `tests/test_windows_protection_response_approval.py`

- [ ] **Step 1: Write failing tests** named `test_unknown_approval_cannot_execute_response`, `test_missing_approver_cannot_execute_response`, `test_agent_recommendation_creates_no_direct_action`, and `test_approved_typed_action_is_audited_with_outcome`.
- [ ] **Step 2: Run** `python -m pytest -q tests/test_windows_protection_response_approval.py`; expect test gaps in the protection response path.
- [ ] **Step 3: Implement** a strict action enum and schema, link requests to a detection ID, reject arbitrary shell/file commands, and reuse `CyberOSEngine.resolve_response_approval` for human approval.
- [ ] **Step 4: Run** `python -m pytest -q tests/test_windows_protection_triage.py tests/test_windows_protection_agent_triage.py tests/test_windows_protection_response_approval.py`; expect all tests to pass.

## Handoff

The dashboard consumes these redacted triage results and approval records through the typed local service contract. Agent recommendations remain descriptive data.
