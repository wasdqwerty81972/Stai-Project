# SVS-Cyber Competition UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a HackerAI-quality SVS-Cyber chat workspace that is reliable and compelling in a live competition demo.

**Architecture:** Keep the existing Next.js app and Python FastAPI bridge. Extract focused presentation components from the active chat workspace, keep backend data flow in `StaiChatWorkspace`, and verify that every visible control reflects an executable API capability.

**Tech Stack:** Next.js 16, React 19, TypeScript, Tailwind, FastAPI, Python, WebSocket, Jest, pytest.

**Spec:** `docs/superpowers/specs/2026-09-27-svs-competition-ui-design.md`

## Global Constraints

- `HackerAI-Source/` and `ECC-source/` are read-only references and cannot become runtime dependencies.
- Preserve existing user changes in the dirty worktree. Do not edit `.kilocode`.
- Only automatic model routing is currently executable through `/api/chat`.
- Do not fabricate tool activity, evidence, token streaming, or approval outcomes.
- Read `ui/hackerai/AGENTS.md` and relevant Next.js 16 docs before frontend edits.
- Keep file ownership disjoint for the parallel phase; do not commit other agents' or existing user changes.

## Review Focus

- A WebSocket event for another session must not appear in the active conversation.
- A reconnect or HTTP response must not duplicate the assistant answer.
- Cancelling one session must not report that another session was cancelled.
- A failed tool or disconnected backend must not look like a successful investigation.
- A narrow/mobile viewport must keep navigation and the send/stop controls reachable.

---

### Task 1: Backend chat contract (parallel owner: backend agent)

**Files:** `ui/api_server.py`, `tests/test_ui_api_contract.py` (new).

**Interfaces:** Preserve `POST /api/chat`, `GET /api/conversations`, `GET /api/conversations/{session_id}/messages`, `POST /api/agent/cancel`, `POST /api/approval/{request_id}/respond`, and `/ws`. The frontend expects event IDs, session IDs, response text, and meaningful cancellation/error results.

- [ ] Inspect the current routes and event bus before changing behavior.
- [ ] Add focused tests for cross-session event delivery, cancellation, duplicate response/history behavior, and unsupported model handling; confirm failures where bugs exist.
- [ ] Implement only confirmed contract fixes in `ui/api_server.py`, preserving compatibility with existing consumers.
- [ ] Run `python -m pytest -q tests/test_ui_api_contract.py` and the relevant existing API/agent tests; report commands and results.

### Task 2: Competition workspace shell (parallel owner: shell agent)

**Files:** new `ui/hackerai/app/components/svs/SvsWorkspaceSidebar.tsx`, `SvsWorkspaceHeader.tsx`, `SvsLandingState.tsx`, and focused tests in the same directory. Do not edit `StaiChatWorkspace.tsx`.

**Interfaces:** Sidebar props: `conversations: Array<{id:string;title:string;last_message?:string;timestamp:string}>`, `activeSessionId:string`, `onClearAll:()=>void|Promise<void>`, `collapsed:boolean`, `onCollapsedChange:(value:boolean)=>void`. Header props: `title:string`, `connection:"connecting"|"connected"|"disconnected"`, `running:boolean`, `onOpenNavigation:()=>void`. Landing props: `onSuggestion:(prompt:string)=>void`. Export named components.

- [ ] Inspect HackerAI's `ChatLayout`, `Sidebar`, `ChatHeader`, and current SVS shell plus relevant Next.js docs.
- [ ] Add focused tests for navigation, active conversation, empty state, connection state, and mobile controls.
- [ ] Implement the three components using existing theme tokens and HackerAI-derived primitives, with SVS branding and no hosted-service hooks.
- [ ] Run targeted Jest tests, TypeScript check, and lint on changed files; report commands and results.

### Task 3: Evidence-first transcript presentation (parallel owner: transcript agent)

**Files:** new `ui/hackerai/app/components/svs/SvsTranscript.tsx` and focused tests. Do not edit `StaiChatWorkspace.tsx`, `SvsCyberComposer.tsx`, or backend files.

**Interfaces:** Export `SvsTranscript` with props `entries: SvsTranscriptEntry[]`, `running:boolean`, `error:string|null`, `sessionId:string`, `onApproval:(requestId:string,approved:boolean)=>void|Promise<void>`, and `bottomRef:React.Ref<HTMLDivElement>`. Export `SvsTranscriptEntry` with `id`, `role`, `timestamp`, optional `finishedAt`, and parts for text, visible activity, and tools. Reuse existing Markdown, tool, reasoning, and WorkedFor primitives where practical.

- [ ] Inspect HackerAI's `Messages`, `MessageItem`, `ReasoningHandler`, and the current SVS assistant rendering.
- [ ] Add focused tests for user/assistant text, reasoning, tool success/failure, approval controls, empty state, and pending state.
- [ ] Implement readable transcript presentation; keep private reasoning and fabricated progress out of the UI.
- [ ] Run targeted Jest tests, TypeScript check, and lint on changed files; report commands and results.

### Task 4: Integrate the shell and transcript (owner: primary agent, after parallel phase)

**Files:** `ui/hackerai/app/components/StaiChatWorkspace.tsx`, `ui/hackerai/app/components/SvsCyberComposer.tsx`, `ui/hackerai/lib/stai-api.ts`, `ui/hackerai/app/contexts/StaiGlobalState.tsx`, and focused tests as needed.

**Interfaces:** Use Task 2 and 3 exports. Keep `/api/chat` and `/ws` as the only chat execution channels. Preserve optimistic message reconciliation by event ID and session ID.

- [ ] Integrate the new components without resetting user edits already present in composer/API files.
- [ ] Make visible chat mode/model/attachment controls truthful to backend capabilities; keep supported keyboard interactions.
- [ ] Verify session history, send, stop, reconnect, tool events, approval, and disconnected states with focused tests.
- [ ] Run TypeScript, targeted Jest, lint, and relevant Python tests.

### Task 5: Visual and end-to-end review (owner: primary agent)

**Files:** Only focused fixes needed to resolve verified defects; no broad source copying.

- [ ] Launch the local stack and compare landing and active chat against `HackerAI-Source` visual structure.
- [ ] Inspect desktop and narrow viewport states, tool/approval presentation, connection failures, and keyboard behavior.
- [ ] Fix verified issues and rerun only affected checks.
- [ ] Review the full diff for reference-checkout imports, fake controls, stale HackerAI branding on the active route, and accidental user-change loss.

