# SVS-Cyber HackerAI UI Migration Specification

## 1. Problem Statement

SVS-Cyber currently has a partial port of the HackerAI chat UI with several confirmed gaps and defects that must be resolved while leaving the SVS backend architecture fully intact.

Specific gaps include:
- Missing attachment UI slot and Ask/Agent mode toggle in the composer
- Duplicate `AgentEventBus` instances causing double-dispatch of events
- No backend `/api/agent/cancel` endpoint wired to stop in-flight runs
- WebSocket reconnect with no exponential backoff, causing retry storms on transient disconnects
- Composer disabled-state ambiguity: only the textarea greys out while the surrounding glass surface and toolbar remain interactive-looking
- `applyEvent` has both a sort-order assertion and a contradicting comment that sort is handled elsewhere, leading to ordering bugs on optimistic merge
- Partial sidebar styling with missing scroll-state class and hover affordances
- Streaming assistant prose rendered without `animate=true`, so MemoizedMarkdown produces no typewriter animation
- Message-level copy actions not wired per message row

The Python backend (agents, tools, workspace, slash commands, subagents) is out of scope and must not be modified beyond what is strictly required to support the new UI contract.

## 2. Users

- **Defensive Security Investigator** — performs IR playbook lookups, IOC pivots, and evidence triage inside the chat shell. Needs dense, scannable activity rows and one-click artifact export.
- **SOC Operator** — runs a high volume of rapid queries, relies on keyboard shortcuts (ArrowUp/Square, Ctrl+C stop), mobile sheet layout for on-call use, and persistent drafts.
- **Forensic / Incident Responder** — needs full tool-call provenance (timers, durations, terminal ANSI fidelity), subagent verdict surfaces, and audit-friendly sidebar list with date grouping.

## 3. Goals

1. Reproduce the actual HackerAI visual and interaction experience (timeline, composer, reasoning, tool calls, sidebar) at pixel-and-animation fidelity for the three user personas above.
2. Feed that UI exclusively with real SVS agent events via a single normalization adapter. No synthetic reasoning text, no fake tool calls, no mock attachments.
3. Preserve, unchanged, the SVS backend surface: Python agents, tools, workspace, slash commands, subagent verdicts, and the existing FastAPI routing layer.
4. Remove every HackerAI commercial, branding, and product surface (logos, pricing, trust, billing dialogs, WorkOS/Stripe flows, tier copy, marketing routes) and replace it with a consistent SVS-Cyber identity.
5. Fix all confirmed UI bugs enumerated in the Problem Statement and in FR10.

## 4. Non-Goals

- No port of HackerAI's Convex, Trigger.dev, WorkOS, or Stripe backend layers.
- No billing, team, entitlements, or usage-metering migration.
- No authentication migration or rewrite; SVS auth remains exactly as-is.
- No behavioral changes to agent execution, tool selection, or tool execution output format.
- No fake attachments or upload UI if the backend does not support file ingestion; the attachment slot is shown disabled with a tooltip instead.
- No removal of legal attribution: `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES` files and code-level attributions are left untouched.

## 5. Functional Requirements

### FR1 — Shell / Layout

- Dark-mode default with the existing SVS-Cyber palette; Geist Sans + Geist Mono fonts loaded from `ui/hackerai/app/fonts` or equivalent local path (no remote fetch at runtime).
- Three-column layout on >=950px viewport: left sidebar 300px, centre chat column, right workspace column. Below 950px, sidebar becomes a collapsible bottom sheet on mobile.
- Sidebar collapsed width exactly 48px (icon-only rail) when the toggle is pressed; state is persisted in `localStorage` under `svs:sidebar:state`.
- Focus trap inside all modal dialogs (Settings, Approval, New Investigation) with Escape to close.

### FR2 — Chat Timeline

- User messages render as right-aligned speech bubbles; text longer than 20 visible lines collapses with a "Show more / Show less" inline toggle.
- Assistant prose is rendered as markdown via the existing `MemoizedMarkdown` component with inline code, tables, and blockquotes intact.
- `WorkedFor` collapsible row for each assistant turn, showing a live wall-clock timer that increments every 1s from `startedAt` until `finishedAt` is stamped; timer freezes once finished and the row shows the final duration.
- Code blocks use Shiki with the `houston` theme and size guards: min-height 56px, max-height 520px with a sticky header. Copy, Download, and Wrap toggle buttons are present on every block.
- Long chat lists use either `LegendList` virtualization or, if that is not landed yet, `content-visibility: auto` on rows with a 180px intrinsic size. Either way: scrolling must not jump when new streaming tokens arrive above the viewport.

### FR3 — Composer

- Outer shell is a `glass-surface` styled container with `rounded-22px`, `min-h:98px`, `max-h:300px`; focus-visible ring rendered on the outer surface, not only on the textarea.
- Inner textarea uses `TextareaAutosize` with CJK IME-safe padding and must never clip long lines at any viewport width, including 320px mobile.
- Keyboard bindings: ArrowUp when empty loads the prior user turn into the composer (square 8x8px hit-target affordance on the left rail), Ctrl/Cmd+C when the run is in progress sends a stop signal — guarded so ordinary text selection copy still works.
- Disabled state must grey out the entire glass surface, toolbar icons, and buttons, not just the textarea. The surface also swallows pointer events.
- Toolbar contains **both** a model selector dropdown **and** an Ask/Agent mode toggle (two-state: concise answer vs. full agent run).
- Attachment icon is rendered in the toolbar but is `disabled` with a tooltip "File attachment not supported in this build" until the backend exposes the capability; no drag-and-drop acceptor is active.
- Draft content is written to `localStorage` under `svs:composer:draft:{conversationId}` on a 500ms debounce and evicted after 7 days via stored timestamp. New chat clears the active draft.

### FR4 — Reasoning / Activity

- SVS `agent_reasoning` events map one-to-one to HackerAI `Reasoning` collapsible blocks with a 12K-character tail preview; streaming chunks open the latest block automatically.
- `AgentWorkHeader` aggregates the per-turn active duration from tool_started to the last completed event and renders a running timer.
- `AgentActivityRow` renders three horizontally-laid-out dot icons that fill as distinct activity phases are observed (planning → execution → synthesis). Dots are filled by event type, never synthesised from text.
- Zero lines of synthetic or marketing copy are ever injected into reasoning or activity rows.

### FR5 — Tool Calls & Workspace

- Event mapping: `tool_started` → ToolBlock `loading`, `tool_output` → appends, `tool_completed` → `success`, `tool_failed` → `error`; state transitions are idempotent keyed by `tool_call_id`.
- `approval_requested` events render an inline Approve/Deny card that POSTs to `/api/approval/{requestId}/respond` with the appropriate action. The card disables itself after first click.
- The five tool categories (terminal, filesystem, browser, knowledge, network) are mirrored to the right workspace column with the topmost recent tool of each category pinned.
- Terminal tool output renders via `TerminalCodeBlock` with cached ANSI parsing and `XtermRenderer` loaded via `dynamic(..., { ssr: false })` to avoid SSR import issues.

### FR6 — Sidebar

- Built on the shadcn/ui `Sidebar` primitive.
- Header row: SVS-Cyber shield logo on the left, "New Investigation" button on the right that creates a fresh conversation and resets composer + timeline state.
- Conversation list is grouped by calendar date (Today, Yesterday, Previous 7 Days, Older), each group header sticky within the scroll pane.
- Scroll container has class `.sidebar-chat-scroll` and toggles `data-scrolling="true"` for 800ms after every `scroll` event so the fade-out shadow overlay is correct.
- Active conversation is highlighted with the accent border; hover reveals a delete-only action (no rename or move affordances unless Open Questions are resolved to include them).

### FR7 — Event Normalization Adapter

- Single hook `useSvsEventStream(conversationId)` encapsulates the WebSocket lifecycle, dedupe logic, and contract mapping.
- Maps at minimum the 11 SVS event types: `user_message`, `assistant_message`, `agent_reasoning`, `tool_started`, `tool_output`, `tool_completed`, `tool_failed`, `approval_requested`, `approval_resolved`, `subagent_verdict`, `run_state`. Any unknown event type is logged via `console.debug` in dev and otherwise ignored.
- Deduplication is idempotent by `event_id`; the hook maintains a `Set<string>` of seen IDs over the lifetime of the conversation.
- Terminal events stamp the correct `finishedAt` by keying off `run_id` so partial terminal output chunks share a lifecycle.
- WebSocket reconnect uses exponential backoff starting at 1s, doubling each attempt, capped at 16s. The connection-indicator dot in the shell header reflects state (green / yellow-reconnecting / red-dead).

### FR8 — SVS Features Preserved

- Slash commands (e.g. `/tools`, `/workspace`, `/agent`) pass through verbatim from the composer to SVS; no filtering, no re-ordering, no HackerAI slash overlay.
- Right workspace column preserves SVS' current layout of file-tree + terminal + notes tabs; the HackerAI workspace surface is an additional overlay that coexists.
- Subagent verdict cards render with the existing SVS verdict taxonomy (`safe`, `suspicious`, `malicious`, `inconclusive`); no colour changes.
- Settings dialog contains exactly five tabs, in this order: Personalization, Security, Data Controls, Agents, Account. Billing, Usage, Team, Entitlements, and Plans tabs are removed entirely; their routes redirect to `/`.

### FR9 — Branding & Product Surfaces

- **Removals** (every instance, search-wide): `HackerAISVG` component, HackerAI wordmark logo, marketing landing hero copy, pricing table, trust badges, download links, billing dialogs, tier-based copy ("Pro", "Team", "Enterprise"), Stripe checkout flows, WorkOS SSO buttons.
- **Replacements**: Shell header, sidebar header, Settings header, landing page, and `<title>` / `<meta>` / OG tags all use "SVS-Cyber" naming and the SVS-Cyber Shield logo.
- Landing suggestion chips are re-authored to defensive-security domain examples (e.g. "Analyze this PCAP for C2 beaconing", "Generate an IR playbook for ransomware", "Pivot this IOC through MISP").
- `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES` files and any code-level attribution comments inside them are not modified.

### FR10 — Confirmed Bugs Fixed

- Unify the two existing `AgentEventBus` instances (one in the shell, one in the chat renderer) into a single module-scoped singleton exported from one file; all imports point at that file.
- Add a backend `POST /api/agent/cancel` endpoint that sets a per-run `threading.Event` and responds 204 within 1s for 9/10 invocations; wire the composer stop button and Ctrl+C handler to this endpoint.
- Fix composer hidden-input-text clipping on mobile and CJK IME by adding an inner padding guard and measuring content height with a mirror `<div>` instead of `scrollHeight` alone.
- Resolve the `applyEvent` comment vs sort contradiction: remove the comment that claims sort is handled elsewhere and instead perform a stable sort by `(createdAt, event_id)` inside `applyEvent`; document this decision in an inline code comment on the sort line.
- Pass `animate={true}` on streaming assistant text so `MemoizedMarkdown` triggers its typewriter animation; non-streaming (historical) passes keep `animate={false}`.
- Wire `MessageActions` copy button per message row so each row copies its own rendered markdown, not the last message.

## 6. Non-Functional Requirements

### NFR1 — Performance

- Streaming token parts are accumulated with a 100–150ms batch window inside `useSvsEventStream` before React state commits.
- Shiki ANSI highlighting is debounced 150ms and cached in a 100-entry LRU keyed by `sha1(content + lang)`.
- Timeline rows >= 180px estimated size use `content-visibility: auto` (or LegendList virtualization) so 500-message conversations remain scrollable at 60fps.

### NFR2 — Independence

- No import path references, `require()`, or dynamic imports under `D:\HackerAI-Source`; the build must succeed with that directory removed from disk.
- No new runtime dependencies on `convex`, `@trigger.dev`, `@workos-inc/*`, or `stripe` packages.

### NFR3 — Accessibility

- All modal dialogs implement a focus trap and close on Escape.
- Layout usable down to 360px CSS width; no horizontal scroll on a 320px-wide viewport when `overflow-x: hidden` is set on `<html>`.
- Animation-heavy components (typewriter, activity dots, WorkedFor timer) respect `prefers-reduced-motion: reduce` by disabling motion.

### NFR4 — Observability

- Every event ingested by the adapter is logged with `console.debug('[svs-events]', type, event_id)` in `NODE_ENV !== 'production'`.
- `tsc --noEmit` and the project linter both return 0 errors on the final tree.

## 7. Constraints

- UI source of truth lives under `d:\STAI 2\ui\hackerai\app`; no parallel React app is introduced.
- The FastAPI backend serving the UI is rooted at `d:\STAI 2\ui`.
- The Python agent runtime and workspace code lives at `d:\STAI 2`.
- The adapter contract is typed in the UI only; backend types in the Python layer are left unchanged.
- No schema migrations to any SVS datastore; all persistence is browser-local.

## 8. Open Questions

| # | Question | Default (used if unresolved) |
|---|---|---|
| OQ-1 | How deeply should "Custom Instructions" wire to SVS? Current port has a stub that never reaches the agent. | Keep settings UI surface; POST to an existing `/api/user/preferences` endpoint if present, otherwise no-op and store in `localStorage` only. |
| OQ-2 | Does the sidebar need conversation rename and move-to-folder actions? The current bug list calls out delete-only hover. | Delete-only for v1. Rename + folders deferred. |
| OQ-3 | How should the public `/login`, `/signup`, and HackerAI `/pricing` routes be handled now that auth and billing are Non-Goals? | Server-side 307 redirect all of them to `/`. Delete the route handler files if they contain no SVS-owned logic. |

## 9. Acceptance Criteria

Every AC below specifies an evidence artifact. Zero ACs are "code reviewed"; all require reproducible output.

| AC | Rule | Rubric / Evidence |
|---|---|---|
| AC-1 | Typecheck passes | `tsc --noEmit -p ui/hackerai/tsconfig.json` exits 0; full log attached. |
| AC-2 | Lint passes | Project lint command (see root `package.json` scripts) exits 0; full log attached. |
| AC-3 | No HackerAI-source imports | `rg "HackerAI-Source" ui/hackerai/app` returns 0 matches; ripgrep stdout attached. |
| AC-4 | Jest suite green-or-documented | `jest` (or the project's configured unit runner) passes; any skipped test has an inline comment explaining the skip and a tracking issue number. Output log attached. |
| AC-5 | WS four-event sequence renders correctly | Manual recording: start a run, capture `agent_reasoning → tool_started → tool_output → tool_completed` in order on a single turn. Screenshot of the rendered turn attached. Events must appear in the order the adapter received them with no row duplication. |
| AC-6 | No HackerAI branding reachable by click | Manually click every reachable route from `/` (sidebar, settings tabs, landing chips, dialogs). Screenshot set attached showing SVS-Cyber branding on each. `rg -i "hackerai"` on the built static HTML (excluding `LICENSE`/`NOTICE`) returns 0 matches. |
| AC-7 | SVS branding consistent | Screenshot triptych: shell header, sidebar expanded, landing page. Shield logo present in all three; `<title>` tag is `SVS-Cyber`. |
| AC-8 | Cancel endpoint responds in <1s 9/10 times | `for i in {1..10}; do curl -s -o /dev/null -w '%{time_total}\n' -X POST /api/agent/cancel; done` — 9 out of 10 lines show `< 1.000`. Raw numbers pasted. |
| AC-9 | Visual fidelity to target | Compare 5 key screens (composer focus, assistant prose + code block, reasoning open, tool block error-state, sidebar) against HackerAI reference screenshots. Rubric per screen: 0 = indistinguishable, 1 = minor spacing/colour only, 2 = structural mismatch. Sum across 5 screens must be ≤ 2. Scoresheet attached. |
| AC-10 | Streaming fidelity | Record a 30-second streaming run. Rubric: 0 = no scroll jumps, smooth typewriter, timer increments exactly 1/s; 1 = one scroll jump or minor animation frame skip; 2 = visible glitches. Score must be ≤ 1. Video or GIF recording attached. |
