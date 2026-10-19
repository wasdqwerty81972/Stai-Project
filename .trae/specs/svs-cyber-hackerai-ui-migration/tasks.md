# SVS-Cyber HackerAI UI Migration — Implementation Task Queue

Dependency ordering summary:
- Task 1 is the **root dependency** and must land before Tasks 2–6 can be considered complete (they may be authored on feature branches that assume Task 1's API).
- Task 7 overlaps Task 3 in timeline; both can proceed in parallel once Task 1's types are merged.
- Task 8 is strictly last and depends on all prior tasks being merged to `main`.

---

## Task 1: UI adapter layer + event normalization + WS reconnect backoff + /api/agent/cancel endpoint + unify duplicate event buses

- **Status:** pending
- **Priority:** high
- **Maps to AC:** AC-1, AC-3, AC-5, AC-8

### Description

Produce the single integration spine the rest of the UI will consume.

1. Create a module-scoped `AgentEventBus` singleton at a canonical path (e.g. `ui/hackerai/app/lib/agent-event-bus.ts`) and rewrite every existing import of the two duplicate buses to point at this single file. Add a 10-entry ring buffer of last events for `console.debug` inspection in dev.
2. Implement `useSvsEventStream(conversationId: string)` hook: opens a WebSocket, dedupes inbound frames by `event_id` (Set-based, lifetime scoped to the conversation), and maps each of the 11 SVS event types (`user_message`, `assistant_message`, `agent_reasoning`, `tool_started`, `tool_output`, `tool_completed`, `tool_failed`, `approval_requested`, `approval_resolved`, `subagent_verdict`, `run_state`) to the shared UI contract types. Unknown event types are debug-logged and dropped.
3. WebSocket reconnect policy: first reconnect at 1s, subsequent attempts double, cap at 16s. Expose a tiny `connectionState` atom (`connected` / `reconnecting` / `dead`) consumed by the shell header dot indicator.
4. Stamp the correct `finishedAt` on terminal tool blocks by keying partial `tool_output` chunks off `run_id`, so the WorkedFor timer can freeze deterministically on completion.
5. Backend: add `POST /api/agent/cancel` to the FastAPI app under `d:\STAI 2\ui`; handler looks up the in-flight run by id (or the active run if none provided) and signals a `threading.Event` already owned by the runner. Respond 204 immediately after `.set()`; the handler must not await the run's cleanup.
6. Adapter batches streaming assistant_message parts with a 120ms window (midpoint of NFR1's 100–150ms) before committing to React state.

### Test Requirements

- **TR-1.1 (type=rule):** `tsc --noEmit -p ui/hackerai/tsconfig.json` exits 0. Evidence: full stdout log.
- **TR-1.2 (type=rule):** `rg "class AgentEventBus|new AgentEventBus" ui/hackerai/app` returns exactly 1 declaration and 0 duplicate constructor sites. Evidence: ripgrep stdout.
- **TR-1.3 (type=rule):** `rg "HackerAI-Source" ui/hackerai/app` returns 0 matches. Evidence: ripgrep stdout.
- **TR-1.4 (type=rubric):** Manually drive a WS session (AC-5 flow). Inject four events in order: `agent_reasoning → tool_started → tool_output → tool_completed`. Screenshot of the rendered turn; events must appear in order with no duplicate rows. Score: 0 = correct order & no dupes; 1 = correct order but one cosmetic re-render flicker; 2 = order swapped or rows duplicated. Must score 0.
- **TR-1.5 (type=rule):** Cancel endpoint latency: hit `POST /api/agent/cancel` 10 times in sequence via curl; attach the raw `%{time_total}` lines. 9 of 10 must be `< 1.000s`.
- **TR-1.6 (type=rule):** Unit test for `useSvsEventStream` dedupe: emit two frames sharing an `event_id` and assert only one state commit occurs. Jest snapshot or assertion diff attached.

---

## Task 2: Composer upgrade — attachment slot disabled, Ask/Agent mode toggle, disabled glass-surface state, draft localStorage persistence, CJK/mobile input padding fix

- **Status:** pending
- **Priority:** high
- **Maps to AC:** AC-1, AC-2, AC-6, AC-9

### Description

Bring the composer to parity while respecting the attachment and mode Non-Goals.

1. Replace the textarea-only disabled flag with a shared `isComposerDisabled` prop applied to the outer `glass-surface`: surface opacity 0.5, pointer-events none, toolbar icons and buttons inherit `aria-disabled` styling. Focus ring must still draw on the outer shell at `rounded-22px`, `min-h:98px`, `max-h:300px`.
2. Add Ask / Agent two-state toggle to the right of the model selector. "Ask" = concise answer, "Agent" = full tool-enabled run. Wire to the existing SVS request payload field (or drop the field name into the request JSON if unknown — leave a typed TODO comment).
3. Attachment icon in the toolbar renders visually but is `disabled` with an explicit tooltip "File attachment not supported in this build". No drag-and-drop acceptor; no `<input type="file">` wired.
4. Draft persistence: on `input` event, debounce 500ms and write `{ ts: Date.now(), content: value }` to `localStorage` under key `svs:composer:draft:{conversationId}`. On component mount, read the key; if the stored `ts` is older than 7 days, `removeItem` instead of restoring. When the user clicks "New Investigation" the active draft key is explicitly cleared.
5. Fix CJK/mobile clipping: add an off-screen mirror `<div>` (same width, font, padding, white-space) that mirrors the textarea value and use that mirror's `offsetHeight` as the autosize driver instead of `scrollHeight`. Add 6px of inner-bottom padding specifically to CJK codepoint ranges detected via `/[\u3000-\u9FFF\uAC00-\uD7AF]/.test(value)`.

### Test Requirements

- **TR-2.1 (type=rule):** `tsc --noEmit` and project lint both exit 0. Evidence: both logs attached.
- **TR-2.2 (type=rubric):** Visual fidelity check (contributes to AC-9): screenshot composer in four states — idle, focused, disabled, and after typing 20 lines. Rubric: 0 = matches target in all four; 1 = minor border-radius/spacing delta; 2 = wrong disabled visual treatment or focus ring on textarea instead of shell. Must score ≤ 1.
- **TR-2.3 (type=rule):** Unit test for CJK height measurement: simulate a 3-line Hangul string and assert the measured height matches the mirror div, not a smaller `scrollHeight` value. Jest assertion attached.
- **TR-2.4 (type=rule):** Draft persistence E2E-ish test harness or manual script: write a value, wait 600ms, reload the page; value restored. Write a value, advance `localStorage` `ts` by 8 days, reload; value cleared. Manual screenshots for each state.
- **TR-2.5 (type=rule):** Branding scan of composer strings: `rg -i "hackerai" ui/hackerai/app/components/composer` returns 0 matches. Evidence: ripgrep stdout.

---

## Task 3: Chat timeline upgrade — resolve sort/comment contradiction, animate=true on assistant streaming, MessageActions copy button, WorkedFor live 1s timer, content-visibility rows

- **Status:** pending
- **Priority:** high
- **Maps to AC:** AC-1, AC-5, AC-9, AC-10

### Description

Upgrade the timeline renderer so it matches HackerAI's behaviour and fixes the documented ordering bug.

1. Locate `applyEvent`. Delete the comment claiming sort is handled by the caller. Add a stable sort immediately after the append: `rows.sort((a, b) => (a.createdAt - b.createdAt) || a.event_id.localeCompare(b.event_id))` and leave a 1-line inline comment on the sort line explicitly citing "resolves spec OQ sort-vs-comment contradiction; sort is applied here idempotently".
2. For assistant rows whose `streaming: true` flag is set by the adapter, pass `animate={true}` into `MemoizedMarkdown`. For historical rows loaded from disk on conversation open, pass `animate={false}`.
3. `MessageActions` copy button: pass the owning message's id into the action handler so `navigator.clipboard.writeText` serialises that specific message's markdown, not a shared ref to the most recent message.
4. `WorkedFor` collapsible row: start a `setInterval` 1s tick when the row mounts with a `startedAt` and no `finishedAt`. On each tick recompute the duration. If/when `finishedAt` is stamped, clear the interval and display the final frozen duration.
5. Apply `content-visibility: auto` with `contain-intrinsic-size: 180px` on every timeline row container. If the codebase already has `LegendList` wired, keep it and ensure row estimates are ≥ 180px; whichever path is taken, confirm no scroll jump by performing the AC-10 streaming check.

### Test Requirements

- **TR-3.1 (type=rule):** `tsc --noEmit` exits 0. Evidence: log attached.
- **TR-3.2 (type=rule):** Deduction-by-construction: `rg "sort is handled elsewhere" ui/hackerai/app` returns 0 matches; `rg "resolves spec OQ sort-vs-comment"` returns exactly 1 match on the sort line. Evidence: ripgrep stdout.
- **TR-3.3 (type=rule):** Copy button unit test: render 3 messages with distinct content, click the copy action on message #2; assert the clipboard call received message #2's markdown. Jest test attached.
- **TR-3.4 (type=rubric, contributes to AC-10):** 30-second streaming run recording. Rubric: 0 = no scroll jumps, typewriter runs, WorkedFor increments exactly 1/s; 1 = one scroll jump OR a single animation frame skip; 2 = multiple jumps or timer visibly wrong. Must score ≤ 1. Video/GIF attached.
- **TR-3.5 (type=rubric, contributes to AC-9):** Screenshot of a turn containing assistant prose + code block with a visible WorkedFor row. Rubric: 0 = identical layout to HackerAI reference; 1 = spacing deltas < 4px; 2 = code block missing copy/download/wrap or WorkedFor not collapsible. Must score ≤ 1.

---

## Task 4: Reasoning & tool activity parity — AgentWorkHeader aggregate, AgentActivityRow distinct-activity dots, subagent tool groups, reasoning 12K streaming tail preview

- **Status:** pending
- **Priority:** high
- **Maps to AC:** AC-5, AC-9, AC-10

### Description

Map real SVS agent events into the HackerAI reasoning and activity surfaces. No synthetic text.

1. `AgentWorkHeader`: compute aggregate duration as `max(lastEvent.finishedAt ?? now, firstEvent.startedAt) - firstEvent.startedAt` across all tool rows belonging to the current turn. Re-render on every new tool_completed / tool_failed event.
2. `AgentActivityRow`: three phase dots. Fill dot 1 (planning) on the first `agent_reasoning` of the turn. Fill dot 2 (execution) on the first `tool_started`. Fill dot 3 (synthesis) on the first `assistant_message` after tool completion. Dot fill is derived purely from event presence; never infer phase from token contents.
3. Subagent tool groups: events carrying a non-empty `subagent_id` render under a collapsible subagent header inside the workspace column. Header label is the subagent id or human name the event already carries; do not invent names.
4. Reasoning blocks: each `agent_reasoning` event is a single collapsible `Reasoning` block. Headline preview is the trailing 12,000 characters of the content (tail, not head); streaming chunks auto-scroll-open the newest block while keeping user-collapsed blocks collapsed.

### Test Requirements

- **TR-4.1 (type=rule):** Wireframe unit test: feed a deterministic ordered event sequence into the row-mapper, assert the three dots fill in order planning → execution → synthesis on exact event boundaries. Jest assertion diff attached.
- **TR-4.2 (type=rule):** `rg "synthetic|marketing|placeholder" ui/hackerai/app/components/reasoning ui/hackerai/app/components/activity` returns 0 matches (excluding test file mocks clearly labelled as such). Evidence: ripgrep stdout.
- **TR-4.3 (type=rubric, AC-9):** Screenshot of an open reasoning block mid-stream plus the three-dot activity row below a WorkedFor header. Rubric: 0 = dots fill in the expected phase pattern and reasoning shows tail preview; 1 = minor icon or colour delta; 2 = wrong dot order or reasoning displays head instead of tail. Must score ≤ 1.
- **TR-4.4 (type=rule):** Subagent grouping: inject two tool events each under two distinct subagent_ids; assert rendered DOM contains two distinct subagent headers with tool rows nested under them (query selector count assertion). Jest + React Testing Library output attached.

---

## Task 5: Terminal & workspace & sidebar upgrades — TerminalCodeBlock ANSI caching, XtermRenderer SSR-false dynamic import, sidebar .sidebar-chat-scroll class + data-scrolling attribute

- **Status:** pending
- **Priority:** medium
- **Maps to AC:** AC-1, AC-2, AC-9

### Description

Hardens three adjacent UI surfaces.

1. `TerminalCodeBlock` ANSI cache: memoize ANSI-to-DOM parsing inside a 100-entry LRU keyed `sha1(rawOutput + 'ansi-v1')`. Debounce re-parses on rapid incoming chunks with a 150ms delay so streaming terminal output stays 60fps.
2. `XtermRenderer` must be `dynamic(() => import('./xterm-renderer'), { ssr: false })` so Next.js SSR builds never attempt to pull Node-only xterm bindings. Ensure the fallback while the JS chunk loads is a non-jumping 16px-above-baseline spacer so row heights are stable.
3. Sidebar scroll container: the scrollable `<div>` of the conversation list must carry class `.sidebar-chat-scroll`. Attach a scroll listener that sets `data-scrolling="true"` on the element for 800ms after the last scroll event fires; use this attribute in CSS to toggle a bottom shadow overlay.
4. Sidebar hover actions: each conversation row on hover exposes only a delete icon. Delete calls SVS' existing conversation-delete endpoint if one exists, otherwise removes the row optimistically from local state and emits a warning; no rename, no move-to-folder (per OQ-2 default).

### Test Requirements

- **TR-5.1 (type=rule):** `tsc --noEmit` and lint exit 0. Evidence: logs attached.
- **TR-5.2 (type=rule):** `rg "import.*XtermRenderer" ui/hackerai/app` returns only one site and that site uses `dynamic(..., { ssr: false })`. Evidence: ripgrep stdout + file snippet.
- **TR-5.3 (type=rule):** `rg "sidebar-chat-scroll" ui/hackerai/app` returns exactly one DOM attribute/class site plus CSS consumers. Evidence: ripgrep stdout.
- **TR-5.4 (type=rubric, AC-9):** Screenshot sidebar in three states: idle, actively scrolling (data-scrolling true), and hovered on a row showing delete-only affordance. Rubric: 0 = shadow + delete look correct; 1 = shadow flickers slightly during 800ms window; 2 = no shadow or extra icons (rename/folder) visible on hover. Must score ≤ 1.
- **TR-5.5 (type=rule):** Performance microbench: paste the same 5,000-line ANSI log into TerminalCodeBlock twice; assert the second render's ANSI-parse time (logged via performance.now) is ≤ 10% of the first. Numbers pasted.

---

## Task 6: Branding pass — remove HackerAI logos/names/commercial UI, Settings strip billing/usage/team tabs, public routes redirect to /, SVS-Cyber titles + landing chips

- **Status:** pending
- **Priority:** high
- **Maps to AC:** AC-3, AC-6, AC-7

### Description

Strip every HackerAI commercial surface and apply the SVS-Cyber identity.

1. Delete or comment out: `HackerAISVG` component, every `<img>` or `<svg>` import carrying the HackerAI wordmark, marketing hero copy, pricing table JSX, trust badge `<a>` tags, download-application links, billing dialog mount points, tier strings ("Pro", "Team", "Enterprise"), Stripe checkout submit hooks, WorkOS SSO button components.
2. Replace each of the above surfaces with the SVS-Cyber Shield logo component (existing SVG in the repo) and the label string "SVS-Cyber".
3. Landing suggestion chips: rewrite the 4–6 default chips to defensive-security examples (e.g. "Analyze this PCAP for C2 beaconing", "Generate an IR playbook for ransomware", "Pivot this IOC through MISP", "Summarize yesterday's firewall alerts", "Draft a quarantine runbook for this host", "Check this hash against VirusTotal via tool").
4. `<title>`, `<meta name="description">`, OpenGraph and Twitter-card tags in the document head all updated to "SVS-Cyber" / SVS-Cyber Shield imagery.
5. Settings dialog: remove the Billing, Usage, Team, Entitlements, and Plans tabs entirely. Keep (in order): Personalization, Security, Data Controls, Agents, Account. Any route handlers for `/settings/billing`, `/settings/team`, `/settings/plans`, `/pricing`, `/login`, `/signup` respond with server-side 307 redirects to `/` (per OQ-3 default).
6. **Do not touch** `LICENSE`, `NOTICE`, or `THIRD_PARTY_NOTICES`; if a global grep hits those files, that is expected and must be excluded from the evidence.

### Test Requirements

- **TR-6.1 (type=rule):** `rg "HackerAI-Source" ui/hackerai/app` returns 0 matches (re-checking AC-3 post-branch). Evidence: ripgrep stdout.
- **TR-6.2 (type=rule):** Branding deep scan on built static HTML: `rg -i "hackerai"` against the Next.js build output directory, excluding `LICENSE`/`NOTICE` files. Must return 0 matches. Evidence: ripgrep stdout.
- **TR-6.3 (type=rule):** Settings tab audit: open Settings, screenshot the tab bar. Count of visible tabs = exactly 5, labelled Personalization / Security / Data Controls / Agents / Account in order.
- **TR-6.4 (type=rule):** Redirect audit: curl each of `/settings/billing`, `/settings/team`, `/settings/plans`, `/pricing`, `/login`, `/signup`; attach the HTTP status lines. All six must be `307` (or SVS' configured equivalent) and the Location header must be `/`.
- **TR-6.5 (type=rule, AC-7):** Screenshot triptych: shell header, sidebar fully expanded, landing page. SVS-Cyber Shield logo must be visible in all three. `<title>` tag in browser DevTools must read exactly `SVS-Cyber`.

---

## Task 7: LegendList virtualization + LegendList perf wiring, confirm no scroll jumps, duplicate message guard, entry dedupe optimizations

- **Status:** pending
- **Priority:** medium
- **Maps to AC:** AC-1, AC-2, AC-10, NFR-1

### Description

Performance pass on the timeline. If `LegendList` is not available in the current dependency set this task falls back to the `content-visibility: auto` path described in FR2 and augments it.

1. Choose virtualization strategy at the start of the task and record the choice in code comments:
   - Path A (LegendList present): install/wire LegendList, provide an estimatedRowSize function, overscan 6, and pin the scroll anchor to the bottom-most visible pixel before prepending streaming rows above the viewport.
   - Path B (no LegendList): keep `content-visibility: auto` already added in Task 3, and additionally wrap the timeline in a scroll-anchor manager that measures `scrollTop` before a React commit and restores it after if the newly-arrived tokens are strictly above the viewport.
2. Duplicate-message guard: inside `applyEvent`, assert (dev-only via `invariant`) that the post-sort array has no duplicate `event_id`s; in production, silently drop duplicates.
3. Entry dedupe optimization: the `Set<string>` of seen `event_id`s in `useSvsEventStream` should not grow without bound; cap at the most recent 10,000 IDs using an LRU or rotating pair of Sets.

### Test Requirements

- **TR-7.1 (type=rule):** `tsc --noEmit` and lint exit 0. Evidence: logs attached.
- **TR-7.2 (type=rule):** Duplicate event injection test: emit the same `event_id` twice through the adapter; assert only one row appears in the post-apply array. Jest test output attached.
- **TR-7.3 (type=rubric, AC-10 streaming fidelity score):** Load a 500-message fixture conversation, start a new streaming run atop it, and record the 30-second run with scroll position in the middle of history. Rubric: 0 = no scroll jumps at all; 1 = exactly one visible jump, immediately recovered; 2 = 2+ jumps. Must score ≤ 1. Video/GIF attached.
- **TR-7.4 (type=rule):** Perf check on 500-message conversation: scroll through the list end-to-end while Chrome DevTools Performance inspector records; 95th-percentile frame must be < 16.7ms. Performance profile summary screenshot or trace JSON attached.

---

## Task 8: Final verification — typecheck, lint, build, jest, manual 19-flow visual testing with screenshots

- **Status:** pending
- **Priority:** high (task-queue final)
- **Maps to AC:** AC-1 through AC-10 inclusive

### Description

Integrate, green-light, and collect the final evidence artefacts.

1. Merge Tasks 1–7 to a single integration branch; resolve any type or build conflicts.
2. Run the project's configured typecheck, lint, build, and Jest suite. Collect full logs.
3. Execute a 19-step manual visual flow covering every reachable click surface:
   1. Cold load landing
   2. New Investigation → blank state
   3. Type composer text, blur, refocus, submit
   4. ArrowUp recalls prior turn
   5. Ctrl+C / stop button mid-run → cancel endpoint exercised
   6. Streaming reasoning block opens
   7. Tool row starts → completes → shows success state
   8. Tool row fails → shows error state
   9. Approval card → click Approve → card disables
   10. Terminal tool block with ANSI colour
   11. Code block → copy, download, wrap toggle
   12. WorkedFor row collapse/expand
   13. Message copy button on an early message
   14. Assistant message >20 lines → Show more / Show less
   15. Sidebar expand → collapse → 48px rail
   16. Sidebar delete conversation (hover action)
   17. Settings dialog → 5 tabs, click through each
   18. Mobile viewport (≤ 400px) → sheet sidebar, composer no horizontal scroll
   19. Disconnect WS → observe reconnect backoff dot states, then restore
4. Attach screenshots for each of the 19 steps, the 5 AC-9 fidelity screens, the AC-7 triptych, the AC-5 turn, and the AC-10 30s recording.
5. Produce a single `evidence.md` in the task's work directory (not the repo root) linking every artefact to its corresponding AC and reporting the AC-9 sum-of-5 score and the AC-10 score verbatim.

### Test Requirements

- **TR-8.1 (type=rule, AC-1):** `tsc --noEmit` exits 0; full log attached.
- **TR-8.2 (type=rule, AC-2):** Lint exits 0; full log attached.
- **TR-8.3 (type=rule, AC-3):** `rg "HackerAI-Source"` over the repo (excluding `D:\HackerAI-Source` directory itself) returns 0 matches. Evidence attached.
- **TR-8.4 (type=rule, AC-4):** Jest full suite log attached; every skipped test carries an inline skip-reason comment and issue id (visible in output).
- **TR-8.5 (type=rule):** Production build succeeds with no warnings promoted to errors. Build log attached.
- **TR-8.6 (type=rubric, AC-9):** AC-9 5-screen fidelity scoresheet filled in with per-screen 0/1/2 and the sum. Sum must be ≤ 2.
- **TR-8.7 (type=rubric, AC-10):** AC-10 streaming fidelity score filled in; must be ≤ 1. Recording attached.
- **TR-8.8 (type=rule, AC-6/AC-7):** Full set of branding screenshots and ripgrep scan output attached as per AC-6 and AC-7.
- **TR-8.9 (type=rule, AC-8):** Cancel endpoint 10-run latency numbers pasted; ≥ 9/10 below 1.000s.
- **TR-8.10 (type=rule):** 19-step manual flow evidence index (`evidence.md`) lists exactly one screenshot or recording per step and cross-references the satisfied AC.
