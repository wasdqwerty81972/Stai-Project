# Persistent Per-Chat Memory Design

**Status:** Approved in conversation; awaiting written-spec review  
**Date:** 2026-10-12

## Goal

Make the SVS-Cyber chat agent remember useful context within each chat across long conversations and app restarts, while letting the user search that chat's history.

## User intent and success criteria

The user wants context to be remembered automatically, without manually managing a memory system. Memory is scoped to one chat/task, persists on the local installation, is retrieved automatically for later prompts, and is searchable in the UI.

Success means:

- A follow-up prompt can use relevant earlier details after the agent process restarts.
- History and memory from one chat never appear in another chat's prompt or search results.
- Long conversations retain a compact summary while older messages remain searchable.
- Search can return matching messages and investigation events with source and time.
- Existing conversation history remains available after migration.
- Clearing a chat clears its memory and searchable conversation history.

## Current behavior

- The active HackerAI client sends the chat route's `session_id` as its stable chat ID.
- `ui/api_server.py` persists a single event deque to `.sessions/ui_conversations.json`, but caps it at 200 events across all chats.
- Prompt construction passes at most the last 12 user/assistant turns, with each message clipped to 1,200 characters.
- `CyberAgent.process_chat_command` creates a new investigation record for each message. Investigation findings are persisted separately and are not reloaded as durable prompt memory on a later turn.
- Existing JSON state stores and UI transcript history therefore do not provide reliable, searchable, per-chat context for long-running work.

## Design

### 1. Memory identity and storage

Use the existing `session_id` as the durable chat/task memory key. Keep each `investigation_id` as the identity of a single run and link run events to the owning `session_id`.

Add a local SQLite memory store under `.sessions`, using the Python SQLite runtime and FTS5 for keyword search. It will be the source of truth for retained conversation events and memory summaries. Store events with a stable event ID, session ID, optional investigation ID, type/role, timestamp, searchable text, and structured metadata. Store one versioned compact summary per session with its update timestamp and source event watermark. Do not add an external database or embedding service.

SQLite writes must be serialized/transactional so simultaneous event callbacks cannot overwrite one another. FTS indexes must be updated atomically with their source event. If FTS5 is unavailable, preserve saving/loading and fall back to bounded recent history; report search as unavailable rather than failing chat.

### 2. Automatic recall and summary

Before each model run, load memory for only that `session_id`: the compact summary, recent user/assistant turns, and a small relevance-ranked set of older matching conversation/investigation events. Build a bounded memory block (target ceiling: 2,000 estimated tokens) and add it to the runtime's existing prompt context. Include timestamps and event IDs in retrieved snippets so the agent can distinguish prior observations from current evidence and refer back to their source.

Keep all retained source events searchable; do not replace or discard them when creating the summary. Refresh the summary when old history must be compacted to stay within the prompt budget, using the configured model where available. If summarization fails, keep the prior summary and continue with recent and retrieved source events. This avoids an extra summarization call on every turn.

Memory is enabled by default for this local chat product. Search and retrieval use the same session scope. No vector embeddings, cross-chat/global memory, memory settings panel, or model-provider changes are included.

### 3. History ingestion and migration

Persist chat events and relevant investigation events as they are emitted, preserving their existing event IDs and timestamps. Adapt conversation listing and message retrieval to read from the SQLite store, with stable chronological ordering and pagination for long chats.

On first startup with an empty memory store, import the existing `ui_conversations.json` events transactionally, retaining original session IDs, event IDs, timestamps, event types, and metadata. Keep the source JSON file until import succeeds. Do not claim to recover entries already discarded by the old global 200-event cap.

### 4. Search and deletion UI/API

Add a search field to the existing chat history/sidebar. Search is scoped to the selected chat and presents matching excerpts with the message/event type and timestamp; selecting a result opens that chat and navigates to the matching message when possible.

Add a session-scoped search endpoint that returns event ID, timestamp, type, excerpt, and the matching message/event payload required for navigation. Reject blank or oversized queries and cap result counts.

Deleting one chat removes its transcript events, summary, and FTS rows. Clearing all chats removes all conversation memory. Investigation operational records remain subject to their existing lifecycle unless they are explicitly part of the deleted chat memory store.

### 5. Privacy and context safety

All memory remains local in `.sessions`. A retrieval query must always include the active session ID filter; never search globally and filter after retrieval. Persisted prior observations are historical context, not verified current system state. Prompt construction must label recalled events as historical and preserve their timestamps/provenance. Existing security-event redaction/truncation rules continue to apply to stored event payloads.

## Error handling

- SQLite is locked or temporarily unavailable: return recent in-memory context for the current run where available; do not fail the user's chat request solely because memory persistence failed.
- A record is malformed: skip that record and continue loading the rest; log a sanitized diagnostic.
- FTS query fails or is unavailable: use recent turns and the saved summary, and return a clear search error to the UI.
- Summary generation fails: retain the last valid summary and source events.
- Migration is interrupted: use a transaction so startup can retry without duplicate events.
- A chat is deleted: remove its memory and search index entries in one transaction.

## Implementation boundaries

Expected product areas are `ui/api_server.py`, `cyber_os/agent_runtime.py`, the existing HackerAI chat workspace/API client, and focused tests for the SQLite store, API contracts, and prompt-memory assembly. Follow existing patterns and avoid changing the unrelated warm-start design, other chat stacks, or the wider event schema unless required by these interfaces.

## Acceptance checks

1. Messages beyond the old 200-event global limit remain available for their chat after restart.
2. A follow-up prompt receives its saved summary and relevant older event after restart, within the memory token budget.
3. Distinct chat IDs cannot retrieve or search each other's messages, investigation records, or summaries.
4. Search returns an older exact match with its original timestamp and event ID; blank/oversized input is rejected safely.
5. Summary refresh does not remove or modify searchable source events; failed refresh preserves the previous summary.
6. JSON history migration is idempotent and only removes neither the source file nor events when the migration fails.
7. Per-chat deletion removes that chat's summary and searchable records; clear-all removes all conversation memory.
8. Memory-store failure does not prevent ordinary chat from running.

## Reference

OmniRoute's documented memory flow scopes records by session, performs SQLite FTS5 retrieval, injects a bounded set into later prompts, and extracts memory after responses. This design adapts that core pattern to SVS-Cyber's local chat/session model without its optional vector stores or external infrastructure: <https://github.com/diegosouzapw/OmniRoute/blob/main/docs/frameworks/MEMORY.md>.
