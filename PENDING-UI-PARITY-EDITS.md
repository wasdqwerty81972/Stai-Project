# PENDING: HackerAI UI parity edits (typing animation + WorkedFor pill)

These edits were applied to the working tree on 2026-09-14, then lost from disk when an
external `git pull --rebase origin main` checked out `1c19cbb` (which does not contain
`ui/hackerai/`). The fork source is intact in commit **`d5bc861`** ("Add remaining project
files"), which the paused rebase has not replayed yet.

Re-apply these six changes once `ui/hackerai/` is back on disk, then run
`npx tsc --noEmit` (only pre-existing convex/billing errors) and
`npx eslint app/components/StaiChatWorkspace.tsx app/components/SvsCyberReasoningPart.tsx`
(only 5 pre-existing nav-a11y warnings).

Goal: match the HackerAI source's streaming behaviour — streamdown's word-by-word
token animation plus the "Working for 12s" / "Worked for 12s" collapsible that folds
every reasoning + tool row of an assistant turn into one pill.

---

## File 1 — `ui/hackerai/app/components/StaiChatWorkspace.tsx`

### 1.1 Add `BrainIcon` to the lucide-react import

```diff
 import {
   Activity,
+  BrainIcon,
   Globe,
```

### 1.2 Import the source's WorkedFor elements (after the shimmer import)

```diff
 import { Shimmer } from "@/components/ai-elements/shimmer";
+import {
+  WorkedFor,
+  WorkedForContent,
+  WorkedForTrigger,
+} from "@/components/ai-elements/worked-for";
```

### 1.3 `ChatEntry` gains a completion timestamp

```diff
   /** ISO timestamp for chronological sorting */
   timestamp: string;
+  /**
+   * ISO timestamp stamped when the run finished. Feeds HackerAI's
+   * "Worked for 12s" trigger (see WorkedForTrigger durationMs).
+   */
+  finishedAt?: string;
   animate?: boolean;
```

### 1.4 New terminal-event set

```diff
   "agent_started",
   "model_info",
   "agent_completed",
+  "agent_failed",
+  "workflow_agent_completed",
   "investigation_completed",
   ...
   // agent_reasoning is handled separately as a ReasoningPart
 ]);
+
+/**
+ * Events that end a run. They do not produce their own entry; they stamp the
+ * assistant entry's `finishedAt` so the work trigger can show a real duration
+ * (HackerAI's `generationTimeMs`).
+ */
+const TERMINAL_RUN_EVENT_TYPES = new Set([
+  "agent_completed",
+  "agent_failed",
+  "workflow_agent_completed",
+  "investigation_completed",
+]);
```

### 1.5 `applyEvent`: stamp `finishedAt` instead of ignoring terminal events

```diff
   // Deduplicate: if we already have this event_id, skip
   if (entries.some((e) => e.id === event.event_id)) return entries;
 
+  // Terminal run events close out the assistant turn instead of adding a row:
+  // stamp the completion time so "Working for …" can settle into
+  // "Worked for …" (HackerAI's WorkedForTrigger durationMs).
+  if (TERMINAL_RUN_EVENT_TYPES.has(event.type)) {
+    const lastAssistantIndex = entries.reduceRight(
+      (found, entry, index) =>
+        found === -1 && entry.role === "assistant" ? index : found,
+      -1,
+    );
+    if (lastAssistantIndex === -1) return entries;
+    return entries.map((entry, index) =>
+      index === lastAssistantIndex
+        ? { ...entry, finishedAt: event.timestamp }
+        : entry,
+    );
+  }
+
   if (HIDDEN_EVENT_TYPES.has(event.type)) return entries;
```

### 1.6 Message list: split user vs assistant rendering

Replace the whole `{(entry.parts ?? []).map((part, partIndex) => { … })}` block
(which handled `text` / `reasoning` / `tool` inline) with:

```tsx
                    {entry.role === "user"
                      ? (entry.parts ?? []).map((part, partIndex) =>
                          part.type === "text" ? (
                            <div
                              className="whitespace-pre-wrap break-words"
                              key={`${entry.id}-${partIndex}`}
                            >
                              {part.text}
                            </div>
                          ) : null,
                        )
                      : (
                          <AssistantEntryBody
                            entry={entry}
                            sessionId={sessionId}
                            isLastEntry={entryIndex === displayed.length - 1}
                            isStreaming={isStreaming}
                            nextEntryTimestamp={displayed[entryIndex + 1]?.timestamp}
                          />
                        )}
```

### 1.7 Pending reasoning row (source's `PendingAgentReasoning`)

Replace "Streaming indicator — HackerAI-style dots" (`Agent is working…`) with:

```tsx
            {/* Pending agent reasoning — HackerAI's PendingAgentReasoning row */}
            {isStreaming && displayed.at(-1)?.role !== "assistant" && (
              <div
                aria-label="Thinking"
                className="flex w-full max-w-full items-center gap-2 text-sm text-muted-foreground"
                data-testid="pending-agent-reasoning"
                role="status"
              >
                <BrainIcon className="size-4 shrink-0" />
                <Shimmer
                  as="span"
                  className="min-w-0 truncate text-left text-sm leading-5"
                >
                  Thinking...
                </Shimmer>
              </div>
            )}
```

### 1.8 New `AssistantEntryBody` component + `buildWorkItems`

Insert **before** the line
`// ─── ToolExecutionPart — HackerAI AgentToolGroupRow style ────────────────────`

```tsx
// ─── AssistantEntryBody — HackerAI MessageItem / WorkedFor parity ────────────

type WorkItem =
  | { kind: "reasoning"; key: string; activity: string }
  | { kind: "tool"; key: string; part: ToolPart };

/**
 * buildWorkItems — mirrors HackerAI's `splitWorkedForParts` projection.
 *
 * Consecutive `agent_reasoning` events are merged into one reasoning block, the
 * way HackerAI's ReasoningHandler collects every consecutive reasoning part from
 * the first one onward. That yields a single live "Thinking..." row that grows
 * token by token instead of a stack of one-line rows per event.
 */
function buildWorkItems(entry: ChatEntry): WorkItem[] {
  const parts = entry.parts ?? [];
  const items: WorkItem[] = [];

  parts.forEach((part, index) => {
    if (part.type === "reasoning") {
      // Only the first part of a consecutive reasoning run renders.
      if (parts[index - 1]?.type === "reasoning") return;
      const lines: string[] = [part.activity];
      for (let next = index + 1; next < parts.length; next++) {
        const candidate = parts[next];
        if (candidate?.type !== "reasoning") break;
        lines.push(candidate.activity);
      }
      items.push({
        kind: "reasoning",
        key: `${entry.id}-reasoning-${index}`,
        activity: lines
          .map((line) => line.trim())
          .filter(Boolean)
          .join("\n\n"),
      });
      return;
    }
    if (part.type === "tool") {
      items.push({ kind: "tool", key: part.toolCallId, part });
    }
  });

  return items;
}

interface AssistantEntryBodyProps {
  entry: ChatEntry;
  sessionId: string;
  isLastEntry: boolean;
  isStreaming: boolean;
  /** Timestamp of the next entry — used as the end time for restored history. */
  nextEntryTimestamp?: string;
}

/**
 * Renders one assistant turn the way HackerAI's MessageItem does: every work
 * part (reasoning + tools) folded into a single collapsible
 * "Working for 12s" / "Worked for 12s" trigger, with the final answer text
 * streamed underneath it.
 */
function AssistantEntryBody({
  entry,
  sessionId,
  isLastEntry,
  isStreaming,
  nextEntryTimestamp,
}: AssistantEntryBodyProps) {
  const workItems = buildWorkItems(entry);
  const textParts = (entry.parts ?? []).filter(
    (part): part is TextPart => part.type === "text",
  );

  // HackerAI only makes the trigger clickable when there is expandable work.
  const hasExpandableWork = workItems.some((item) => item.kind === "tool");
  const startedAt = Date.parse(entry.timestamp);
  const finishedSource = entry.finishedAt ?? nextEntryTimestamp;
  const finishedAt = finishedSource ? Date.parse(finishedSource) : NaN;
  const durationMs =
    Number.isFinite(startedAt) && Number.isFinite(finishedAt)
      ? Math.max(0, finishedAt - startedAt)
      : undefined;
  const isTiming = isStreaming && isLastEntry;
  const lastReasoningItemIndex = workItems.reduceRight(
    (found, item, index) =>
      found === -1 && item.kind === "reasoning" ? index : found,
    -1,
  );

  const renderWorkItems = () =>
    workItems.map((item, index) =>
      item.kind === "reasoning" ? (
        <SvsCyberReasoningPart
          key={item.key}
          activity={item.activity}
          isStreaming={isStreaming}
          isLatest={isTiming && index === lastReasoningItemIndex}
        />
      ) : (
        <ToolExecutionPart
          key={item.key}
          part={item.part}
          sessionId={sessionId}
        />
      ),
    );

  return (
    <>
      {workItems.length > 0 && (
        <WorkedFor
          hasWork={hasExpandableWork}
          defaultOpen={isTiming}
          isTiming={isTiming}
        >
          <WorkedForTrigger
            isTiming={isTiming}
            startedAt={Number.isFinite(startedAt) ? startedAt : undefined}
            durationMs={durationMs}
          />
          <WorkedForContent>{renderWorkItems()}</WorkedForContent>
        </WorkedFor>
      )}

      {textParts.map((part, index) => (
        <MemoizedMarkdown
          key={`${entry.id}-text-${index}`}
          content={part.text}
          // HackerAI parity (MessagePartHandler): only the message currently
          // streaming animates, which is what produces the token-by-token
          // fade-in that looks like the model typing.
          isAnimating={isStreaming && isLastEntry}
        />
      ))}
    </>
  );
}
```

---

## File 2 — `ui/hackerai/app/components/SvsCyberReasoningPart.tsx`

```diff
   if (!showBounded) {
-    return <MemoizedMarkdown content={content} />;
+    // `isAnimating` keeps the streamdown token animation running while the
+    // agent is still producing reasoning, so the text fades in word by word
+    // instead of appearing all at once.
+    return <MemoizedMarkdown content={content} isAnimating={isStreaming} />;
   }
```

---

## Not yet done (next steps once the tree is restored)

- Turn consolidation in `applyEvent`: one assistant entry per turn (reasoning, tools and
  the final `response` text currently land in separate entries, so a turn can render as
  two or three bubbles). Needs a `currentTurnAssistantIndex()` guard so reasoning/tools/text
  append to the assistant entry that follows the last user message.
- Swap the hand-rolled `ToolExecutionPart` for the source's `AgentActivityRow` /
  `AgentToolGroupRow`, and add the source's `MessageActions` (copy / retry) row.
- Composer chrome parity: `ChatInput`'s attachment / mode / permission / sandbox controls,
  the `chat-input-glass-context` strip and `ScrollToBottomButton`.
- Decide the fate of the fork-only header ("Live" dot) and the activity chip strip, which
  the source does not have.
