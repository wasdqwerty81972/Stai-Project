"use client";

/**
 * SvsCyberReasoningPart — HackerAI ReasoningHandler ported for SVS-Cyber.
 *
 * Ported from:
 *   app/components/ReasoningHandler.tsx
 *   components/ai-elements/reasoning.tsx
 *
 * Renders agent_reasoning events from the SVS-Cyber backend as the HackerAI
 * collapsible reasoning row:
 *   - BrainIcon + "Thinking..." shimmer text when actively streaming
 *   - Collapse/expand chevron
 *   - Long-content tail preview (12k chars) with "Show full reasoning" button
 *   - Fades in/out on open/close
 *
 * SECURITY: Only renders `activity` (the user-visible message from
 * agent_reasoning events). NEVER renders system prompts, credentials, hidden
 * chain-of-thought, or private model internals.
 */

import { memo, useState } from "react";
import {
  Reasoning,
  ReasoningContent,
  ReasoningTrigger,
} from "@/components/ai-elements/reasoning";
import { MemoizedMarkdown } from "./MemoizedMarkdown";

// ─── Constants (same as HackerAI ReasoningHandler) ───────────────────────────

const LONG_REASONING_THRESHOLD = 12_000;
const LONG_REASONING_TAIL_LENGTH = 6_000;

const getReasoningTail = (content: string): string => {
  const tail = content.slice(-LONG_REASONING_TAIL_LENGTH);
  const firstNewline = tail.indexOf("\n");
  return firstNewline >= 0 ? tail.slice(firstNewline + 1) : tail;
};

// ─── Sub-component: ReasoningBody (direct port from ReasoningHandler.tsx) ────

const ReasoningBody = memo(function ReasoningBody({
  content,
  isStreaming,
}: {
  content: string;
  isStreaming: boolean;
}) {
  const [showFull, setShowFull] = useState(false);
  const isLong = content.length > LONG_REASONING_THRESHOLD;
  const showBounded = isLong && (isStreaming || !showFull);

  if (!showBounded) {
    // `isAnimating` keeps the streamdown token animation running while the
    // agent is still producing reasoning, so the text fades in word by word
    // instead of appearing all at once.
    return <MemoizedMarkdown content={content} isAnimating={isStreaming} />;
  }

  return (
    <div className="space-y-2" data-testid="long-reasoning-preview">
      <p className="text-xs text-muted-foreground/80">
        {isStreaming
          ? "Showing the latest reasoning while it runs to keep the chat responsive."
          : "Showing the latest section of this long reasoning to keep the chat responsive."}
      </p>
      <div
        className="whitespace-pre-wrap break-words [overflow-wrap:anywhere]"
        data-testid="long-reasoning-preview-body"
      >
        {getReasoningTail(content)}
      </div>
      {!isStreaming && (
        <button
          type="button"
          className="text-xs text-foreground/80 underline-offset-4 hover:text-foreground hover:underline"
          onClick={() => setShowFull(true)}
        >
          Show full reasoning
        </button>
      )}
    </div>
  );
});

// ─── Main export ─────────────────────────────────────────────────────────────

interface SvsCyberReasoningPartProps {
  /**
   * The user-visible reasoning/activity text.
   * Only safe, user-visible activity — never system prompts or private CoT.
   * Comes from agent_reasoning event.message in the SVS-Cyber backend.
   */
  activity: string;
  /** True while the agent is actively running and streaming this reasoning */
  isStreaming: boolean;
  /** True if this is the last (most recent) reasoning block */
  isLatest?: boolean;
}

export const SvsCyberReasoningPart = memo(function SvsCyberReasoningPart({
  activity,
  isStreaming,
  isLatest = false,
}: SvsCyberReasoningPartProps) {
  // Don't show empty or redacted reasoning
  if (!activity || !activity.trim()) return null;

  const isActivelyReasoning = isStreaming && isLatest;
  const autoOpen = isStreaming && isLatest;

  return (
    <Reasoning
      className="w-full"
      isStreaming={autoOpen}
      isActive={isActivelyReasoning}
      collapseWhenInactive={isStreaming}
    >
      <ReasoningTrigger />
      <ReasoningContent>
        <ReasoningBody content={activity} isStreaming={isStreaming} />
      </ReasoningContent>
    </Reasoning>
  );
});
