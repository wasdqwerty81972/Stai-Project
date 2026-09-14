"use client";

/**
 * SvsCyberComposer — HackerAI ChatInput ported for SVS-Cyber.
 *
 * This is a DIRECT PORT of the HackerAI ChatInput JSX structure:
 * - Same glass surface (`chat-input-glass-surface` CSS class from globals.css)
 * - Same rounded-[22px] container shape
 * - Same min-height / max-height constraints
 * - Same border / shadow treatment
 * - TextareaAutosize with min 1 row, max ~240px
 * - Enter to send, Shift+Enter for newline
 * - ArrowUp send button (rounded-full, w-8 h-8) from SubmitStopButton
 * - Square stop button when generating
 * - Focus glow from HackerAI globals.css chat-input-glass-surface
 *
 * Only changed from original:
 * - Removed Convex, WorkOS, file upload, queued messages, approval prompt
 * - State is passed directly via props from StaiChatWorkspace
 * - Model selector uses SVS-Cyber models (SvsCyberModelSelector)
 * - onStop calls the real SVS-Cyber cancellation endpoint
 */

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import TextareaAutosize from "react-textarea-autosize";
import { ArrowUp, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useHotkeys } from "react-hotkeys-hook";
import { SvsCyberModelSelector } from "./SvsCyberModelSelector";
import type { SelectedModel } from "@/app/contexts/StaiGlobalState";

// ─── Types ────────────────────────────────────────────────────────────────────

export type SvsStatus = "ready" | "submitted" | "streaming" | "error";

interface SvsCyberComposerProps {
  /** Current text draft */
  value: string;
  onChange: (value: string) => void;
  /** Called when the user submits (Enter / Send button) */
  onSubmit: (e: FormEvent) => void | Promise<void>;
  /** Called when the user clicks Stop */
  onStop: () => void | Promise<void>;
  /** "ready" | "submitted" | "streaming" */
  status: SvsStatus;
  /** Placeholder text */
  placeholder?: string;
  /** Whether to auto-focus on mount */
  autoFocus?: boolean;
  /** Current investigation/chat id */
  chatId?: string;
  /** Selected model */
  selectedModel?: SelectedModel;
  onModelChange?: (model: SelectedModel) => void;
  /** Whether to show on landing (centered) */
  isCentered?: boolean;
}

// ─── Constants matching HackerAI exactly ─────────────────────────────────────

const BASE_BUTTON_CLASSES = "rounded-full p-0 w-8 h-8 min-w-0";

// ─── Component ────────────────────────────────────────────────────────────────

export function SvsCyberComposer({
  value,
  onChange,
  onSubmit,
  onStop,
  status,
  placeholder = "Message the SVS-Cyber agent",
  autoFocus = true,
  selectedModel = "gemini",
  onModelChange,
  isCentered = false,
}: SvsCyberComposerProps) {
  const isGenerating = status === "submitted" || status === "streaming";
  const isStopping = useRef(false);
  const [isFocused, setIsFocused] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Ctrl+C to stop — matches HackerAI SubmitStopButton while preserving normal text copy
  useHotkeys(
    "ctrl+c",
    (e) => {
      // If user has highlighted text (e.g. copying text in textarea or page), don't stop generation
      const selection = typeof window !== "undefined" ? window.getSelection()?.toString() : "";
      if (selection && selection.length > 0) {
        return;
      }
      e.preventDefault();
      void onStop();
    },
    {
      enabled: isGenerating,
      enableOnFormTags: true,
      enableOnContentEditable: true,
      preventDefault: true,
      description: "Stop agent",
    },
    [isGenerating, onStop],
  );

  // Reset stopping state when generation finishes
  useEffect(() => {
    if (!isGenerating) {
      isStopping.current = false;
    }
  }, [isGenerating]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        if (status === "ready" && value.trim()) {
          e.currentTarget.form?.requestSubmit();
        }
      }
    },
    [status, value],
  );

  const handleSubmit = useCallback(
    (e: FormEvent) => {
      e.preventDefault();
      if (isGenerating || !value.trim()) return;
      void onSubmit(e);
    },
    [isGenerating, onSubmit, value],
  );

  const handleStop = useCallback(async () => {
    if (isStopping.current) return;
    isStopping.current = true;
    try {
      await onStop();
    } catch {
      isStopping.current = false;
    }
  }, [onStop]);

  const canSend = status === "ready" && value.trim().length > 0;

  return (
    /* Matches HackerAI: relative px-4 pb-3 wrapper */
    <div className={`relative min-w-0 px-4 ${isCentered ? "" : "pb-3"}`}>
      <div className="mx-auto w-full min-w-0 max-w-full sm:min-w-[390px] sm:max-w-[768px]">
        <form onSubmit={handleSubmit}>
          {/*
            HackerAI glass surface container:
            - chat-input-glass-surface = frosted glass background (defined in globals.css)
            - rounded-[22px] = exact HackerAI composer shape
            - border border-black/8 dark:border-border = HackerAI border
            - shadow-[0px_12px_32px_0px_rgba(0,0,0,0.02)] = HackerAI shadow
            - focus-within ring mirrors HackerAI focus highlight
          */}
          <div
            className={`
              chat-input-glass-surface
              relative z-10
              flex min-h-[98px] max-h-[300px] flex-col
              rounded-[22px]
              border border-black/8 dark:border-border
              shadow-[0px_12px_32px_0px_rgba(0,0,0,0.02)]
              transition-all duration-150
              ${
                isFocused
                  ? "ring-2 ring-ring/30 border-ring/40 dark:border-ring/40"
                  : ""
              }
            `}
          >
            {/* Textarea row — matches HackerAI ChatInputTextarea wrapper */}
            <div className="overflow-y-auto pl-4 pr-2 pt-3 flex-1">
              <TextareaAutosize
                ref={textareaRef}
                value={value}
                onChange={(e) => onChange(e.target.value)}
                onKeyDown={handleKeyDown}
                onFocus={() => setIsFocused(true)}
                onBlur={() => setIsFocused(false)}
                placeholder={placeholder}
                disabled={isGenerating}
                autoFocus={autoFocus}
                minRows={1}
                data-testid="chat-input"
                className="
                  flex rounded-md border-input
                  focus-visible:outline-none focus-visible:ring-ring
                  disabled:cursor-not-allowed disabled:opacity-50
                  overflow-hidden flex-1 bg-transparent p-0 pt-[1px]
                  border-0 focus-visible:ring-0 focus-visible:ring-offset-0
                  w-full placeholder:text-muted-foreground text-base
                  shadow-none resize-none min-h-[28px]
                "
              />
            </div>

            {/* Toolbar row — model selector + send/stop button */}
            <div className="flex min-w-0 items-center gap-2 px-3 pb-3 pt-1">
              {/* Left: model selector */}
              <div className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden">
                {onModelChange && (
                  <SvsCyberModelSelector
                    value={selectedModel}
                    onChange={onModelChange}
                  />
                )}
              </div>

              {/* Right: send / stop */}
              <div className="flex shrink-0 items-center gap-2 ml-auto">
                {isGenerating ? (
                  /* Stop button — matches HackerAI SubmitStopButton stop state */
                  <Button
                    type="button"
                    onClick={() => void handleStop()}
                    variant="ghost"
                    className={`
                      ${BASE_BUTTON_CLASSES}
                      bg-muted hover:bg-muted/70 text-foreground
                    `}
                    aria-label="Stop generation"
                    title="Stop (⌃C)"
                    data-testid="stop-button"
                  >
                    <Square className="w-[15px] h-[15px]" fill="currentColor" />
                  </Button>
                ) : (
                  /* Send button — matches HackerAI SubmitStopButton send state */
                  <Button
                    type="submit"
                    disabled={!canSend}
                    variant="default"
                    className={`${BASE_BUTTON_CLASSES}`}
                    aria-label="Send message"
                    title="Send (⏎)"
                    data-testid="send-button"
                  >
                    <ArrowUp size={15} strokeWidth={3} />
                  </Button>
                )}
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
