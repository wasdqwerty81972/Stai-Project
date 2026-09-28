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
import { ArrowUp, Square, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useHotkeys } from "react-hotkeys-hook";
import { SvsCyberModelSelector } from "./SvsCyberModelSelector";
import type { ChatMode, SelectedModel } from "@/app/contexts/StaiGlobalState";

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
  /** Placeholder text (overrides chatMode default if provided) */
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
  /** Chat mode: "agent" (autonomous with tools) or "ask" (fast Q&A) */
  chatMode?: ChatMode;
  /** Called when the user toggles chat mode */
  onChatModeChange?: (mode: ChatMode) => void;
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
  placeholder,
  autoFocus = true,
  chatId,
  selectedModel = "gemini",
  onModelChange,
  isCentered = false,
  chatMode = "agent",
  onChatModeChange,
}: SvsCyberComposerProps) {
  const isGenerating = status === "submitted" || status === "streaming";
  const isStopping = useRef(false);
  const [isFocused, setIsFocused] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

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

  // ─── Draft persistence to localStorage ─────────────────────────────────────
  const DRAFT_TTL = 7 * 24 * 60 * 60 * 1000;
  const draftKey = `svs_draft_${chatId || 'landing'}`;

  useEffect(() => {
    if (debounceTimer.current) {
      clearTimeout(debounceTimer.current);
    }
    debounceTimer.current = setTimeout(() => {
      try {
        localStorage.setItem(
          draftKey,
          JSON.stringify({ content: value, timestamp: Date.now() }),
        );
      } catch {
        // ignore localStorage errors (quota, private mode, etc.)
      }
    }, 500);
    return () => {
      if (debounceTimer.current) {
        clearTimeout(debounceTimer.current);
      }
    };
  }, [value, draftKey]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(draftKey);
      if (raw) {
        const parsed = JSON.parse(raw) as {
          content: string;
          timestamp: number;
        };
        const age = Date.now() - parsed.timestamp;
        if (age <= DRAFT_TTL && typeof parsed.content === "string") {
          onChange(parsed.content);
        } else if (age > DRAFT_TTL) {
          localStorage.removeItem(draftKey);
        }
      }
    } catch {
      // ignore malformed stored drafts
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draftKey]);

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
      try {
        localStorage.removeItem(draftKey);
      } catch {
        // ignore
      }
      void onSubmit(e);
    },
    [isGenerating, onSubmit, value, draftKey],
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

  const effectivePlaceholder =
    placeholder ??
    (chatMode === "ask"
      ? "Ask SVS-Cyber a quick question…"
      : "Tell SVS-Cyber to investigate your target…");

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
              ${
                isGenerating
                  ? "opacity-80 cursor-not-allowed"
                  : ""
              }
            `}
          >
            {/* Textarea row — matches HackerAI ChatInputTextarea wrapper */}
            <div
              className={`overflow-y-auto pl-4 pr-12 pt-3.5 pb-3 flex-1 ${
                isGenerating ? "pointer-events-none" : ""
              }`}
            >
              <TextareaAutosize
                ref={textareaRef}
                value={value}
                onChange={(e) => onChange(e.target.value)}
                onKeyDown={handleKeyDown}
                onFocus={() => setIsFocused(true)}
                onBlur={() => setIsFocused(false)}
                placeholder={effectivePlaceholder}
                disabled={isGenerating}
                autoFocus={autoFocus}
                minRows={1}
                data-testid="chat-input"
                className="
                  flex rounded-md border-input
                  focus-visible:outline-none focus-visible:ring-ring
                  disabled:cursor-not-allowed disabled:opacity-50
                  overflow-hidden flex-1 bg-transparent p-0 py-0.5 pr-1
                  border-0 focus-visible:ring-0 focus-visible:ring-offset-0
                  w-full placeholder:text-muted-foreground text-base
                  shadow-none resize-none min-h-[28px]
                "
              />
            </div>

            {/* Toolbar row — attachment, chat mode, model selector + send/stop button */}
            <div className="flex min-w-0 items-center gap-2 px-3 pb-3 pt-1">
              {/* Left: attachment button + chat mode toggle + model selector */}
              <div className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden">
                <TooltipProvider delayDuration={150}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <button
                        type="button"
                        onClick={() => {
                          // Wiring SVS file upload handler after backend endpoint is added
                        }}
                        disabled={true}
                        className="
                          flex h-7 items-center justify-center gap-1.5 rounded-full px-2 py-1 text-xs font-medium
                          bg-transparent text-muted-foreground
                          border border-transparent
                          transition-colors duration-150
                          hover:bg-accent hover:text-accent-foreground hover:border-border/50
                          focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring
                          opacity-50 cursor-not-allowed
                        "
                        aria-label="Attach files (coming soon)"
                        data-testid="attachment-button"
                      >
                        <Plus className="size-3.5 shrink-0" />
                      </button>
                    </TooltipTrigger>
                    <TooltipContent side="top" className="text-xs">
                      Attach files (coming soon)
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>

                {onChatModeChange && (
                  <div
                    className="
                      inline-flex h-7 items-center rounded-full
                      bg-muted/50 p-0.5
                      border border-border/40
                    "
                    role="group"
                    aria-label="Chat mode toggle"
                    data-testid="chat-mode-toggle"
                  >
                    <button
                      type="button"
                      onClick={() => onChatModeChange("ask")}
                      className={[
                        "rounded-full px-2 py-1 text-xs font-medium transition-colors duration-150",
                        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-0",
                        chatMode === "ask"
                          ? "bg-background shadow-sm text-foreground border border-border/60"
                          : "text-muted-foreground hover:text-foreground",
                      ].join(" ")}
                      aria-pressed={chatMode === "ask"}
                    >
                      Ask
                      <span className="ml-1 text-[10px] font-normal opacity-60">fast</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => onChatModeChange("agent")}
                      className={[
                        "rounded-full px-2 py-1 text-xs font-medium transition-colors duration-150",
                        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-0",
                        chatMode === "agent"
                          ? "bg-background shadow-sm text-foreground border border-border/60"
                          : "text-muted-foreground hover:text-foreground",
                      ].join(" ")}
                      aria-pressed={chatMode === "agent"}
                    >
                      Agent
                      <span className="ml-1 text-[10px] font-normal opacity-60">tools</span>
                    </button>
                  </div>
                )}

                {onModelChange && (
                  <SvsCyberModelSelector
                    value={selectedModel}
                    onChange={onModelChange}
                    disabled={isGenerating}
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
