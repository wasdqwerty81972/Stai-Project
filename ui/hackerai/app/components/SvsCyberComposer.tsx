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
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";
import TextareaAutosize from "react-textarea-autosize";
import { ArrowUp, Square, Plus, Terminal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SvsCyberModelSelector } from "./SvsCyberModelSelector";
import type { SelectedModel } from "@/app/contexts/StaiGlobalState";
import { useHotkeys } from "react-hotkeys-hook";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Brain, ChevronDown } from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

export type SvsStatus = "ready" | "submitted" | "streaming" | "error";
export type SvsReasoningLevel = "low" | "medium" | "high";

export interface SvsCommand {
  name: string;
  description: string;
  argument_hint?: string;
}

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
  selectedModel?: SelectedModel;
  onModelChange?: (model: SelectedModel) => void;
  reasoningLevel?: SvsReasoningLevel;
  onReasoningLevelChange?: (level: SvsReasoningLevel) => void;
  /** Whether to show on landing (centered) */
  isCentered?: boolean;
  /** Slash commands made available by the SVS-Cyber command registry. */
  commands?: SvsCommand[];
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
  selectedModel = "auto",
  onModelChange,
  reasoningLevel = "medium",
  onReasoningLevelChange,
  isCentered = false,
  commands = [],
}: SvsCyberComposerProps) {
  const isGenerating = status === "submitted" || status === "streaming";
  const isStopping = useRef(false);
  const [isFocused, setIsFocused] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [selectedCommandIndex, setSelectedCommandIndex] = useState(0);
  const [commandMenuDismissed, setCommandMenuDismissed] = useState(false);
  const commandQuery = value.match(/^\/([^\s]*)$/)?.[1]?.toLowerCase();
  const matchingCommands = useMemo(
    () =>
      commandQuery === undefined
        ? []
        : commands
            .filter((command) =>
              `${command.name} ${command.description}`
                .toLowerCase()
                .includes(commandQuery),
            )
            .sort((left, right) => {
              const rank = (command: SvsCommand) => {
                const name = command.name.toLowerCase();
                if (name === commandQuery) return 0;
                if (name.startsWith(commandQuery)) return 1;
                return 2;
              };
              return rank(left) - rank(right);
            })
            .slice(0, 6),
    [commands, commandQuery],
  );
  const showCommandMenu =
    !isGenerating &&
    !commandMenuDismissed &&
    commandQuery !== undefined &&
    matchingCommands.length > 0;

  useEffect(() => {
    setSelectedCommandIndex(0);
    setCommandMenuDismissed(false);
  }, [value]);

  const selectCommand = useCallback(
    (command: SvsCommand) => {
      onChange(`/${command.name} `);
      textareaRef.current?.focus();
    },
    [onChange],
  );

  // Ctrl+C to stop — matches HackerAI SubmitStopButton while preserving normal text copy
  useHotkeys(
    "ctrl+c",
    (e) => {
      // If user has highlighted text (e.g. copying text in textarea or page), don't stop generation
      const selection =
        typeof window !== "undefined" ? window.getSelection()?.toString() : "";
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
  const draftKey = `svs_draft_${chatId || "landing"}`;

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
      if (showCommandMenu) {
        if (e.key === "ArrowDown") {
          e.preventDefault();
          setSelectedCommandIndex((index) =>
            Math.min(index + 1, matchingCommands.length - 1),
          );
          return;
        }
        if (e.key === "ArrowUp") {
          e.preventDefault();
          setSelectedCommandIndex((index) => Math.max(index - 1, 0));
          return;
        }
        if (e.key === "Escape") {
          e.preventDefault();
          setCommandMenuDismissed(true);
          return;
        }
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          const command = matchingCommands[selectedCommandIndex];
          if (command) selectCommand(command);
          return;
        }
      }
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        if (status === "ready" && value.trim()) {
          e.currentTarget.form?.requestSubmit();
        }
      }
    },
    [
      matchingCommands,
      selectedCommandIndex,
      selectCommand,
      showCommandMenu,
      status,
      value,
    ],
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

  const effectivePlaceholder = placeholder ?? "Tell SVS-Cyber what you need…";

  return (
    /* Matches HackerAI: relative px-4 pb-3 wrapper */
    <div className={`relative min-w-0 px-4 ${isCentered ? "" : "pb-3"}`}>
      <div className="mx-auto w-full min-w-0 max-w-full sm:min-w-[390px] sm:max-w-[768px]">
        <form onSubmit={handleSubmit}>
          <div
            className={`
              relative z-10 bg-transparent
              flex min-h-[76px] max-h-[300px] flex-col rounded-[20px]
              border border-black/8 dark:border-border
              shadow-[0px_12px_32px_0px_rgba(0,0,0,0.02)] transition-all duration-150
              ${
                isFocused
                  ? "ring-2 ring-ring/30 border-ring/40 dark:border-ring/40"
                  : ""
              }
              ${isGenerating ? "opacity-80 cursor-not-allowed" : ""}
            `}
          >
            {/* Textarea row — matches HackerAI ChatInputTextarea wrapper */}
            <div
              className={`relative overflow-y-auto pl-4 pr-12 pt-3 pb-1.5 flex-1 ${
                isGenerating ? "pointer-events-none" : ""
              }`}
            >
              {showCommandMenu && (
                <div
                  className="mb-2 overflow-hidden rounded-xl border border-border/60 bg-background/95 shadow-lg backdrop-blur-xl"
                  role="listbox"
                  aria-label="Commands"
                >
                  <div className="flex items-center gap-2 border-b border-border/50 px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                    <Terminal className="size-3" /> Commands
                    <span className="ml-auto normal-case tracking-normal">
                      ↑↓ select · Enter apply
                    </span>
                  </div>
                  {matchingCommands.map((command, index) => (
                    <button
                      key={command.name}
                      type="button"
                      role="option"
                      aria-selected={index === selectedCommandIndex}
                      className={[
                        "flex w-full items-center gap-3 px-3 py-2 text-left transition-colors",
                        index === selectedCommandIndex
                          ? "bg-primary/10 text-foreground"
                          : "text-muted-foreground hover:bg-muted/70 hover:text-foreground",
                      ].join(" ")}
                      onMouseDown={(event) => event.preventDefault()}
                      onClick={() => selectCommand(command)}
                    >
                      <code className="rounded bg-muted px-1.5 py-0.5 text-xs font-semibold text-foreground">
                        /{command.name}
                      </code>
                      <span className="min-w-0 flex-1 truncate text-xs">
                        {command.description}
                      </span>
                      {command.argument_hint && (
                        <span className="shrink-0 text-[11px] text-muted-foreground/80">
                          {command.argument_hint}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              )}
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
              {isGenerating ? (
                <Button
                  type="button"
                  onClick={() => void handleStop()}
                  variant="ghost"
                  className={`${BASE_BUTTON_CLASSES} absolute bottom-1.5 right-3 bg-muted hover:bg-muted/70 text-foreground`}
                  aria-label="Stop generation"
                  data-testid="stop-button"
                >
                  <Square className="w-[15px] h-[15px]" fill="currentColor" />
                </Button>
              ) : (
                <Button
                  type="submit"
                  disabled={!canSend}
                  variant="default"
                  className={`${BASE_BUTTON_CLASSES} absolute bottom-1.5 right-3`}
                  aria-label="Send message"
                  data-testid="send-button"
                >
                  <ArrowUp size={15} strokeWidth={3} />
                </Button>
              )}
            </div>

            <div className="flex min-w-0 items-center gap-2 px-3 pb-2 pt-0">
              <div className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden">
                <button
                  type="button"
                  disabled
                  className="flex h-7 items-center justify-center rounded-full px-2 text-muted-foreground opacity-50"
                  aria-label="Attach files (coming soon)"
                  data-testid="attachment-button"
                >
                  <Plus className="size-3.5" />
                </button>
                {onModelChange && (
                  <SvsCyberModelSelector
                    value={selectedModel}
                    onChange={onModelChange}
                    disabled={isGenerating}
                  />
                )}
                {onReasoningLevelChange && (
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild disabled={isGenerating}>
                      <button
                        type="button"
                        className="flex h-7 items-center gap-1.5 rounded-full border border-transparent px-2.5 text-xs font-medium text-muted-foreground transition-colors hover:border-border/50 hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
                        aria-label={`Reasoning: ${reasoningLevel}. Click to change.`}
                        data-testid="reasoning-level-selector"
                      >
                        <Brain className="size-3 shrink-0" aria-hidden="true" />
                        <span>Reasoning: {reasoningLevel}</span>
                        <ChevronDown
                          className="size-3 shrink-0 opacity-60"
                          aria-hidden="true"
                        />
                      </button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent
                      align="start"
                      sideOffset={6}
                      className="w-48 p-1"
                    >
                      <DropdownMenuLabel className="px-2 py-1 text-xs font-medium text-muted-foreground">
                        Reasoning level
                      </DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      {(["low", "medium", "high"] as const).map((level) => (
                        <DropdownMenuItem
                          key={level}
                          onSelect={() => onReasoningLevelChange(level)}
                          className="cursor-pointer capitalize"
                          data-testid={`reasoning-level-option-${level}`}
                        >
                          {level}
                          {reasoningLevel === level ? " · selected" : ""}
                        </DropdownMenuItem>
                      ))}
                    </DropdownMenuContent>
                  </DropdownMenu>
                )}
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
