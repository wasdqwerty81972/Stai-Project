"use client";

/**
 * StaiChatWorkspace — SVS-Cyber main chat workspace.
 *
 * Architecture:
 *   StaiGlobalStateProvider (lightweight Convex-free GlobalState)
 *     └─ ToolWorkspaceProvider (right-side panel)
 *        └─ StaiChatWorkspaceContent
 *              ├─ Sidebar (investigations list)
 *              ├─ Main chat column
 *              │    ├─ Header (title + connection status)
 *              │    ├─ Activity strip (agent work header)
 *              │    ├─ Message list
 *              │    │    ├─ User bubbles
 *              │    │    ├─ Assistant responses (MemoizedMarkdown)
 *              │    │    ├─ SvsCyberReasoningPart (HackerAI reasoning UI)
 *              │    │    └─ ToolExecutionPart (HackerAI tool group style)
 *              │    └─ SvsCyberComposer (HackerAI glass surface composer)
 *              └─ ToolWorkspaceContainer (right-side panel)
 *
 * MESSAGE ORDERING FIX:
 *   All entries carry a `timestamp` ISO string.
 *   Before rendering, entries are sorted by timestamp ascending.
 *   Optimistic user messages use Date.now() so they always appear before
 *   any assistant response that arrives later.
 *   When the server confirms the real user_event_id, we replace the
 *   optimistic entry in-place without reordering.
 */

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  BrainIcon,
  Globe,
  PanelLeft,
  PanelLeftClose,
  Radar,
  Search,
  Shield,
  SquarePen,
  Terminal,
  Wrench,
  FileText,
} from "lucide-react";
import { MemoizedMarkdown } from "./MemoizedMarkdown";
import ToolBlock from "@/components/ui/tool-block";
import {
  ToolWorkspaceProvider,
  useToolWorkspace,
} from "@/app/contexts/ToolWorkspaceContext";
import { ToolWorkspaceContainer } from "./ToolWorkspaceContainer";
import type { ToolWorkspaceContent } from "@/app/contexts/ToolWorkspaceContext";
import {
  getStaiMessages,
  getStaiConversations,
  clearStaiConversations,
  openStaiEvents,
  respondToStaiApproval,
  sendStaiMessage,
  cancelStaiRun,
  type StaiAgentEvent,
} from "@/lib/stai-api";
import { StaiGlobalStateProvider } from "@/app/contexts/StaiGlobalState";
import type { SelectedModel } from "@/app/contexts/StaiGlobalState";
import { SvsCyberComposer } from "./SvsCyberComposer";
import type { SvsStatus } from "./SvsCyberComposer";
import { SvsCyberReasoningPart } from "./SvsCyberReasoningPart";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Shimmer } from "@/components/ai-elements/shimmer";
import {
  WorkedFor,
  WorkedForContent,
  WorkedForTrigger,
} from "@/components/ai-elements/worked-for";

// ─── Types ────────────────────────────────────────────────────────────────────

interface TextPart {
  type: "text";
  text: string;
}

interface ReasoningPart {
  type: "reasoning";
  /** User-visible activity text only — never private chain-of-thought */
  activity: string;
}

interface ToolPart {
  type: "tool";
  toolCallId: string;
  toolName: string;
  state:
    | "input-streaming"
    | "input-available"
    | "approval-requested"
    | "approval-responded"
    | "output-available"
    | "output-error";
  input?: Record<string, unknown>;
  output?: unknown;
  progress?: number;
  elapsedSeconds?: number;
  errorText?: string;
  approval?: { requestId?: string; approved?: boolean };
}

type MessagePart = TextPart | ReasoningPart | ToolPart;

interface ChatEntry {
  id: string;
  role: "user" | "assistant" | "event";
  parts: MessagePart[];
  /** ISO timestamp for chronological sorting */
  timestamp: string;
  /**
   * ISO timestamp stamped when the run finished. Feeds HackerAI's
   * "Worked for 12s" trigger (see WorkedForTrigger durationMs).
   */
  finishedAt?: string;
  animate?: boolean;
}

interface ConversationSummary {
  id: string;
  title: string;
  last_message?: string;
  timestamp: string;
}

interface ActivityEvent {
  id: string;
  label: string;
  detail: string;
  status: "running" | "completed" | "failed" | "info";
  startedAt?: number;
}

// ─── Event filter ─────────────────────────────────────────────────────────────

const HIDDEN_EVENT_TYPES = new Set([
  "investigation_started",
  "agent_started",
  "model_info",
  "agent_completed",
  "agent_failed",
  "workflow_agent_completed",
  "investigation_completed",
  "context_usage",
  "state",
  "conversation_title",
  "finding_created",
  // agent_reasoning is handled separately as a ReasoningPart
]);

/**
 * Events that end a run. They do not produce their own entry; they stamp the
 * assistant entry's `finishedAt` so the work trigger can show a real duration
 * (HackerAI's `generationTimeMs`).
 */
const TERMINAL_RUN_EVENT_TYPES = new Set([
  "agent_completed",
  "agent_failed",
  "workflow_agent_completed",
  "investigation_completed",
]);

// ─── Helper functions ─────────────────────────────────────────────────────────

function toolId(event: StaiAgentEvent) {
  return String(
    event.data?.tool_call_id ||
      event.data?.request_id ||
      event.tool ||
      event.event_id,
  );
}

function toolName(event: StaiAgentEvent) {
  return event.tool || String(event.data?.tool || "security tool");
}

function toolInput(
  event: StaiAgentEvent,
): Record<string, unknown> | undefined {
  const input = event.data?.arguments || event.data?.input;
  return input && typeof input === "object" && !Array.isArray(input)
    ? (input as Record<string, unknown>)
    : undefined;
}

function toolWorkspaceType(name: string): ToolWorkspaceContent["type"] {
  const n = name.toLowerCase();
  if (
    n.includes("browser") ||
    n.includes("computer") ||
    n.includes("open_url") ||
    n.includes("web_search") ||
    n === "web"
  )
    return "browser";
  if (
    n.includes("terminal") ||
    n.includes("shell") ||
    n.includes("command")
  )
    return "terminal";
  if (n.includes("http") || n.includes("request")) return "http";
  if (
    n.includes("secret") ||
    n.includes("finding") ||
    n.includes("scan") ||
    n.includes("static") ||
    n.includes("analysis")
  )
    return "findings";
  if (n.includes("file") || n.includes("filesystem")) return "files";
  return null;
}

function workspaceFromEvent(
  event: StaiAgentEvent,
  sessionId: string,
): ToolWorkspaceContent | null {
  const type = toolWorkspaceType(toolName(event));
  if (!type) return null;
  const data = event.data || {};
  const status =
    event.type === "tool_failed" || event.type === "tool_cancelled"
      ? "failed"
      : event.type === "tool_completed"
        ? "completed"
        : "running";
  const output = data.output ?? data.result;
  const findings = Array.isArray(data.findings)
    ? data.findings.filter(
        (
          finding,
        ): finding is NonNullable<ToolWorkspaceContent["findings"]>[number] =>
          Boolean(
            finding &&
              typeof finding === "object" &&
              "severity" in finding &&
              "type" in finding &&
              "message" in finding,
          ),
      )
    : undefined;
  return {
    type,
    title: toolName(event),
    toolCallId: toolId(event),
    sessionId,
    agentRunId: event.investigation_id || undefined,
    toolExecutionId: toolId(event),
    status,
    command: typeof data.command === "string" ? data.command : undefined,
    output:
      typeof output === "string"
        ? output
        : output === undefined
          ? undefined
          : formatToolValue(output),
    url:
      typeof data.url === "string"
        ? data.url
        : typeof data.target === "string" && type === "browser"
          ? data.target
          : undefined,
    method: typeof data.method === "string" ? data.method : undefined,
    requestHeaders:
      data.request_headers && typeof data.request_headers === "object"
        ? (data.request_headers as Record<string, string>)
        : undefined,
    responseStatus:
      typeof data.status_code === "number" ? data.status_code : undefined,
    responseBody:
      typeof data.response_body === "string" ? data.response_body : undefined,
    filePath: typeof data.path === "string" ? data.path : undefined,
    findings,
    metadata: {
      runtimeAvailable: data.runtime_available === true,
      screenshot:
        typeof data.screenshot === "string" ? data.screenshot : undefined,
      path: data.path,
      fileType: data.file_type,
      size: data.size,
    },
  };
}

function activityFromEvent(event: StaiAgentEvent): ActivityEvent | null {
  if (event.type === "agent_reasoning")
    return {
      id: event.event_id,
      label: "Agent activity",
      detail: event.message || "Reviewing the investigation",
      status: "info",
    };
  if (event.type === "tool_started" || event.type === "tool_output")
    return {
      id: event.event_id,
      label: toolName(event),
      detail: event.message || "Running tool",
      status: "running",
      startedAt: Date.now(),
    };
  if (event.type === "tool_completed")
    return {
      id: event.event_id,
      label: toolName(event),
      detail: event.message || "Completed",
      status: "completed",
    };
  if (event.type === "tool_failed" || event.type === "tool_cancelled")
    return {
      id: event.event_id,
      label: toolName(event),
      detail: event.message || "Failed",
      status: "failed",
    };
  if (event.type === "skill_loaded" || event.type === "todo_updated")
    return {
      id: event.event_id,
      label: event.type === "skill_loaded" ? "Skill" : "Investigation plan",
      detail: event.message || "Updated",
      status: "info",
    };
  if (event.type === "finding_created")
    return {
      id: event.event_id,
      label: "Security finding",
      detail: (event.data?.title as string) || event.message || "Finding recorded",
      status: "info",
    };
  if (event.type === "agent_completed")
    return {
      id: event.event_id,
      label: "Agent complete",
      detail: event.message || "Investigation complete",
      status: "completed",
    };
  if (event.type === "agent_error")
    return {
      id: event.event_id,
      label: "Agent error",
      detail: event.message || "An error occurred",
      status: "failed",
    };
  return null;
}

function toolPartFromEvent(event: StaiAgentEvent): ToolPart {
  const input = toolInput(event);
  const output = event.data?.output ?? event.data?.result;
  const state =
    event.type === "tool_started" || event.type === "tool_output"
      ? input
        ? "input-available"
        : "input-streaming"
      : event.type === "approval_requested"
        ? "approval-requested"
        : event.type === "approval_response"
          ? "approval-responded"
          : event.type === "tool_failed" || event.type === "tool_cancelled"
            ? "output-error"
            : "output-available";
  return {
    type: "tool",
    toolCallId: toolId(event),
    toolName: toolName(event),
    state,
    input,
    output,
    progress:
      typeof event.data?.progress === "number"
        ? event.data.progress
        : undefined,
    elapsedSeconds:
      typeof event.data?.elapsed_seconds === "number"
        ? event.data.elapsed_seconds
        : undefined,
    errorText:
      event.type === "tool_failed" || event.type === "tool_cancelled"
        ? String(event.data?.error || event.message)
        : undefined,
    approval:
      event.type === "approval_requested" ||
      event.type === "approval_response"
        ? {
            requestId: String(
              event.data?.request_id || event.event_id,
            ),
            approved: event.data?.approved as boolean | undefined,
          }
        : undefined,
  };
}

/**
 * applyEvent — pure function that merges an incoming event into the entry list.
 *
 * MESSAGE ORDERING FIX:
 * All entries carry a timestamp. We never re-sort after insertion — we insert
 * in the correct position by timestamp. This ensures:
 *   USER 1 → ASSISTANT 1 → USER 2 → ASSISTANT 2
 * even if WebSocket and fetch responses race.
 */
function applyEvent(
  entries: ChatEntry[],
  event: StaiAgentEvent,
  animateAssistant = false,
): ChatEntry[] {
  if (!event.message && !event.type) return entries;

  // Deduplicate: if we already have this event_id, skip
  if (entries.some((e) => e.id === event.event_id)) return entries;

  // Terminal run events close out the assistant turn instead of adding a row:
  // stamp the completion time so "Working for …" can settle into
  // "Worked for …" (HackerAI's WorkedForTrigger durationMs).
  if (TERMINAL_RUN_EVENT_TYPES.has(event.type)) {
    const lastAssistantIndex = entries.reduceRight(
      (found, entry, index) =>
        found === -1 && entry.role === "assistant" ? index : found,
      -1,
    );
    if (lastAssistantIndex === -1) return entries;
    return entries.map((entry, index) =>
      index === lastAssistantIndex
        ? { ...entry, finishedAt: event.timestamp }
        : entry,
    );
  }

  if (HIDDEN_EVENT_TYPES.has(event.type)) return entries;

  // agent_reasoning → append as reasoning part to latest assistant entry
  // (or create a new assistant entry if none exists)
  if (event.type === "agent_reasoning" && event.message) {
    const reasoningPart: ReasoningPart = {
      type: "reasoning",
      activity: event.message,
    };
    // Try to append to the last assistant entry that has no tool parts yet
    const lastAssistantIdx = entries.reduceRight(
      (found, e, i) => (found === -1 && e.role === "assistant" ? i : found),
      -1,
    );
    if (lastAssistantIdx !== -1) {
      return entries.map((e, i) =>
        i === lastAssistantIdx
          ? {
              ...e,
              parts: [...e.parts, { ...reasoningPart, type: "reasoning" as const }],
              id: e.id, // keep the original id
            }
          : e,
      );
    }
    return [
      ...entries,
      {
        id: event.event_id,
        role: "assistant",
        parts: [reasoningPart],
        timestamp: event.timestamp,
      },
    ];
  }

  if (event.type === "user_message") {
    // Deduplicate by content to avoid double-render of optimistic + server echo
    const lastEntry = entries.at(-1);
    if (
      lastEntry?.role === "user" &&
      lastEntry.parts[0]?.type === "text" &&
      lastEntry.parts[0].text === event.message
    ) {
      return entries;
    }
    return [
      ...entries,
      {
        id: event.event_id,
        role: "user",
        parts: [{ type: "text", text: event.message }],
        timestamp: event.timestamp,
      },
    ];
  }

  if (event.type === "response") {
    // Deduplicate by content
    const lastEntry = entries.at(-1);
    if (
      lastEntry?.role === "assistant" &&
      lastEntry.parts.length === 1 &&
      lastEntry.parts[0]?.type === "text" &&
      lastEntry.parts[0].text === event.message
    ) {
      return entries;
    }
    return [
      ...entries,
      {
        id: event.event_id,
        role: "assistant",
        parts: [{ type: "text", text: event.message }],
        timestamp: event.timestamp,
        animate: animateAssistant,
      },
    ];
  }

  if (
    event.type === "tool_started" ||
    event.type === "tool_output" ||
    event.type === "tool_completed" ||
    event.type === "tool_failed" ||
    event.type === "tool_cancelled" ||
    event.type === "approval_requested" ||
    event.type === "approval_response"
  ) {
    const nextPart = toolPartFromEvent(event);
    const messageIndex = entries.findIndex((e) =>
      e.parts.some((part) => {
        if (part.type !== "tool") return false;
        if (part.toolCallId === nextPart.toolCallId) return true;
        return (
          event.type === "tool_started" &&
          part.toolName === nextPart.toolName &&
          (part.state === "input-streaming" ||
            part.state === "input-available")
        );
      }),
    );
    if (messageIndex === -1) {
      return [
        ...entries,
        {
          id: `tool-message-${nextPart.toolCallId}`,
          role: "assistant",
          parts: [nextPart],
          timestamp: event.timestamp,
        },
      ];
    }
    return entries.map((entry, index) => {
      if (index !== messageIndex) return entry;
      return {
        ...entry,
        parts: entry.parts.map((part) =>
          part.type === "tool" &&
          (part.toolCallId === nextPart.toolCallId ||
            (event.type === "tool_started" &&
              part.toolName === nextPart.toolName &&
              (part.state === "input-streaming" ||
                part.state === "input-available")))
            ? {
                ...part,
                ...nextPart,
                input: nextPart.input ?? part.input,
                output: nextPart.output ?? part.output,
                errorText:
                  event.type === "tool_output"
                    ? part.errorText
                    : nextPart.errorText,
              }
            : part,
        ),
      };
    });
  }

  // Generic fallback for unknown displayable events
  if (event.message) {
    return [
      ...entries,
      {
        id: event.event_id,
        role: "assistant",
        parts: [{ type: "text", text: event.message || event.type }],
        timestamp: event.timestamp,
      },
    ];
  }

  return entries;
}

/**
 * Sort entries by timestamp ascending so chronological order is always correct.
 * This is the core of the message ordering bug fix.
 */
function sortedEntries(entries: ChatEntry[]): ChatEntry[] {
  return [...entries].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
  );
}

function formatToolValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

// ─── Public export: wraps providers ──────────────────────────────────────────

export function StaiChatWorkspace(props: {
  sessionId?: string;
  landing?: boolean;
}) {
  return (
    <StaiGlobalStateProvider>
      <ToolWorkspaceProvider>
        <StaiChatWorkspaceContent {...props} />
      </ToolWorkspaceProvider>
    </StaiGlobalStateProvider>
  );
}

// ─── Main workspace content ───────────────────────────────────────────────────

function StaiChatWorkspaceContent({
  sessionId = "default",
  landing = false,
}: {
  sessionId?: string;
  landing?: boolean;
}) {
  const [entries, setEntries] = useState<ChatEntry[]>([]);
  const [draft, setDraft] = useState("");
  const [connected, setConnected] = useState(false);
  const [status, setStatus] = useState<SvsStatus>("ready");
  const [error, setError] = useState<string | null>(null);
  const [conversations, setConversations] = useState<ConversationSummary[]>(
    [],
  );
  const [activities, setActivities] = useState<ActivityEvent[]>([]);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [sidebarQuery, setSidebarQuery] = useState("");
  // The backend owns provider routing. "auto" is the only mode it exposes.
  const [selectedModel, setSelectedModel] = useState<SelectedModel>("auto");
  const bottomRef = useRef<HTMLDivElement>(null);
  const landingSessionIdRef = useRef<string | null>(null);
  const activeSessionIdRef = useRef<string | null>(null);
  const requestControllerRef = useRef<AbortController | null>(null);
  const { openWorkspace, updateWorkspaceContent } = useToolWorkspace();

  async function clearTasks() {
    await clearStaiConversations();
    setConversations([]);
    setEntries([]);
    if (!landing) window.location.assign("/");
  }

  const appendEvent = useCallback(
    (event: StaiAgentEvent) => {
      const activity = activityFromEvent(event);
      if (activity) {
        setActivities((current) =>
          [
            ...current.filter(
              (item) =>
                item.label !== activity.label || activity.status !== "running",
            ),
            activity,
          ].slice(-8),
        );
      }
      const workspace = workspaceFromEvent(event, event.session_id || sessionId);
      if (workspace) {
        if (event.type === "tool_started") openWorkspace(workspace);
        else updateWorkspaceContent(workspace);
      }
      setEntries((current) => {
        if (current.some((e) => e.id === event.event_id)) return current;
        return applyEvent(current, event, event.type === "response");
      });
    },
    [openWorkspace, sessionId, updateWorkspaceContent],
  );

  // Load conversations list + connect WebSocket
  useEffect(() => {
    let cancelled = false;

    getStaiConversations()
      .then((items) => {
        if (!cancelled) setConversations(items);
      })
      .catch(() => undefined);

    if (landing) {
      return () => {
        cancelled = true;
      };
    }

    const socket = openStaiEvents(
      (event) => {
        if (cancelled || event.session_id !== sessionId) return;
        appendEvent(event);
      },
      () => {
        if (!cancelled) setConnected(false);
      },
    );
    socket.addEventListener("open", () => setConnected(true));
    socket.addEventListener("close", () => setConnected(false));

    getStaiMessages(sessionId)
      .then((events) => {
        if (!cancelled) {
          setEntries(
            events.reduce(
              (currentEntries, event) => applyEvent(currentEntries, event),
              [] as ChatEntry[],
            ),
          );
          setActivities(
            events
              .map(activityFromEvent)
              .filter((item): item is ActivityEvent => item !== null)
              .slice(-8),
          );
        }
      })
      .catch((loadError) => {
        if (!cancelled) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : "Unable to load conversation",
          );
        }
      });

    return () => {
      cancelled = true;
      socket.close();
    };
  }, [landing, sessionId, appendEvent]);

  // Auto-scroll to bottom when new entries or status changes
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [entries, status]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const message = draft.trim();
    if (!message || status !== "ready") return;

    setDraft("");
    setError(null);
    setStatus("submitted");

    const targetSessionId = landing
      ? (landingSessionIdRef.current ??= crypto.randomUUID())
      : sessionId;
    activeSessionIdRef.current = targetSessionId;
    requestControllerRef.current?.abort();
    requestControllerRef.current = new AbortController();

    // Optimistic user message — with current timestamp for correct ordering
    const now = new Date().toISOString();
    const optimisticId = `local-user-${targetSessionId}-${Date.now()}`;
    setEntries((current) =>
      applyEvent(current, {
        type: "user_message",
        timestamp: now,
        session_id: targetSessionId,
        event_id: optimisticId,
        investigation_id: "",
        source: "ui",
        correlation_id: "",
        entity_ids: [],
        tool: null,
        agent: null,
        status: "",
        message,
        data: {},
      }),
    );

    try {
      setStatus("streaming");
      const response = await sendStaiMessage(
        message,
        targetSessionId,
        selectedModel,
        requestControllerRef.current.signal,
      );

      // Replace optimistic entry with real user_event_id if returned
      if (response.user_event_id) {
        setEntries((current) => {
          const withoutOptimistic = current.filter(
            (e) => e.id !== optimisticId,
          );
          return applyEvent(withoutOptimistic, {
            type: "user_message",
            timestamp: now, // preserve original timestamp for stable ordering
            session_id: targetSessionId,
            event_id: response.user_event_id as string,
            investigation_id: "",
            source: "ui",
            correlation_id: "",
            entity_ids: [],
            tool: null,
            agent: null,
            status: "",
            message,
            data: {},
          });
        });
      }

      // If a synchronous response is included (non-agent mode), apply it
      if (response.message) {
        setEntries((current) =>
          applyEvent(current, {
            type: "response",
            timestamp: new Date().toISOString(),
            session_id: targetSessionId,
            event_id:
              response.response_event_id || crypto.randomUUID(),
            investigation_id: "",
            source: "api_server",
            correlation_id: "",
            entity_ids: [],
            tool: null,
            agent: null,
            status: "",
            message: response.message,
            data: {},
          }, true),
        );
        if (landing) {
          window.location.assign(
            `/c/${encodeURIComponent(targetSessionId)}`,
          );
        } else {
          getStaiConversations()
            .then(setConversations)
            .catch(() => undefined);
        }
      }
    } catch (sendError) {
      if (!(sendError instanceof DOMException && sendError.name === "AbortError")) {
        setError(
          sendError instanceof Error ? sendError.message : "Message failed",
        );
      }
    } finally {
      requestControllerRef.current = null;
      activeSessionIdRef.current = null;
      setStatus("ready");
    }
  }

  async function handleStop() {
    if (status === "ready") return;
    const targetSessionId = activeSessionIdRef.current ?? sessionId;
    requestControllerRef.current?.abort();
    try {
      await cancelStaiRun(targetSessionId);
    } catch {
      // ignore — backend will report status via WebSocket
    } finally {
      setStatus("ready");
    }
  }

  const isStreaming = status === "streaming" || status === "submitted";
  const displayed = sortedEntries(entries);

  return (
    <div className="flex h-full min-h-0 w-full overflow-hidden bg-background text-foreground">
      {/* ── Sidebar ────────────────────────────────────────────────────── */}
      <aside
        className={`hidden h-full shrink-0 flex-col border-r border-sidebar-border bg-sidebar transition-[width] duration-200 md:flex ${
          sidebarCollapsed ? "w-12" : "w-[280px]"
        }`}
      >
        <div className="flex h-14 shrink-0 items-center justify-between px-3">
          {!sidebarCollapsed && (
            <a
              href="/"
              className="flex items-center gap-2 text-sm font-semibold tracking-tight"
            >
              <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-sidebar-accent text-xs">
                <Shield className="size-4" />
              </span>
              SVS-Cyber
            </a>
          )}
          <button
            type="button"
            onClick={() => setSidebarCollapsed((v) => !v)}
            className="ml-auto flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-foreground"
            aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {sidebarCollapsed ? (
              <PanelLeft className="size-4" />
            ) : (
              <PanelLeftClose className="size-4" />
            )}
          </button>
        </div>

        {!sidebarCollapsed && (
          <>
            <div className="px-3 pb-3">
              <a
                href="/"
                className="flex h-9 items-center gap-2 rounded-lg px-2 text-sm text-sidebar-foreground transition-colors hover:bg-sidebar-accent"
              >
                <SquarePen className="size-4" />
                New investigation
              </a>
              <label className="mt-2 flex h-9 items-center gap-2 rounded-lg border border-sidebar-border bg-sidebar-accent/30 px-2 text-muted-foreground">
                <Search className="size-4 shrink-0" />
                <input
                  value={sidebarQuery}
                  onChange={(e) => setSidebarQuery(e.target.value)}
                  placeholder="Search investigations"
                  className="min-w-0 flex-1 bg-transparent text-xs text-sidebar-foreground outline-none placeholder:text-muted-foreground"
                />
              </label>
              <button
                type="button"
                onClick={() => void clearTasks()}
                className="mt-2 w-full rounded-lg px-2 py-1.5 text-left text-xs text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-foreground"
              >
                Clear all
              </button>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto sidebar-chat-scroll px-2">
              <div className="px-2 pb-2 pt-1 text-xs font-medium text-muted-foreground">
                Investigations
              </div>
              <div className="flex flex-col gap-0.5">
                {conversations
                  .filter((c) =>
                    c.title
                      .toLowerCase()
                      .includes(sidebarQuery.trim().toLowerCase()),
                  )
                  .map((c) => (
                    <a
                      key={c.id}
                      href={`/c/${encodeURIComponent(c.id)}`}
                      className={`block truncate rounded-lg px-3 py-2 text-sm transition-colors hover:bg-sidebar-accent ${
                        c.id === sessionId
                          ? "bg-sidebar-accent text-sidebar-foreground"
                          : "text-sidebar-foreground/75"
                      }`}
                    >
                      {c.title || "Untitled investigation"}
                    </a>
                  ))}
                {conversations.length === 0 && (
                  <div className="px-3 py-2 text-xs text-muted-foreground">
                    No investigations yet
                  </div>
                )}
              </div>
            </div>

            <div className="shrink-0 border-t border-sidebar-border p-3 text-xs text-muted-foreground">
              Defensive security assistant
            </div>
          </>
        )}
      </aside>

      {/* ── Main column ──────────────────────────────────────────────────── */}
      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {/* Header */}
        <header className="flex shrink-0 items-center justify-between bg-background px-4 pt-3 pb-1">
          <div className="flex min-w-0 items-center gap-2 text-lg font-medium">
            <a
              href="/"
              className="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-accent md:hidden"
              aria-label="Open sidebar"
            >
              <PanelLeft className="size-4" />
            </a>
            <span className="truncate">
              {conversations.find((c) => c.id === sessionId)?.title ||
                "SVS-Cyber"}
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span
              className={`h-2 w-2 rounded-full ${connected ? "bg-emerald-400" : isStreaming ? "bg-amber-400 animate-pulse" : "bg-muted-foreground"}`}
            />
            {connected
              ? isStreaming
                ? "Agent running"
                : "Live"
              : "Connecting..."}
          </div>
        </header>

        {/* Activity strip — HackerAI-style agent work header */}
        {activities.length > 0 && (
          <div
            className="mx-auto flex w-full max-w-[768px] items-center gap-2 overflow-x-auto px-4 py-2 text-xs text-muted-foreground"
            aria-label="Agent activity"
          >
            <Activity
              className="size-3.5 shrink-0"
              aria-hidden="true"
            />
            {activities.slice(-4).map((item) => (
              <span
                key={item.id}
                className={`inline-flex shrink-0 items-center gap-1 rounded border border-border px-2 py-1 ${
                  item.status === "failed"
                    ? "text-destructive"
                    : item.status === "completed"
                      ? "text-emerald-400"
                      : item.status === "running"
                        ? "text-amber-400"
                        : ""
                }`}
              >
                {item.status === "completed"
                  ? "✓"
                  : item.status === "failed"
                    ? "!"
                    : item.status === "running"
                      ? "●"
                      : "·"}{" "}
                {item.label}
              </span>
            ))}
          </div>
        )}

        {/* Message list */}
        <section className="min-h-0 flex-1 overflow-y-auto px-4 pt-6 pb-4">
          <div className="mx-auto flex w-full max-w-[768px] flex-col gap-6">
            {displayed.length === 0 && status === "ready" && (
              <div className="flex min-h-[45vh] items-center justify-center text-center text-sm text-muted-foreground">
                What investigation are we running?
              </div>
            )}

            {displayed.map((entry, entryIndex) => (
              <article
                key={entry.id}
                className={`message-row flex w-full flex-col overflow-hidden ${
                  entry.role === "user" ? "items-end" : "items-start"
                }`}
              >
                <div
                  className={
                    entry.role === "user"
                      ? "flex w-full flex-col items-end gap-1"
                      : "w-full min-w-0 text-foreground"
                  }
                >
                  <div
                    className={
                      entry.role === "user"
                        ? "max-w-[80%] rounded-[18px] rounded-se-lg border border-border bg-secondary px-4 py-1.5 text-primary-foreground"
                        : "prose max-w-none min-w-0 space-y-3 overflow-hidden dark:prose-invert"
                    }
                  >
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
                  </div>
                </div>
              </article>
            ))}

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

            {error && (
              <div role="alert" className="text-sm text-destructive">
                {error}
              </div>
            )}
            <div ref={bottomRef} />
          </div>
        </section>

        {/* Composer */}
        <SvsCyberComposer
          value={draft}
          onChange={setDraft}
          onSubmit={handleSubmit}
          onStop={handleStop}
          status={status}
          placeholder={
            landing
              ? "What investigation should we run?"
              : "Message the SVS-Cyber agent"
          }
          chatId={sessionId}
          selectedModel={selectedModel}
          onModelChange={setSelectedModel}
          isCentered={landing}
        />
      </main>

      {/* Right-side tool workspace */}
      <ToolWorkspaceContainer />
    </div>
  );
}

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

// ─── ToolExecutionPart — HackerAI AgentToolGroupRow style ────────────────────

const TOOL_AUTO_COLLAPSE_MS = 500;

function ToolExecutionPart({
  part,
  sessionId,
}: {
  part: ToolPart;
  sessionId: string;
}) {
  const { openWorkspace } = useToolWorkspace();
  const [open, setOpen] = useState(true);
  const [approvalDecision, setApprovalDecision] = useState<boolean | null>(
    null,
  );
  const collapseTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const isTerminal =
    part.toolName.toLowerCase().includes("shell") ||
    part.toolName.toLowerCase().includes("terminal") ||
    part.toolName.toLowerCase().includes("command");
  const isBrowser =
    part.toolName.toLowerCase().includes("browser") ||
    part.toolName.toLowerCase().includes("web") ||
    part.toolName.toLowerCase().includes("computer");
  const isHttp =
    part.toolName.toLowerCase().includes("http") ||
    part.toolName.toLowerCase().includes("request");
  const isFindings =
    part.toolName.toLowerCase().includes("scan") ||
    part.toolName.toLowerCase().includes("secret") ||
    part.toolName.toLowerCase().includes("finding");

  const isRunning =
    part.state === "input-streaming" ||
    part.state === "input-available" ||
    part.state === "approval-requested";
  const isFailed = part.state === "output-error";
  const isCompleted = part.state === "output-available";

  // Auto-collapse after completion — same as HackerAI AgentToolGroupRow
  useEffect(() => {
    if (isCompleted && open) {
      collapseTimerRef.current = setTimeout(() => {
        setOpen(false);
        collapseTimerRef.current = null;
      }, TOOL_AUTO_COLLAPSE_MS);
    }
    return () => {
      if (collapseTimerRef.current !== null) {
        clearTimeout(collapseTimerRef.current);
        collapseTimerRef.current = null;
      }
    };
  }, [isCompleted, open]);

  const toolIcon = isTerminal ? (
    <Terminal className="size-4" />
  ) : isBrowser ? (
    <Globe className="size-4" />
  ) : isHttp ? (
    <Globe className="size-4" />
  ) : isFindings ? (
    <Radar className="size-4" />
  ) : (
    <Wrench className="size-4" />
  );

  const target = isTerminal && part.input?.command
    ? String(part.input.command)
    : (part.input?.target ?? part.input?.url)
      ? String(part.input.target ?? part.input.url)
      : undefined;

  const action = isFailed
    ? `${part.toolName} failed`
    : part.state === "approval-requested"
      ? "Awaiting approval"
      : isRunning
        ? `Running ${part.toolName}${part.progress === undefined ? "" : ` (${part.progress}%)`}${part.progress === undefined && part.elapsedSeconds !== undefined ? ` · ${Math.floor(part.elapsedSeconds)}s` : ""}`
        : `${part.toolName} completed`;

  const workspaceType = toolWorkspaceType(part.toolName);

  const openToolWorkspace = () => {
    if (!workspaceType) return;
    openWorkspace({
      type: workspaceType,
      title: part.toolName,
      toolCallId: part.toolCallId,
      sessionId,
      status: isFailed ? "failed" : isRunning ? "running" : "completed",
      command: isTerminal ? target : undefined,
      output: formatToolValue(part.output),
      url:
        typeof part.input?.url === "string"
          ? part.input.url
          : typeof part.input?.target === "string"
            ? part.input.target
            : undefined,
      metadata: { runtimeAvailable: false },
    });
  };

  const respondToApproval = async (approved: boolean) => {
    const requestId = part.approval?.requestId;
    if (!requestId) return;
    await respondToStaiApproval(requestId, approved);
    setApprovalDecision(approved);
  };

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="w-full my-2">
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className="group flex w-full max-w-full items-center gap-2 text-left text-sm text-muted-foreground transition-colors hover:text-foreground"
          aria-label={`${action}${target ? `: ${target}` : ""}. ${open ? "Hide" : "Show"} details.`}
          onClick={workspaceType ? openToolWorkspace : undefined}
          data-testid={`tool-part-${part.toolCallId}`}
        >
          <ToolBlock
            icon={toolIcon}
            action={action}
            target={target}
            isShimmer={isRunning}
            accessibleLabel={`${action}${target ? `: ${target}` : ""}`}
            isClickable={Boolean(workspaceType)}
            onClick={openToolWorkspace}
            renderAs="div"
          />
        </button>
      </CollapsibleTrigger>

      <CollapsibleContent className="worked-for-content mt-2">
        <div className="overflow-hidden rounded-lg border border-border bg-muted/20 text-xs">
          {part.input && (
            <div className="border-b border-border p-3">
              <div className="mb-2 font-medium text-muted-foreground">Input</div>
              <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words font-mono text-foreground">
                {formatToolValue(part.input)}
              </pre>
            </div>
          )}
          {(part.output !== undefined || part.errorText) && (
            <div className="p-3">
              <div
                className={`mb-2 font-medium ${part.errorText ? "text-destructive" : "text-muted-foreground"}`}
              >
                {part.errorText ? "Error" : "Output"}
              </div>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words font-mono text-foreground">
                {formatToolValue(part.errorText || part.output)}
              </pre>
            </div>
          )}
          {part.approval && (
            <div className="border-t border-border p-3 text-muted-foreground">
              {approvalDecision === null &&
              part.approval.approved === undefined ? (
                <div className="flex items-center justify-between gap-3">
                  <span>Approval requested for this action.</span>
                  <span className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => void respondToApproval(false)}
                      className="rounded border border-border px-2 py-1 text-xs hover:bg-muted"
                    >
                      Deny
                    </button>
                    <button
                      type="button"
                      onClick={() => void respondToApproval(true)}
                      className="rounded bg-foreground px-2 py-1 text-xs text-background hover:opacity-80"
                    >
                      Allow
                    </button>
                  </span>
                </div>
              ) : approvalDecision ?? part.approval.approved ? (
                "Approved."
              ) : (
                "Denied."
              )}
            </div>
          )}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}
