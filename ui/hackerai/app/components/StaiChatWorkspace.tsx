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
 *              │    ├─ SvsTranscript (messages and evidence)
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
import { Activity } from "lucide-react";
import { useRouter } from "next/navigation";
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
import { SvsWorkspaceSidebar } from "./svs/SvsWorkspaceSidebar";
import { SvsWorkspaceHeader } from "./svs/SvsWorkspaceHeader";
import { SvsLandingState } from "./svs/SvsLandingState";
import { SvsTranscript } from "./svs/SvsTranscript";

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

export interface ChatEntry {
  id: string;
  /** Every displayable event folded into this entry, for reconnect dedupe. */
  eventIds?: string[];
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

function toolInput(event: StaiAgentEvent): Record<string, unknown> | undefined {
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
  if (n.includes("terminal") || n.includes("shell") || n.includes("command"))
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
      detail:
        (event.data?.title as string) || event.message || "Finding recorded",
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
      event.type === "approval_requested" || event.type === "approval_response"
        ? {
            requestId: String(event.data?.request_id || event.event_id),
            approved: event.data?.approved as boolean | undefined,
          }
        : undefined,
  };
}

/**
 * Fold events into one assistant entry per user turn. Event timestamps locate
 * the turn even when history arrives after a live WebSocket event.
 */
export function applyEvent(
  entries: ChatEntry[],
  event: StaiAgentEvent,
  animateAssistant = false,
): ChatEntry[] {
  if (!event.message && !event.type) return entries;
  if (
    entries.some(
      (entry) =>
        entry.id === event.event_id || entry.eventIds?.includes(event.event_id),
    )
  )
    return entries;

  const eventTime = Date.parse(event.timestamp);
  const timestampOf = (entry: ChatEntry) => Date.parse(entry.timestamp);
  const insert = (entry: ChatEntry) => sortedEntries([...entries, entry]);
  const userTimes = entries
    .filter((entry) => entry.role === "user")
    .map(timestampOf);
  const turnStart = Math.max(
    -Infinity,
    ...userTimes.filter((time) => time <= eventTime),
  );
  const turnEnd = Math.min(
    Infinity,
    ...userTimes.filter((time) => time > eventTime),
  );
  const assistantIndex = entries.findIndex((entry) => {
    const time = timestampOf(entry);
    return entry.role === "assistant" && time >= turnStart && time < turnEnd;
  });
  const updateAssistant = (
    update: (entry: ChatEntry) => ChatEntry,
  ): ChatEntry[] =>
    sortedEntries(
      entries.map((entry, index) =>
        index === assistantIndex
          ? update({
              ...entry,
              timestamp:
                timestampOf(entry) <= eventTime
                  ? entry.timestamp
                  : event.timestamp,
              eventIds: [...(entry.eventIds ?? [entry.id]), event.event_id],
            })
          : entry,
      ),
    );
  const createAssistant = (part: MessagePart): ChatEntry[] =>
    insert({
      id: event.event_id,
      eventIds: [event.event_id],
      role: "assistant",
      parts: [part],
      timestamp: event.timestamp,
      animate: animateAssistant,
    });

  if (TERMINAL_RUN_EVENT_TYPES.has(event.type)) {
    if (assistantIndex === -1) return entries;
    return updateAssistant((entry) => ({
      ...entry,
      finishedAt: event.timestamp,
    }));
  }
  if (HIDDEN_EVENT_TYPES.has(event.type)) return entries;

  if (event.type === "user_message") {
    const optimisticIndex = entries.findIndex(
      (entry) =>
        entry.role === "user" &&
        entry.id.startsWith("local-user-") &&
        entry.parts[0]?.type === "text" &&
        entry.parts[0].text === event.message,
    );
    if (optimisticIndex !== -1) {
      return sortedEntries(
        entries.map((entry, index) =>
          index === optimisticIndex
            ? {
                ...entry,
                id: event.event_id,
                eventIds: [...(entry.eventIds ?? [entry.id]), event.event_id],
                // Keep the instant the user sent the prompt so the echoed
                // server event cannot move the turn after agent activity.
                timestamp: entry.timestamp,
              }
            : entry,
        ),
      );
    }
    return insert({
      id: event.event_id,
      eventIds: [event.event_id],
      role: "user",
      parts: [{ type: "text", text: event.message }],
      timestamp: event.timestamp,
    });
  }

  if (event.type === "agent_reasoning" && event.message) {
    const part: ReasoningPart = {
      type: "reasoning",
      activity: event.message,
    };
    return assistantIndex === -1
      ? createAssistant(part)
      : updateAssistant((entry) => ({
          ...entry,
          parts: [...entry.parts, part],
        }));
  }

  if (event.type === "response") {
    const part: TextPart = { type: "text", text: event.message };
    return assistantIndex === -1
      ? createAssistant(part)
      : updateAssistant((entry) => ({
          ...entry,
          parts: entry.parts.some(
            (existing) =>
              existing.type === "text" && existing.text === event.message,
          )
            ? entry.parts
            : [...entry.parts, part],
          animate: entry.animate || animateAssistant,
        }));
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
    if (assistantIndex === -1) return createAssistant(nextPart);
    return updateAssistant((entry) => {
      const exactIndex = entry.parts.findIndex(
        (part) =>
          part.type === "tool" && part.toolCallId === nextPart.toolCallId,
      );
      const fallbackIndex =
        exactIndex === -1 && event.type !== "tool_started"
          ? entry.parts.findIndex(
              (part) =>
                part.type === "tool" &&
                part.toolName === nextPart.toolName &&
                part.state !== "output-available" &&
                part.state !== "output-error",
            )
          : -1;
      const partIndex = exactIndex === -1 ? fallbackIndex : exactIndex;
      if (partIndex === -1) {
        return { ...entry, parts: [...entry.parts, nextPart] };
      }
      return {
        ...entry,
        parts: entry.parts.map((part, index) => {
          if (index !== partIndex || part.type !== "tool") return part;
          const terminal =
            part.state === "output-available" || part.state === "output-error";
          const staleRunningUpdate =
            terminal &&
            (nextPart.state === "input-streaming" ||
              nextPart.state === "input-available");
          return {
            ...part,
            ...nextPart,
            state: staleRunningUpdate ? part.state : nextPart.state,
            input: nextPart.input ?? part.input,
            output: nextPart.output ?? part.output,
            errorText: staleRunningUpdate ? part.errorText : nextPart.errorText,
          };
        }),
      };
    });
  }

  if (event.message) {
    const part: TextPart = { type: "text", text: event.message };
    return assistantIndex === -1
      ? createAssistant(part)
      : updateAssistant((entry) => ({
          ...entry,
          parts: [...entry.parts, part],
        }));
  }
  return entries;
}

export function reconcileEvents(events: StaiAgentEvent[]): ChatEntry[] {
  const unique = new Map<string, StaiAgentEvent>();
  events.forEach((event) => {
    if (!unique.has(event.event_id)) unique.set(event.event_id, event);
  });
  return [...unique.values()]
    .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))
    .reduce((entries, event) => applyEvent(entries, event), [] as ChatEntry[]);
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
  const [connection, setConnection] = useState<
    "connecting" | "connected" | "disconnected"
  >("connecting");
  const [status, setStatus] = useState<SvsStatus>("ready");
  const [error, setError] = useState<string | null>(null);
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [activities, setActivities] = useState<ActivityEvent[]>([]);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  // The backend owns provider routing. "auto" is the only mode it exposes.
  const [selectedModel, setSelectedModel] = useState<SelectedModel>("auto");
  const bottomRef = useRef<HTMLDivElement>(null);
  const eventLogRef = useRef(new Map<string, StaiAgentEvent>());
  const loggedSessionRef = useRef(sessionId);
  const landingSessionIdRef = useRef<string | null>(null);
  const activeSessionIdRef = useRef<string | null>(null);
  const requestControllerRef = useRef<AbortController | null>(null);
  const router = useRouter();
  const { openWorkspace, updateWorkspaceContent } = useToolWorkspace();

  useEffect(() => {
    const media = window.matchMedia("(max-width: 767px)");
    const closeOnMobile = (event: MediaQueryListEvent) => {
      if (event.matches) setSidebarCollapsed(true);
    };
    if (media.matches) setSidebarCollapsed(true);
    media.addEventListener("change", closeOnMobile);
    return () => media.removeEventListener("change", closeOnMobile);
  }, []);

  async function clearTasks() {
    await clearStaiConversations();
    eventLogRef.current.clear();
    setConversations([]);
    setEntries([]);
    if (!landing) router.push("/");
  }

  const appendEvent = useCallback(
    (event: StaiAgentEvent) => {
      if (eventLogRef.current.has(event.event_id)) return;
      eventLogRef.current.set(event.event_id, event);
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
      const workspace = workspaceFromEvent(
        event,
        event.session_id || sessionId,
      );
      if (workspace) {
        if (event.type === "tool_started") openWorkspace(workspace);
        else updateWorkspaceContent(workspace);
      }
      setEntries(reconcileEvents([...eventLogRef.current.values()]));
    },
    [openWorkspace, sessionId, updateWorkspaceContent],
  );

  // Load conversations list + connect WebSocket
  useEffect(() => {
    let cancelled = false;
    if (loggedSessionRef.current !== sessionId) {
      loggedSessionRef.current = sessionId;
      eventLogRef.current.clear();
      setEntries([]);
      setActivities([]);
    }

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
        if (!cancelled) setConnection("disconnected");
      },
      () => {
        if (!cancelled) setConnection("connected");
      },
      () => {
        if (!cancelled) setConnection("disconnected");
      },
    );

    getStaiMessages(sessionId)
      .then((events) => {
        if (!cancelled) {
          events.forEach((event) => {
            if (!eventLogRef.current.has(event.event_id)) {
              eventLogRef.current.set(event.event_id, event);
            }
          });
          setEntries(reconcileEvents([...eventLogRef.current.values()]));
          setActivities(
            [...eventLogRef.current.values()]
              .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))
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
    eventLogRef.current.set(optimisticId, {
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
    });
    setEntries(reconcileEvents([...eventLogRef.current.values()]));

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
        eventLogRef.current.delete(optimisticId);
        if (!eventLogRef.current.has(response.user_event_id)) {
          eventLogRef.current.set(response.user_event_id, {
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
        }
        setEntries(reconcileEvents([...eventLogRef.current.values()]));
      }

      // If a synchronous response is included (non-agent mode), apply it
      if (response.message) {
        const responseEventId =
          response.response_event_id || crypto.randomUUID();
        if (!eventLogRef.current.has(responseEventId)) {
          eventLogRef.current.set(responseEventId, {
            type: "response",
            timestamp: new Date().toISOString(),
            session_id: targetSessionId,
            event_id: responseEventId,
            investigation_id: "",
            source: "api_server",
            correlation_id: "",
            entity_ids: [],
            tool: null,
            agent: null,
            status: "",
            message: response.message,
            data: {},
          });
        }
        setEntries(reconcileEvents([...eventLogRef.current.values()]));
        if (landing) {
          router.push(`/c/${encodeURIComponent(targetSessionId)}`);
        } else {
          getStaiConversations()
            .then(setConversations)
            .catch(() => undefined);
        }
      }
    } catch (sendError) {
      if (!(
        sendError instanceof DOMException && sendError.name === "AbortError"
      )) {
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
      <SvsWorkspaceSidebar
        conversations={conversations}
        activeSessionId={landing ? undefined : sessionId}
        onClearAll={clearTasks}
        collapsed={sidebarCollapsed}
        onCollapsedChange={setSidebarCollapsed}
      />

      {/* ── Main column ──────────────────────────────────────────────────── */}
      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <SvsWorkspaceHeader
          title={
            landing
              ? "SVS-Cyber"
              : conversations.find((c) => c.id === sessionId)?.title ||
                "SVS-Cyber"
          }
          connection={landing ? "idle" : connection}
          running={isStreaming}
          onOpenNavigation={() => setSidebarCollapsed(false)}
        />

        {/* Activity strip — HackerAI-style agent work header */}
        {activities.length > 0 && (
          <div
            className="mx-auto flex w-full max-w-[768px] items-center gap-2 overflow-x-auto px-4 py-2 text-xs text-muted-foreground"
            aria-label="Agent activity"
          >
            <Activity className="size-3.5 shrink-0" aria-hidden="true" />
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
          {landing && displayed.length === 0 && status === "ready" ? (
            <SvsLandingState onSuggestion={setDraft} />
          ) : (
            <SvsTranscript
              entries={displayed}
              running={isStreaming}
              error={error}
              sessionId={sessionId}
              onApproval={async (requestId, approved) => {
                await respondToStaiApproval(requestId, approved, sessionId);
              }}
              bottomRef={bottomRef}
            />
          )}
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
