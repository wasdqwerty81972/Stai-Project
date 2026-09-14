export interface StaiAgentEvent {
  type: string;
  timestamp: string;
  session_id: string;
  event_id: string;
  investigation_id: string;
  source: string;
  correlation_id: string;
  entity_ids: string[];
  tool: string | null;
  agent: string | null;
  status: string;
  message: string;
  data: Record<string, unknown>;
}

export interface StaiChatResponse {
  status: string;
  session_id: string;
  message: string;
  user_event_id?: string;
  response_event_id?: string;
}

export interface StaiCancelResponse {
  status: "cancelled" | "not_found" | "error";
  message?: string;
}

export interface StaiConversationSummary {
  id: string;
  title: string;
  last_message?: string;
  timestamp: string;
}

const jsonHeaders = { "Content-Type": "application/json" };
const backendOrigin =
  process.env.NEXT_PUBLIC_BACKEND_ORIGIN?.trim() ||
  "http://127.0.0.1:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(new URL(path, backendOrigin), {
    ...init,
    headers: { ...jsonHeaders, ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `STAI API request failed: ${response.status}`);
  }
  return (await response.json()) as T;
}

export function sendStaiMessage(
  message: string,
  sessionId = "default",
  model?: string,
  signal?: AbortSignal,
): Promise<StaiChatResponse> {
  return request<StaiChatResponse>("/api/chat", {
    method: "POST",
    signal,
    body: JSON.stringify({ message, session_id: sessionId, model }),
  });
}

export function getStaiMessages(sessionId: string) {
  return request<StaiAgentEvent[]>(
    `/api/conversations/${encodeURIComponent(sessionId)}/messages`,
  );
}

export function getStaiConversations() {
  return request<StaiConversationSummary[]>("/api/conversations");
}

export function clearStaiConversations() {
  return request<{ status: string; count: number }>("/api/conversations", {
    method: "DELETE",
  });
}

export function respondToStaiApproval(
  requestId: string,
  approved: boolean,
) {
  return request<{ request_id: string; approved: boolean }>(
    `/api/approval/${encodeURIComponent(requestId)}/respond?approved=${approved}`,
    { method: "POST" },
  );
}

/**
 * Cancel the running agent for a given session.
 * Calls /api/agent/cancel on the SVS-Cyber backend.
 * Returns a result object — never throws on "not found".
 */
export async function cancelStaiRun(
  sessionId: string,
): Promise<StaiCancelResponse> {
  try {
    return await request<StaiCancelResponse>("/api/agent/cancel", {
      method: "POST",
      body: JSON.stringify({ session_id: sessionId }),
    });
  } catch (err) {
    return {
      status: "error",
      message: err instanceof Error ? err.message : "Cancel request failed",
    };
  }
}

export function openStaiEvents(
  onEvent: (event: StaiAgentEvent) => void,
  onError?: () => void,
): WebSocket {
  const backendUrl = backendOrigin
    ? new URL(backendOrigin)
    : new URL(window.location.origin);
  const protocol = backendUrl.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${protocol}//${backendUrl.host}/ws`);
  socket.addEventListener("message", (event) => {
    try {
      onEvent(JSON.parse(event.data) as StaiAgentEvent);
    } catch {
      onError?.();
    }
  });
  socket.addEventListener("error", () => onError?.());
  return socket;
}