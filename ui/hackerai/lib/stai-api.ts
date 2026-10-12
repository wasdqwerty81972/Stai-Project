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
  ok: boolean;
  cancelled: boolean;
  reason?: string;
  error?: string;
}

export interface StaiConversationSummary {
  id: string;
  title: string;
  last_message?: string;
  timestamp: string;
}

/** Safe metadata shown by the composer slash-command picker. */
export interface StaiCommand {
  name: string;
  description: string;
  argument_hint?: string;
}

export interface CommunicationsStatus {
  settings: {
    enabled: Record<string, boolean>;
    notifications: { enabled: boolean; event_types: string[]; destinations: string[] };
  };
  platforms: Record<string, { account_id: string; status: string; error: string }>;
}

export interface SensorCapabilityStatus {
  id: number;
  registry_id?: number;
  key: string;
  name: string;
  state: string;
  source: string;
  permissions?: string[];
  error?: string | null;
}

export interface SensorRegistryEntry {
  id: number;
  key: string;
  name: string;
  description: string;
  category: string;
  layer: number;
  kind: string;
  platform_support: Record<string, string>;
  host_support: string;
  telemetry_source: string;
  shared_collector_id: string;
  required_permissions: string[];
  event_schema: {
    id: string;
    required_fields: string[];
    specific_fields: string[];
    privacy: string;
  };
  collection_method: string;
  operational_status: "implemented" | "partial" | "registered_only";
  performance_cost: { class: string; measured: boolean };
  test_refs: string[];
  coverage_notes: string;
  derived_from: string[];
  phase1_requested_id?: number | null;
  phase1_requested_name?: string | null;
  runtime_state: string;
  runtime_error?: string | null;
}

export interface SensorPendingApproval {
  approval_id: string;
  alert_id: string;
  summary: string;
  severity: string;
  proposed_actions: string[];
}

export interface SensorRuntimeStatus {
  running: boolean;
  platform: string;
  capabilities: SensorCapabilityStatus[];
  registry_version?: string;
  registry?: SensorRegistryEntry[];
  queue: {
    depth: number;
    capacity: number;
    dropped: number;
    deduplicated: number;
    backpressure?: number;
  };
  last_event_time?: string | null;
  last_error?: string | null;
  pending_approvals: SensorPendingApproval[];
  privacy: {
    collect_file_paths: boolean;
    collect_dns_names: boolean;
    collect_command_lines: boolean;
  };
}

export function getBackendOrigin(): string {
  const envOrigin = process.env.NEXT_PUBLIC_BACKEND_ORIGIN?.trim();
  if (envOrigin) {
    return envOrigin;
  }
  if (typeof window !== "undefined") {
    const protocol = window.location.protocol === "https:" ? "https:" : "http:";
    return `${protocol}//${window.location.hostname}:6764`;
  }
  return "http://127.0.0.1:6764";
}

const jsonHeaders = { "Content-Type": "application/json" };

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const origin = getBackendOrigin();
  const response = await fetch(new URL(path, origin), {
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

export function getStaiCommands() {
  return request<StaiCommand[]>("/api/commands");
}

export function clearStaiConversations() {
  return request<{ status: string; count: number }>("/api/conversations", {
    method: "DELETE",
  });
}

export function respondToStaiApproval(
  requestId: string,
  approved: boolean,
  sessionId = "default",
) {
  const query = new URLSearchParams({
    approved: String(approved),
    session_id: sessionId,
  });
  return request<{ request_id: string; approved: boolean }>(
    `/api/approval/${encodeURIComponent(requestId)}/respond?${query}`,
    { method: "POST" },
  );
}

/**
 * Cancel the running agent for a given session.
 * Calls /api/agent/cancel on the SVS-Cyber backend.
 * Returns a result object — never throws (network errors become error response).
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
      ok: false,
      cancelled: false,
      error: err instanceof Error ? err.message : "Cancel request failed",
    };
  }
}

export function getCommunicationsStatus() {
  return request<CommunicationsStatus>("/api/communications/status");
}

export function setCommunicationsEnabled(enabled: Record<string, boolean>) {
  return request<CommunicationsStatus["settings"]>("/api/communications/settings", {
    method: "PUT",
    body: JSON.stringify({ enabled }),
  });
}

export function setCommunicationsCredential(platform: string, token: string) {
  return request<{ status: string; platform: string; account_id: string }>(
    `/api/communications/credentials/${encodeURIComponent(platform)}/default`,
    { method: "POST", body: JSON.stringify({ token }) },
  );
}

export function deleteCommunicationsCredential(platform: string) {
  return request<{ status: string }>(
    `/api/communications/credentials/${encodeURIComponent(platform)}/default`,
    { method: "DELETE" },
  );
}

export function getCommunicationsPairingRequests() {
  return request<Array<Record<string, string>>>("/api/communications/pairing-requests");
}

export function getCommunicationsPairings() {
  return request<Array<{ key: string; channel: string; account_id: string; sender_id: string; role: string }>>(
    "/api/communications/pairings",
  );
}

export function approveCommunicationsPairing(requestId: string, role: string) {
  return request<{ status: string; role: string }>(
    `/api/communications/pairing-requests/${encodeURIComponent(requestId)}/approve`,
    { method: "POST", body: JSON.stringify({ role }) },
  );
}

export function revokeCommunicationsPairing(platform: string, accountId: string, senderId: string) {
  return request<{ status: string }>(
    `/api/communications/pairings/${encodeURIComponent(platform)}/${encodeURIComponent(accountId)}/${encodeURIComponent(senderId)}`,
    { method: "DELETE" },
  );
}

export function setCommunicationsNotifications(value: {
  enabled: boolean;
  event_types: string[];
  destinations: string[];
}) {
  return request<CommunicationsStatus["settings"]>("/api/communications/notifications", {
    method: "PUT",
    body: JSON.stringify(value),
  });
}

export function sendCommunicationsTest(destination: string) {
  return request<{ status: string }>("/api/communications/test", {
    method: "POST",
    body: JSON.stringify({ destination }),
  });
}

export function disableAllCommunications() {
  return request<CommunicationsStatus["settings"]>("/api/communications/disable", {
    method: "POST",
  });
}

export function getCommunicationsDeliveries() {
  return request<Array<{ event_id: string; platform: string; event_type: string; status: string; timestamp: number }>>(
    "/api/communications/deliveries",
  );
}

export interface StaiEventStreamHandle {
  close(): void;
}

export function openStaiEvents(
  onEvent: (event: StaiAgentEvent) => void,
  onError?: (error?: Event) => void,
  onOpen?: () => void,
  onClose?: () => void,
): StaiEventStreamHandle {
  let backendUrl: URL;
  try {
    backendUrl = new URL(getBackendOrigin());
  } catch {
    backendUrl = new URL(window.location.origin);
  }
  const protocol = backendUrl.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${backendUrl.host}/ws`;

  let socket: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let attempt = 0;
  let explicitlyClosed = false;

  function connect() {
    socket = new WebSocket(wsUrl);

    socket.addEventListener("message", (event) => {
      try {
        onEvent(JSON.parse(event.data) as StaiAgentEvent);
      } catch {
        onError?.();
      }
    });

    socket.addEventListener("open", () => {
      attempt = 0;
      onOpen?.();
    });

    socket.addEventListener("error", (ev) => {
      onError?.(ev);
    });

    socket.addEventListener("close", () => {
      onClose?.();
      if (explicitlyClosed) return;
      const delay = Math.min(1000 * Math.pow(2, attempt), 16000);
      attempt += 1;
      reconnectTimer = setTimeout(connect, delay);
    });
  }

  connect();

  return {
    close() {
      explicitlyClosed = true;
      if (reconnectTimer !== null) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (socket !== null) {
        try {
          socket.close();
        } catch {
          // ignore close errors
        }
        socket = null;
      }
    },
  };
}

export function getSensorRuntimeStatus(): Promise<SensorRuntimeStatus> {
  return request<SensorRuntimeStatus>("/api/sensors/status");
}

export function startSensorMonitoring(): Promise<SensorRuntimeStatus> {
  return request<SensorRuntimeStatus>("/api/sensors/start", { method: "POST" });
}

export function stopSensorMonitoring(): Promise<SensorRuntimeStatus> {
  return request<SensorRuntimeStatus>("/api/sensors/stop", { method: "POST" });
}
