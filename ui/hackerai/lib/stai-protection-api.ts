/**
 * Typed client for the STAI local Windows protection service HTTP API.
 *
 * Wraps the `/api/protection/*` routes exposed by `ui/api_server.py`. Every
 * response type mirrors the Pydantic `response_model` declared there, so the
 * dashboard is built strictly against the real service contract.
 *
 * Nothing here simulates success: transport failures and service
 * 4xx/5xx/501/503 responses surface as thrown `ProtectionApiError` values (or,
 * for restore, a typed failure result). Callers render honest
 * unavailable / error states from these — never a fabricated "protected" or
 * "restored" outcome.
 *
 * Consumed by `SvsProtectionDashboard` and the components under
 * `app/components/svs/protection/`.
 */

import { getBackendOrigin } from "@/lib/stai-api";

export type ProtectionState =
  "active" | "degraded" | "unavailable" | (string & {});

export interface ProtectionWindowsSecurity {
  /** OS-registered antivirus provider, or null when the OS query is unavailable. */
  registered_av_provider: string | null;
  defender_mode?: string | null;
  [key: string]: unknown;
}

export interface ProtectionStatus {
  state: ProtectionState;
  /** kernel_realtime | user_mode_limited | on_demand_only | unavailable */
  protection_mode?: string;
  scanner_ready?: boolean;
  fallback_coverage?: Record<string, unknown>;
  driver_state: string;
  service_state: string;
  rules_version: string;
  last_scan: string | null;
  /** Distinct, non-conflated counts, e.g. { detected, blocked, quarantined }. */
  counts: Record<string, number>;
  windows_security: ProtectionWindowsSecurity;
  sensor_coverage: Record<string, unknown>;
  last_error: string | null;
}

export type ScanScope = "quick" | "system";

export interface ScanJob {
  job_id: string;
  scope: string;
  /** queued | running | completed | partial | cancelled | failed */
  state: string;
  files_scanned: number;
  files_total: number;
  detections: number;
  errors: number;
  files_skipped: number;
  unknown_verdicts: number;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
}

export interface ThreatRecord {
  detection_id: string;
  sha256: string;
  rule_id: string;
  rule_version: string;
  /** block | observe | ... — a confirmed denial is distinct from an observation. */
  action: string;
  confidence: string;
  severity: string;
  file_type: string | null;
  size_bytes: number | null;
  file_path: string | null;
  created_at: string;
  triage_enqueued: boolean;
}

export interface QuarantineItem {
  item_id: string;
  original_path: string;
  quarantined_path: string;
  sha256: string;
  rule_id: string;
  rule_version: string;
  action_result: string;
  detection_id: string;
  created_at: string;
  restored_at: string | null;
  restore_result: string | null;
}

export interface QuarantineRestoreResult {
  success: boolean;
  item?: QuarantineItem | null;
  error?: string | null;
}

export interface AgentMessageResponse {
  session_id: string;
  message: string;
  /** Always empty for the investigation-scoped protection agent. */
  tool_calls: unknown[];
  response_action: string | null;
}

export interface ProtectionAgentMessage {
  role: "user" | "assistant";
  message: string;
  timestamp?: string;
  response_action?: string | null;
}

export interface ProtectionAgentHistory {
  session_id: string;
  messages: ProtectionAgentMessage[];
}

export interface ProtectionTriage {
  triage_id: string;
  detection_id: string;
  summary: string;
  recommendations: string[];
  state: string;
  created_at?: string;
  updated_at?: string;
}

export interface MonitoredProcess {
  pid: number;
  instance_id: string;
  identity_verified: boolean;
  name: string;
  parent_pid?: number | null;
  create_time?: number | null;
  exe?: string | null;
  username?: string | null;
  status: string;
  cpu_percent: number | null;
  memory_bytes: number | null;
  thread_count?: number | null;
  io_read_bytes?: number | null;
  io_write_bytes?: number | null;
  io_semantics?: string | null;
  network_connection_count?: number | null;
  entropy_score?: number | null;
  entropy_state?: string;
  entropy_source?: string | null;
  entropy_threshold?: number | null;
  auto_scan_status?: string;
  scan_status?: string | null;
  scan_action?: string | null;
  scan_rule_id?: string | null;
  scan_sha256?: string | null;
  scan_error?: string | null;
  observed_at?: string;
}

export interface ProcessMonitorHealth {
  state: string;
  source?: "protection_service" | "local_fallback" | "unavailable";
  source_error?: string | null;
  event_source: string;
  event_source_name?: string | null;
  event_source_error?: string | null;
  dropped_events: number;
  last_reconcile_seconds_ago?: number | null;
  sample_interval_seconds: number;
  reconcile_interval_seconds: number;
  sampling_profile?: "low" | "normal" | "high" | "custom";
  last_error?: string | null;
}

export interface ProcessMonitorSnapshot {
  sequence: number;
  observed_at: string;
  processes: MonitoredProcess[];
  health: ProcessMonitorHealth;
}

export interface ProcessConnection {
  pid: number | null;
  instance_id: string | null;
  process_name: string;
  ownership_status: string;
  family: string;
  protocol: string;
  local_address: string | null;
  local_port: number | null;
  remote_address: string | null;
  remote_port: number | null;
  state: string;
  throughput_bytes_per_second: number | null;
}

export interface ProcessScanResult {
  instance_id: string;
  pid: number;
  executable: string;
  status: string;
  action: string;
  rule_id: string | null;
  rule_version: string;
  sha256: string | null;
  reason: string;
  reason_code: string;
  detection_id: string | null;
  quarantine: { state: string; error: string | null } | null;
}

export interface ProcessMonitorEvent {
  type: "snapshot" | "process_added" | "process_removed" | "process_metrics_updated" | "health" | "heartbeat";
  sequence?: number;
  process?: MonitoredProcess;
  instance_id?: string;
  health?: ProcessMonitorHealth;
  processes?: MonitoredProcess[];
  observed_at?: string;
  timestamp?: string;
  resync?: boolean;
}

/** Error carrying the HTTP status so callers can distinguish 501/503/404. */
export class ProtectionApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ProtectionApiError";
    this.status = status;
  }
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
    const raw = await response.text().catch(() => "");
    let message = raw;
    try {
      const parsed = JSON.parse(raw) as { detail?: unknown };
      if (parsed && parsed.detail != null) {
        message =
          typeof parsed.detail === "string"
            ? parsed.detail
            : JSON.stringify(parsed.detail);
      }
    } catch {
      // Non-JSON error body — keep the raw text as the message.
    }
    throw new ProtectionApiError(
      message || `Protection API request failed (${response.status})`,
      response.status,
    );
  }
  return (await response.json()) as T;
}

export function getProtectionStatus(): Promise<ProtectionStatus> {
  return request<ProtectionStatus>("/api/protection/status");
}

/** Connect to the authenticated local process stream; reconnect with bounded backoff. */
export function subscribeToProcessMonitor(
  onEvent: (event: ProcessMonitorEvent) => void,
  onState: (state: "connecting" | "connected" | "disconnected" | "error") => void,
): () => void {
  const backend = new URL(getBackendOrigin());
  const protocol = backend.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${backend.host}/api/antivirus/process-monitor/stream`;
  let socket: WebSocket | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let closed = false;
  let attempt = 0;

  const connect = () => {
    if (closed) return;
    onState("connecting");
    try {
      socket = new WebSocket(url);
      socket.onopen = () => {
        attempt = 0;
        onState("connected");
      };
      socket.onmessage = (message) => {
        try {
          const event = JSON.parse(String(message.data)) as ProcessMonitorEvent;
          onEvent(event);
        } catch {
          onState("error");
        }
      };
      socket.onerror = () => onState("error");
      socket.onclose = () => {
        socket = null;
        if (closed) return;
        onState("disconnected");
        const delay = Math.min(10_000, 500 * 2 ** Math.min(attempt++, 5));
        timer = setTimeout(connect, delay);
      };
    } catch {
      onState("error");
      timer = setTimeout(connect, 2_000);
    }
  };

  connect();
  return () => {
    closed = true;
    if (timer) clearTimeout(timer);
    socket?.close();
    socket = null;
  };
}

export function getProcessConnections(
  instanceId: string,
): Promise<{ instance_id: string; available: boolean; connections: ProcessConnection[] }> {
  return request(`/api/antivirus/processes/${encodeURIComponent(instanceId)}/connections`);
}

export function getProcessDetails(instanceId: string): Promise<MonitoredProcess> {
  return request(`/api/antivirus/processes/${encodeURIComponent(instanceId)}`);
}

export function scanProcessExecutable(instanceId: string): Promise<ProcessScanResult> {
  return request(`/api/antivirus/processes/${encodeURIComponent(instanceId)}/scan`, {
    method: "POST",
  });
}

export function setProcessMonitorProfile(
  profile: "low" | "normal" | "high",
): Promise<ProcessMonitorHealth> {
  return request("/api/antivirus/process-monitor/profile", {
    method: "POST",
    body: JSON.stringify({ profile }),
  });
}

export function startScan(scope: ScanScope): Promise<ScanJob> {
  return request<ScanJob>("/api/protection/scans", {
    method: "POST",
    body: JSON.stringify({ scope }),
  });
}

export function getScan(jobId: string): Promise<ScanJob> {
  return request<ScanJob>(`/api/protection/scans/${encodeURIComponent(jobId)}`);
}

export function cancelScan(
  jobId: string,
): Promise<{ status: string; job_id: string }> {
  return request<{ status: string; job_id: string }>(
    `/api/protection/scans/${encodeURIComponent(jobId)}`,
    { method: "DELETE" },
  );
}

export function listThreats(limit = 100): Promise<ThreatRecord[]> {
  const query = new URLSearchParams({ limit: String(limit) });
  return request<ThreatRecord[]>(`/api/protection/threats?${query}`);
}

export function getTriage(detectionId: string): Promise<ProtectionTriage> {
  const query = new URLSearchParams({ detection_id: detectionId });
  return request<ProtectionTriage>(`/api/protection/triage?${query}`);
}

export function requestTriage(detectionId: string): Promise<ProtectionTriage> {
  return request<ProtectionTriage>(
    `/api/protection/triage/${encodeURIComponent(detectionId)}`,
    { method: "POST" },
  );
}

export function getAgentHistory(
  sessionId: string,
): Promise<ProtectionAgentHistory> {
  return request<ProtectionAgentHistory>(
    `/api/protection/agent/conversations/${encodeURIComponent(sessionId)}`,
  );
}

export function sendAgentMessage(
  sessionId: string,
  message: string,
  detectionId: string | null,
): Promise<AgentMessageResponse> {
  return request<AgentMessageResponse>("/api/protection/agent/messages", {
    method: "POST",
    body: JSON.stringify({
      session_id: sessionId,
      message,
      detection_id: detectionId,
    }),
  });
}

export function listQuarantine(): Promise<QuarantineItem[]> {
  return request<QuarantineItem[]>("/api/protection/quarantine");
}

/**
 * Restore a quarantined item. Never throws: HTTP/transport failures are mapped
 * to a typed `{ success: false, error }` result so the UI can show the real
 * restore outcome (success or the actual failure reason).
 */
export async function restoreQuarantine(
  itemId: string,
): Promise<QuarantineRestoreResult> {
  try {
    return await request<QuarantineRestoreResult>(
      `/api/protection/quarantine/${encodeURIComponent(itemId)}/restore`,
      { method: "POST" },
    );
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : "Restore request failed",
    };
  }
}
