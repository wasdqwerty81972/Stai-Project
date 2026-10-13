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
