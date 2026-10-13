import { invoke, isTauri } from "@tauri-apps/api/core";

export type ProtectionState = "active" | "degraded" | "unavailable";
export type ScanScope = "quick" | "system";

export interface ProtectionCounts {
  detected: number | null;
  blocked: number | null;
  quarantined: number | null;
}

export interface ProtectionStatus {
  state: ProtectionState;
  driver_state: string | null;
  service_state: string | null;
  rules_version: string | null;
  last_scan: string | null;
  counts: Partial<ProtectionCounts> | null;
  windows_security: {
    registered_av_provider: string | null;
    defender_mode: string | null;
    query_available: boolean;
  } | null;
  sensor_coverage: Record<string, string | boolean | null> | null;
  last_error: string | null;
}

export interface ScanJob {
  job_id: string;
  scope: ScanScope;
  state: "queued" | "running" | "completed" | "cancelled" | "failed";
  files_scanned: number;
  files_total: number | null;
  detections: number;
  errors: number;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
}

export type ScanCadence = "daily" | "weekly";
export type ScanWeekday = "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun";

export interface ScanSchedule {
  configured: boolean;
  enabled: boolean;
  cadence?: ScanCadence | null;
  local_time?: string | null;
  days_of_week?: ScanWeekday[] | null;
  last_run_date?: string | null;
  last_job_id?: string | null;
  last_result?: string | null;
  next_run_local?: string | null;
}

export interface ScanProfileRefresh {
  ready: boolean;
  refreshed_at: string | null;
  folders: string[];
}

export interface ScanScheduleInput {
  enabled: boolean;
  cadence: ScanCadence;
  localTime: string;
  daysOfWeek: ScanWeekday[];
}

export interface DetectionRecord {
  detection_id: string;
  action: "block" | "allow";
  confidence: "high" | "medium" | "low";
  severity: string;
  file_type: string | null;
  size_bytes: number | null;
  file_path: string | null;
  created_at: string;
  triage_enqueued: boolean;
  summary?: string | null;
}

export interface TriageRecord {
  triage_id: string;
  detection_id: string;
  summary: string | null;
  recommendations?: string[] | null;
  state: string;
  error?: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface AgentMessageRecord {
  role: "user" | "assistant";
  content: string;
  created_at?: string | null;
}

export interface AgentHistory {
  session_id: string;
  messages: AgentMessageRecord[];
}

export interface AgentReply {
  session_id: string;
  message: string;
  tool_calls: unknown[];
  response_action: string | null;
  status?: "queued" | "completed" | "unavailable" | "failed" | "rejected";
}

export interface QuarantineItem {
  item_id: string;
  original_path: string;
  quarantined_path?: string | null;
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
  item: QuarantineItem | null;
  error: string | null;
}

export interface ProtectionContext {
  isTauri: boolean;
  protocol: string;
  hostname: string;
  port: string;
}

/** Allow the bridge only in a Tauri webview on the bundled app origin. */
export function isTrustedProtectionContext(context: ProtectionContext): boolean {
  if (!context.isTauri) return false;

  if (context.protocol === "tauri:" && context.hostname === "localhost") {
    return true;
  }

  if (context.protocol === "http:" && context.hostname === "tauri.localhost") {
    return true;
  }

  // Tauri development uses the dedicated, loopback-only Vite port.
  return (
    context.protocol === "http:" &&
    (context.hostname === "localhost" || context.hostname === "127.0.0.1") &&
    context.port === "1420"
  );
}

function invokeProtection<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (typeof window === "undefined") {
    return Promise.reject(new Error("protection bridge is available only in the local SVS Cyber app"));
  }

  const context: ProtectionContext = {
    isTauri: isTauri(),
    protocol: window.location.protocol,
    hostname: window.location.hostname,
    port: window.location.port,
  };

  if (!isTrustedProtectionContext(context)) {
    return Promise.reject(new Error("protection bridge is restricted to the local SVS Cyber app"));
  }

  return invoke<T>(command, args);
}

export const getProtectionStatus = () =>
  invokeProtection<ProtectionStatus>("get_protection_status");

export const startScan = (scope: ScanScope) =>
  invokeProtection<ScanJob>("start_protection_scan", { scope });

export const getScan = (jobId: string) =>
  invokeProtection<ScanJob>("get_protection_scan", { jobId });

export const getScanSchedule = () =>
  invokeProtection<ScanSchedule>("get_protection_scan_schedule");

export const refreshScanProfile = () =>
  invokeProtection<ScanProfileRefresh>("refresh_protection_scan_profile");

export const setScanSchedule = (schedule: ScanScheduleInput) =>
  invokeProtection<ScanSchedule>("set_protection_scan_schedule", {
    enabled: schedule.enabled,
    cadence: schedule.cadence,
    localTime: schedule.localTime,
    daysOfWeek: schedule.daysOfWeek,
  });

export const cancelScan = (jobId: string) =>
  invokeProtection<ScanJob | void>("cancel_protection_scan", { jobId });

export const listThreats = () =>
  invokeProtection<DetectionRecord[]>("list_protection_threats");

export const getProtectionTriage = (detectionId: string) =>
  invokeProtection<TriageRecord>("get_protection_triage", { detectionId });

export const requestProtectionTriage = (detectionId: string) =>
  invokeProtection<TriageRecord>("request_protection_triage", { detectionId });

export const getAgentHistory = (sessionId: string) =>
  invokeProtection<AgentHistory>("get_protection_agent_history", { sessionId });

export const sendAgentMessage = (
  sessionId: string,
  message: string,
  detectionId: string | null,
) =>
  invokeProtection<AgentReply>("send_protection_agent_message", {
    sessionId,
    message,
    detectionId,
  });

export const listQuarantine = () =>
  invokeProtection<QuarantineItem[]>("list_quarantine_items");

export const restoreQuarantine = (itemId: string) =>
  invokeProtection<QuarantineRestoreResult>("restore_quarantine_item", { itemId });
