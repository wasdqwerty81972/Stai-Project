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
    return Promise.reject(new Error("protection bridge is available only in the local STAI app"));
  }

  const context: ProtectionContext = {
    isTauri: isTauri(),
    protocol: window.location.protocol,
    hostname: window.location.hostname,
    port: window.location.port,
  };

  if (!isTrustedProtectionContext(context)) {
    return Promise.reject(new Error("protection bridge is restricted to the local STAI app"));
  }

  return invoke<T>(command, args);
}

export const getProtectionStatus = () =>
  invokeProtection<ProtectionStatus>("get_protection_status");

export const startScan = (scope: ScanScope) =>
  invokeProtection<ScanJob>("start_protection_scan", { scope });

export const getScan = (jobId: string) =>
  invokeProtection<ScanJob>("get_protection_scan", { jobId });

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
