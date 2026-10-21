import { invoke, isTauri } from "@tauri-apps/api/core";

export type ProtectionState = "active" | "degraded" | "unavailable";
export type ScanScope = "quick" | "system";
export type ScanFrequency = "daily" | "weekly";

export interface ProtectionCounts {
  detected: number | null;
  blocked: number | null;
  quarantined: number | null;
}

export interface NetworkTelemetryStatus {
  /** "not_configured" when the service was built without a WFP monitor. */
  state: string;
  startup_error?: string | null;
  error?: string | null;
}

export interface ProtectionStatus {
  state: ProtectionState;
  driver_state: string | null;
  service_state: string | null;
  rules_version: string | null;
  /** The service only sets this when it validated the signed rule package. */
  rules_trusted?: boolean | null;
  rule_count?: number | null;
  sha256_rule_count?: number | null;
  yara_rule_count?: number | null;
  rules_fingerprint?: string | null;
  last_scan: string | null;
  counts: Partial<ProtectionCounts> | null;
  windows_security: {
    registered_av_provider: string | null;
    defender_mode: string | null;
    query_available: boolean;
  } | null;
  sensor_coverage: Record<string, string | boolean | null> | null;
  sensors: SensorRuntimeStatus | null;
  sensor_error: string | null;
  network_telemetry?: NetworkTelemetryStatus | null;
  threat_intel?: {
    state: "advisory" | "unavailable" | "degraded";
    integrity_ok: boolean;
    block_eligible_records: number;
    activation: "inactive";
  } | null;
  last_error: string | null;
}

export interface SensorRegistryEntry {
  id: number;
  key: string;
  name: string;
  category: string;
  layer: string;
  runtime_state: string;
  runtime_error?: string | null;
  host_support: string;
}

export interface SensorRuntimeStatus {
  running: boolean;
  platform: string;
  registry_version: string;
  registry: SensorRegistryEntry[];
  capabilities: Array<{
    id: number;
    registry_id: number;
    key: string;
    name: string;
    state: string;
    error: string;
  }>;
  queue: {
    depth: number;
    capacity: number;
    dropped: number;
    deduplicated: number;
    backpressure: number;
  };
  last_event_time: string | null;
  last_error: string | null;
  privacy: Record<string, boolean>;
  warnings: SensorWarning[];
  drop_folder_watch?: {
    state: "running" | "error" | "unavailable" | string;
    roots: string[];
    active_roots: number;
    errors: Record<string, string>;
    coverage: string;
  };
}

export interface SensorWarning {
  event_id: string;
  sensor_ids: number[];
  timestamp: string;
  severity: string;
  summary: string;
  evidence: string[];
  protection_state: string;
  ai_state: string;
  ai_analysis: string | null;
  classification?: string | null;
  ai_confidence?: number | null;
  protection_action?: string | null;
  recommended_action?: string | null;
}

export interface ScanJob {
  job_id: string;
  scope: ScanScope;
  state:
    "queued" | "running" | "completed" | "partial" | "cancelled" | "failed";
  files_scanned: number;
  files_total: number | null;
  detections: number;
  errors: number;
  files_skipped?: number;
  unknown_verdicts?: number;
  engine_version?: string;
  rules_version?: string;
  duration_ms?: number | null;
  root_snapshot?: string[];
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
}

export interface ActiveScanState {
  active_scan: ScanJob | null;
}

export interface ScanSchedule {
  enabled: boolean;
  frequency: ScanFrequency;
  scope: ScanScope;
  local_time: string;
  weekday: number | null;
  next_run_at: string | null;
  last_run_at: string | null;
  last_job_id: string | null;
  last_result: string | null;
  error_message: string | null;
  updated_at: string | null;
}

export interface DetectionRecord {
  detection_id: string;
  sha256?: string;
  rule_id?: string;
  rule_version?: string;
  action: "block" | "allow";
  confidence: "high" | "medium" | "low";
  severity: string;
  file_type: string | null;
  size_bytes: number | null;
  file_path: string | null;
  created_at: string;
  triage_enqueued: boolean;
  summary?: string | null;
  threat_intel_evidence?: ThreatIntelEvidence | null;
}

export interface ThreatIntelEvidence {
  indicator_type: "sha256";
  indicator_value: string;
  source: string;
  verification: string;
  confidence: number;
  severity: string;
  feed_version: string;
  first_seen: string;
  last_seen: string;
  freshness: string;
  corroborations: number;
  block_eligible: boolean;
  decision_reason: string;
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

declare const __STAI_TAURI_DEV_PORT__: string;
const DEFAULT_TAURI_DEV_PORT =
  typeof __STAI_TAURI_DEV_PORT__ === "string"
    ? __STAI_TAURI_DEV_PORT__
    : "1420";

/** Allow the bridge only in a Tauri webview on the bundled app origin. */
export function isTrustedProtectionContext(
  context: ProtectionContext,
  devPort: string = DEFAULT_TAURI_DEV_PORT,
): boolean {
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
    context.port === devPort
  );
}

function invokeProtection<T>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T> {
  if (typeof window === "undefined") {
    return Promise.reject(
      new Error("protection bridge is available only in the local STAI app"),
    );
  }

  const context: ProtectionContext = {
    isTauri: isTauri(),
    protocol: window.location.protocol,
    hostname: window.location.hostname,
    port: window.location.port,
  };

  if (!isTrustedProtectionContext(context)) {
    return Promise.reject(
      new Error("protection bridge is restricted to the local STAI app"),
    );
  }

  return invoke<T>(command, args);
}

export const getProtectionStatus = () =>
  invokeProtection<ProtectionStatus>("get_protection_status");

export interface ProcessAssessment {
  classification:
    | "known_threat"
    | "needs_review"
    | "no_known_match"
    | "unavailable"
    | "pending";
  entropy: number | null;
  reason: string;
  rule_id: string | null;
  rule_version: string | null;
  sha256: string | null;
  sampled_bytes: number;
}

export interface LiveProcess {
  pid: number;
  process_identity?: string | null;
  name: string;
  username: string | null;
  exe: string | null;
  cpu_percent: number | null;
  memory_bytes: number | null;
  status: string;
  visibility_errors?: string[];
  assessment: ProcessAssessment;
}

export interface DeviceActivity {
  observed_at: string;
  collecting?: boolean;
  stale?: boolean;
  processes: LiveProcess[];
  connections: Array<{
    pid: number | null;
    process_name: string;
    process_identity?: string | null;
    ownership_status?: string;
    protocol: string;
    local_address: string;
    remote_address: string;
    state: string;
  }>;
  network: {
    download_bytes_sec: number | null;
    upload_bytes_sec: number | null;
    bytes_received: number | null;
    bytes_sent: number | null;
  };
  database: {
    available: boolean;
    version: string | null;
    rule_count: number | null;
    sha256_rule_count?: number | null;
    yara_rule_count?: number | null;
    demo: boolean;
    analysis_available?: boolean;
    active_in_protection_service?: boolean;
    coverage: string;
  };
  errors: string[];
  cpu_count: number;
}

export const getDeviceActivity = () =>
  invokeProtection<DeviceActivity>("get_device_activity");

export const startScan = (scope: ScanScope) =>
  invokeProtection<ScanJob>("start_protection_scan", { scope });

export const getScan = (jobId: string) =>
  invokeProtection<ScanJob>("get_protection_scan", { jobId });

export const getActiveScan = () =>
  invokeProtection<ActiveScanState>("get_active_protection_scan");

export const cancelScan = (jobId: string) =>
  invokeProtection<ScanJob | void>("cancel_protection_scan", { jobId });

export const getScanSchedule = () =>
  invokeProtection<ScanSchedule>("get_protection_scan_schedule");

export const setScanSchedule = (
  schedule: Pick<
    ScanSchedule,
    "enabled" | "frequency" | "scope" | "local_time" | "weekday"
  >,
) =>
  invokeProtection<ScanSchedule>("set_protection_scan_schedule", {
    enabled: schedule.enabled,
    frequency: schedule.frequency,
    scope: schedule.scope,
    localTime: schedule.local_time,
    weekday: schedule.weekday,
  });

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
  invokeProtection<QuarantineRestoreResult>("restore_quarantine_item", {
    itemId,
  });
