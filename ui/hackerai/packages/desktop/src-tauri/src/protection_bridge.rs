//! Typed bridge from the bundled Windows dashboard to the local protection service.
//!
//! The service named-pipe server and installer are separate deliverables. Until
//! that endpoint is present, transport failures are returned as an explicit
//! unavailable error; this module never manufactures protection data.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tauri::WebviewWindow;
use url::Url;

const PIPE_NAME: &str = r"\\.\pipe\STAI.Protection.v1";
const PROTOCOL_VERSION: u16 = 1;
const MAX_FRAME_BYTES: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ScanScope {
    Quick,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProtectionCounts {
    pub detected: Option<u64>,
    pub blocked: Option<u64>,
    pub quarantined: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WindowsSecurityStatus {
    pub registered_av_provider: Option<String>,
    pub defender_mode: Option<String>,
    pub query_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProtectionStatus {
    pub state: String,
    pub driver_state: Option<String>,
    pub service_state: Option<String>,
    pub rules_version: Option<String>,
    pub last_scan: Option<String>,
    pub counts: Option<ProtectionCounts>,
    pub windows_security: Option<WindowsSecurityStatus>,
    pub sensor_coverage: Option<Value>,
    pub sensors: Option<Value>,
    pub sensor_error: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ScanJob {
    pub job_id: String,
    pub scope: ScanScope,
    pub state: String,
    pub files_scanned: u64,
    pub files_total: Option<u64>,
    pub detections: u64,
    pub errors: u64,
    #[serde(default)]
    pub files_skipped: u64,
    #[serde(default)]
    pub unknown_verdicts: u64,
    #[serde(default)]
    pub engine_version: Option<String>,
    #[serde(default)]
    pub rules_version: Option<String>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub root_snapshot: Vec<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ScanSchedule {
    pub enabled: bool,
    pub frequency: String,
    pub scope: String,
    pub local_time: String,
    pub weekday: Option<u8>,
    pub next_run_at: Option<String>,
    pub last_run_at: Option<String>,
    pub last_job_id: Option<String>,
    pub last_result: Option<String>,
    pub error_message: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DetectionRecord {
    pub detection_id: String,
    pub action: String,
    pub confidence: String,
    pub severity: String,
    pub file_type: Option<String>,
    pub size_bytes: Option<u64>,
    pub file_path: Option<String>,
    pub created_at: String,
    pub triage_enqueued: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TriageRecord {
    pub triage_id: String,
    pub detection_id: String,
    pub summary: Option<String>,
    #[serde(default)]
    pub recommendations: Vec<String>,
    pub state: String,
    pub error: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Persisted triage rows do not carry a separate triage id or recommendations.
/// Adapt them here to the stable dashboard contract used by the HTTP adapter.
#[derive(Debug, Clone, Deserialize)]
struct StoredTriageRecord {
    pub detection_id: String,
    pub status: String,
    pub summary: Option<String>,
    pub error: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<StoredTriageRecord> for TriageRecord {
    fn from(record: StoredTriageRecord) -> Self {
        Self {
            triage_id: record.detection_id.clone(),
            detection_id: record.detection_id,
            summary: record.summary,
            recommendations: Vec::new(),
            state: record.status,
            error: record.error,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AgentMessageRecord {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AgentHistory {
    pub session_id: String,
    #[serde(default)]
    pub messages: Vec<AgentMessageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AgentReply {
    pub session_id: String,
    pub message: String,
    #[serde(default)]
    pub tool_calls: Vec<Value>,
    pub response_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct QuarantineItem {
    pub item_id: String,
    pub original_path: String,
    pub quarantined_path: Option<String>,
    pub sha256: String,
    pub rule_id: String,
    pub rule_version: String,
    pub action_result: String,
    pub detection_id: String,
    pub created_at: String,
    pub restored_at: Option<String>,
    pub restore_result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct QuarantineRestoreResult {
    pub success: bool,
    pub item: Option<QuarantineItem>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ProtectionOperation {
    GetStatus,
    StartScan,
    GetScan,
    CancelScan,
    GetScanSchedule,
    SetScanSchedule,
    ListThreats,
    GetTriage,
    RequestTriage,
    GetAgentHistory,
    SendAgentMessage,
    ListQuarantine,
    RestoreQuarantine,
}

#[derive(Debug, Serialize)]
struct PipeRequest<'a, P> {
    version: u16,
    request_id: &'a str,
    operation: ProtectionOperation,
    payload: P,
}

#[derive(Debug, Deserialize)]
struct PipeResponse<T> {
    version: u16,
    request_id: String,
    ok: bool,
    #[serde(default)]
    data: Option<T>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct EmptyPayload {}

#[derive(Debug, Serialize)]
struct ScopePayload {
    scope: ScanScope,
}

#[derive(Debug, Serialize)]
struct ScanSchedulePayload<'a> {
    enabled: bool,
    frequency: &'a str,
    scope: ScanScope,
    local_time: &'a str,
    weekday: Option<u8>,
}

#[derive(Debug, Serialize)]
struct JobIdPayload<'a> {
    job_id: &'a str,
}

#[derive(Debug, Serialize)]
struct DetectionIdPayload<'a> {
    detection_id: &'a str,
}

#[derive(Debug, Serialize)]
struct SessionIdPayload<'a> {
    session_id: &'a str,
}

#[derive(Debug, Serialize)]
struct ItemIdPayload<'a> {
    item_id: &'a str,
}

#[derive(Debug, Serialize)]
struct AgentMessagePayload<'a> {
    session_id: &'a str,
    message: &'a str,
    detection_id: Option<&'a str>,
}

fn unavailable_error() -> String {
    "protection service unavailable".to_string()
}

fn ensure_local_dashboard(window: &WebviewWindow) -> Result<(), String> {
    let url = window
        .url()
        .map_err(|_| "unable to verify protection dashboard origin".to_string())?;
    ensure_local_dashboard_url(&url)
}

fn ensure_local_dashboard_url(url: &Url) -> Result<(), String> {
    let protocol = url.scheme();
    let host = url.host_str().unwrap_or_default();
    let is_bundle = (protocol == "tauri" && host == "localhost")
        || (protocol == "http" && host == "tauri.localhost");
    let is_dev = protocol == "http"
        && (host == "127.0.0.1" || host == "localhost")
        && url.port() == Some(1420);
    if is_bundle || is_dev {
        Ok(())
    } else {
        Err("protection commands are restricted to the local STAI dashboard".to_string())
    }
}

fn validate_scope(scope: &str) -> Result<ScanScope, String> {
    match scope {
        "quick" => Ok(ScanScope::Quick),
        "system" => Ok(ScanScope::System),
        _ => Err("scan scope must be quick or system".to_string()),
    }
}

async fn request<T: for<'de> Deserialize<'de>, P: Serialize>(
    operation: ProtectionOperation,
    payload: P,
) -> Result<T, String> {
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let request = PipeRequest {
        version: PROTOCOL_VERSION,
        request_id: &request_id,
        operation,
        payload,
    };
    let body = serde_json::to_vec(&request)
        .map_err(|_| "unable to encode protection request".to_string())?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err("protection request exceeds the IPC frame limit".to_string());
    }
    let framed = frame(&body)?;
    let response_body = exchange_frame(&framed).await?;
    let response: PipeResponse<T> = serde_json::from_slice(&response_body)
        .map_err(|_| "invalid response from protection service".to_string())?;
    if response.version != PROTOCOL_VERSION || response.request_id != request_id {
        return Err("protection service response did not match the request".to_string());
    }
    if !response.ok {
        return Err(response.error.unwrap_or_else(|| "protection request failed".to_string()));
    }
    response
        .data
        .ok_or_else(|| "protection service returned no result".to_string())
}

fn frame(body: &[u8]) -> Result<Vec<u8>, String> {
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err("protection IPC frame exceeds the size limit".to_string());
    }
    let length = u32::try_from(body.len())
        .map_err(|_| "protection IPC frame exceeds the size limit".to_string())?;
    let mut bytes = Vec::with_capacity(4 + body.len());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(body);
    Ok(bytes)
}

#[cfg(windows)]
async fn exchange_frame(frame: &[u8]) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;

    let result = tokio::time::timeout(IO_TIMEOUT, async {
        let mut pipe = ClientOptions::new()
            .open(PIPE_NAME)
            .map_err(|_| unavailable_error())?;
        pipe.write_all(frame)
            .await
            .map_err(|_| unavailable_error())?;
        pipe.flush().await.map_err(|_| unavailable_error())?;

        let mut header = [0u8; 4];
        pipe.read_exact(&mut header)
            .await
            .map_err(|_| unavailable_error())?;
        let length = u32::from_le_bytes(header) as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            return Err("protection service response exceeds the IPC frame limit".to_string());
        }
        let mut body = vec![0u8; length];
        pipe.read_exact(&mut body)
            .await
            .map_err(|_| unavailable_error())?;
        Ok(body)
    })
    .await
    .map_err(|_| "protection service request timed out".to_string())?;
    result
}

#[cfg(not(windows))]
async fn exchange_frame(_frame: &[u8]) -> Result<Vec<u8>, String> {
    let _ = (PIPE_NAME, IO_TIMEOUT);
    Err(unavailable_error())
}

#[tauri::command]
pub(crate) async fn get_protection_status(
    window: WebviewWindow,
) -> Result<ProtectionStatus, String> {
    ensure_local_dashboard(&window)?;
    request(ProtectionOperation::GetStatus, EmptyPayload {}).await
}

#[tauri::command]
pub(crate) async fn start_protection_scan(
    window: WebviewWindow,
    scope: String,
) -> Result<ScanJob, String> {
    ensure_local_dashboard(&window)?;
    let payload = ScopePayload { scope: validate_scope(&scope)? };
    request(ProtectionOperation::StartScan, payload).await
}

#[tauri::command]
pub(crate) async fn get_protection_scan(
    window: WebviewWindow,
    job_id: String,
) -> Result<ScanJob, String> {
    ensure_local_dashboard(&window)?;
    request(ProtectionOperation::GetScan, JobIdPayload { job_id: &job_id }).await
}

#[tauri::command]
pub(crate) async fn cancel_protection_scan(
    window: WebviewWindow,
    job_id: String,
) -> Result<ScanJob, String> {
    ensure_local_dashboard(&window)?;
    request(ProtectionOperation::CancelScan, JobIdPayload { job_id: &job_id }).await
}

#[tauri::command]
pub(crate) async fn get_protection_scan_schedule(
    window: WebviewWindow,
) -> Result<ScanSchedule, String> {
    ensure_local_dashboard(&window)?;
    request(ProtectionOperation::GetScanSchedule, EmptyPayload {}).await
}

#[tauri::command]
pub(crate) async fn set_protection_scan_schedule(
    window: WebviewWindow,
    enabled: bool,
    frequency: String,
    scope: String,
    local_time: String,
    weekday: Option<u8>,
) -> Result<ScanSchedule, String> {
    ensure_local_dashboard(&window)?;
    if !matches!(frequency.as_str(), "daily" | "weekly") {
        return Err("schedule frequency must be daily or weekly".to_string());
    }
    let scan_scope = validate_scope(&scope)?;
    if !valid_local_time(&local_time) {
        return Err("schedule time must use HH:MM".to_string());
    }
    if frequency == "weekly" && !matches!(weekday, Some(0..=6)) {
        return Err("weekly schedules require a weekday from 0 through 6".to_string());
    }
    if frequency == "daily" && weekday.is_some() {
        return Err("daily schedules do not accept a weekday".to_string());
    }
    request(
        ProtectionOperation::SetScanSchedule,
        ScanSchedulePayload {
            enabled,
            frequency: &frequency,
            scope: scan_scope,
            local_time: &local_time,
            weekday,
        },
    )
    .await
}

fn valid_local_time(value: &str) -> bool {
    let mut parts = value.split(':');
    let (Some(hour), Some(minute), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    hour.len() == 2
        && minute.len() == 2
        && hour.parse::<u8>().is_ok_and(|number| number <= 23)
        && minute.parse::<u8>().is_ok_and(|number| number <= 59)
}

#[tauri::command]
pub(crate) async fn list_protection_threats(
    window: WebviewWindow,
) -> Result<Vec<DetectionRecord>, String> {
    ensure_local_dashboard(&window)?;
    request(ProtectionOperation::ListThreats, EmptyPayload {}).await
}

#[tauri::command]
pub(crate) async fn get_protection_triage(
    window: WebviewWindow,
    detection_id: String,
) -> Result<TriageRecord, String> {
    ensure_local_dashboard(&window)?;
    request::<StoredTriageRecord, _>(
        ProtectionOperation::GetTriage,
        DetectionIdPayload { detection_id: &detection_id },
    )
    .await
    .map(Into::into)
}

#[tauri::command]
pub(crate) async fn request_protection_triage(
    window: WebviewWindow,
    detection_id: String,
) -> Result<TriageRecord, String> {
    ensure_local_dashboard(&window)?;
    request::<StoredTriageRecord, _>(
        ProtectionOperation::RequestTriage,
        DetectionIdPayload { detection_id: &detection_id },
    )
    .await
    .map(Into::into)
}

#[tauri::command]
pub(crate) async fn get_protection_agent_history(
    window: WebviewWindow,
    session_id: String,
) -> Result<AgentHistory, String> {
    ensure_local_dashboard(&window)?;
    request(ProtectionOperation::GetAgentHistory, SessionIdPayload { session_id: &session_id }).await
}

#[tauri::command]
pub(crate) async fn send_protection_agent_message(
    window: WebviewWindow,
    session_id: String,
    message: String,
    detection_id: Option<String>,
) -> Result<AgentReply, String> {
    ensure_local_dashboard(&window)?;
    if message.trim().is_empty() || message.len() > 2_000 {
        return Err("agent message must contain between 1 and 2000 bytes".to_string());
    }
    let payload = AgentMessagePayload {
        session_id: &session_id,
        message: message.trim(),
        detection_id: detection_id.as_deref(),
    };
    request(ProtectionOperation::SendAgentMessage, payload).await
}

#[tauri::command]
pub(crate) async fn list_quarantine_items(
    window: WebviewWindow,
) -> Result<Vec<QuarantineItem>, String> {
    ensure_local_dashboard(&window)?;
    request(ProtectionOperation::ListQuarantine, EmptyPayload {}).await
}

#[tauri::command]
pub(crate) async fn restore_quarantine_item(
    window: WebviewWindow,
    item_id: String,
) -> Result<QuarantineRestoreResult, String> {
    ensure_local_dashboard(&window)?;
    request(ProtectionOperation::RestoreQuarantine, ItemIdPayload { item_id: &item_id }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bridge_rejects_unknown_scope() {
        assert_eq!(validate_scope("quick").unwrap(), ScanScope::Quick);
        assert_eq!(validate_scope("system").unwrap(), ScanScope::System);
        assert!(validate_scope("C:\\").is_err());
        assert!(validate_scope("arbitrary").is_err());
    }

    #[test]
    fn bridge_has_no_shell_command_operation() {
        let operations = [
            ProtectionOperation::GetStatus,
            ProtectionOperation::StartScan,
            ProtectionOperation::GetScan,
            ProtectionOperation::CancelScan,
            ProtectionOperation::GetScanSchedule,
            ProtectionOperation::SetScanSchedule,
            ProtectionOperation::ListThreats,
            ProtectionOperation::GetTriage,
            ProtectionOperation::RequestTriage,
            ProtectionOperation::GetAgentHistory,
            ProtectionOperation::SendAgentMessage,
            ProtectionOperation::ListQuarantine,
            ProtectionOperation::RestoreQuarantine,
        ];
        let encoded = operations
            .iter()
            .map(|operation| serde_json::to_string(operation).unwrap())
            .collect::<Vec<_>>();
        assert!(!encoded.iter().any(|value| value.contains("shell")));
        assert!(!encoded.iter().any(|value| value.contains("file_command")));
        assert_eq!(encoded.len(), 13);
    }

    #[test]
    fn bridge_maps_service_unavailable_to_error() {
        assert_eq!(unavailable_error(), "protection service unavailable");
    }

    #[test]
    fn bridge_serializes_status_contract() {
        let status = ProtectionStatus {
            state: "degraded".to_string(),
            driver_state: Some("stopped".to_string()),
            service_state: Some("running".to_string()),
            rules_version: None,
            last_scan: None,
            counts: None,
            windows_security: None,
            sensor_coverage: None,
            last_error: Some("driver not loaded".to_string()),
        };
        let value = serde_json::to_value(status).unwrap();
        assert_eq!(value["state"], "degraded");
        assert_eq!(value["driver_state"], "stopped");
        assert!(value["counts"].is_null());
    }

    #[test]
    fn bridge_rejects_hosted_origin() {
        let hosted = Url::parse("https://hackerai.co/").unwrap();
        let local = Url::parse("http://tauri.localhost/").unwrap();
        let dev = Url::parse("http://127.0.0.1:1420/").unwrap();
        assert!(ensure_local_dashboard_url(&hosted).is_err());
        assert!(ensure_local_dashboard_url(&local).is_ok());
        assert!(ensure_local_dashboard_url(&dev).is_ok());
    }

    #[test]
    fn bridge_agent_chat_is_typed() {
        let payload = AgentMessagePayload {
            session_id: "sess-1",
            message: "Explain this detection",
            detection_id: Some("det-1"),
        };
        let value = serde_json::to_value(payload).unwrap();
        assert_eq!(value, json!({
            "session_id": "sess-1",
            "message": "Explain this detection",
            "detection_id": "det-1"
        }));
        assert_eq!(value.as_object().unwrap().len(), 3);
    }

    #[test]
    fn bridge_scan_schedule_payload_is_typed_and_time_is_validated() {
        let payload = ScanSchedulePayload {
            enabled: true,
            frequency: "weekly",
            scope: ScanScope::Quick,
            local_time: "09:30",
            weekday: Some(2),
        };
        assert_eq!(serde_json::to_value(payload).unwrap(), json!({
            "enabled": true,
            "frequency": "weekly",
            "scope": "quick",
            "local_time": "09:30",
            "weekday": 2
        }));
        assert!(valid_local_time("00:00"));
        assert!(valid_local_time("23:59"));
        assert!(!valid_local_time("24:00"));
        assert!(!valid_local_time("9:30"));
    }

    #[test]
    fn bridge_scan_job_reads_persisted_outcome_fields_and_legacy_defaults() {
        let job: ScanJob = serde_json::from_value(json!({
            "job_id": "job-1",
            "scope": "quick",
            "state": "completed",
            "files_scanned": 2,
            "files_total": 2,
            "detections": 0,
            "errors": 0,
            "started_at": null,
            "completed_at": null,
            "error_message": null
        }))
        .unwrap();
        assert_eq!(job.files_skipped, 0);
        assert!(job.root_snapshot.is_empty());
        assert_eq!(job.engine_version, None);
    }

    #[test]
    fn bridge_uses_resource_specific_ids() {
        assert_eq!(
            serde_json::to_value(JobIdPayload { job_id: "job-1" }).unwrap(),
            json!({ "job_id": "job-1" })
        );
        assert_eq!(
            serde_json::to_value(DetectionIdPayload { detection_id: "det-1" }).unwrap(),
            json!({ "detection_id": "det-1" })
        );
        assert_eq!(
            serde_json::to_value(SessionIdPayload { session_id: "sess-1" }).unwrap(),
            json!({ "session_id": "sess-1" })
        );
        assert_eq!(
            serde_json::to_value(ItemIdPayload { item_id: "item-1" }).unwrap(),
            json!({ "item_id": "item-1" })
        );
    }

    #[test]
    fn bridge_adapts_stored_triage_to_stable_dashboard_contract() {
        let record: StoredTriageRecord = serde_json::from_value(json!({
            "detection_id": "det-1",
            "status": "queued",
            "summary": null,
            "error": null,
            "created_at": null,
            "updated_at": null
        }))
        .unwrap();
        let adapted = TriageRecord::from(record);
        assert_eq!(adapted.triage_id, "det-1");
        assert_eq!(adapted.detection_id, "det-1");
        assert_eq!(adapted.state, "queued");
        assert_eq!(adapted.summary, None);
        assert!(adapted.recommendations.is_empty());
    }

    #[test]
    fn pipe_frames_are_bounded_and_length_prefixed() {
        let framed = frame(b"{}").unwrap();
        assert_eq!(&framed[..4], &2u32.to_le_bytes());
        assert_eq!(&framed[4..], b"{}");
        assert!(frame(&vec![0; MAX_FRAME_BYTES + 1]).is_err());
    }
}
