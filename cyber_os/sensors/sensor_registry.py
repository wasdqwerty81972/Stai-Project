"""Canonical, auditable registry for SVS-Cyber's 256 logical sensors.

Registry entries describe capabilities and their best-fit telemetry sources.
They do not claim an adapter is installed or running. Runtime collection state
is attached separately by :func:`build_runtime_registry`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence


REGISTRY_VERSION = "1.0.0"
_DATA_PATH = Path(__file__).with_name("sensor_registry_data.json")

# The first implementation request used a separate Phase 1 numbering scheme.
# Keep those IDs as aliases while catalog IDs remain stable at 1..256.
PHASE1_TO_REGISTRY_ID: dict[int, int] = {
    1: 1,    # Process Creation
    3: 3,    # Parent-Child Process -> Parent Process
    6: 17,   # Cross-Process Access -> Process Handle Access
    17: 49,  # File Creation
    18: 50,  # File Modification
    19: 51,  # File Deletion
    25: 65,  # Registry Autorun
    26: 67,  # Scheduled Task
    27: 68,  # Service Installation -> Service Persistence
    33: 89,  # DNS Query
    35: 97,  # Outbound Connection
    49: 129, # Login Success -> Successful Login
    50: 130, # Login Failure -> Failed Login
    58: 180, # Security Service Integrity -> Security Service Health
}

_PHASE1_NAMES = {
    1: "Process Creation",
    3: "Parent-Child Process",
    6: "Cross-Process Access",
    17: "File Creation",
    18: "File Modification",
    19: "File Deletion",
    25: "Registry Autorun",
    26: "Scheduled Task",
    27: "Service Installation",
    33: "DNS Query",
    35: "Outbound Connection",
    49: "Login Success",
    50: "Login Failure",
    58: "Security Service Integrity",
}


# One profile per catalogue subcategory (eight entries). These are shared
# sources: multiple logical sensors intentionally reference the same collector.
# Values: source, collector, method, permissions, cost, event-specific fields.
_PROFILES: dict[int, tuple[str, str, str, tuple[str, ...], str, tuple[str, ...]]] = {
    1: ("Windows Security 4688/4689; optionally Sysmon process events", "windows.security_eventlog", "Shared Windows Event Log reader; process lifecycle rules derive from the same stream", ("Read Security event log", "Matching audit policy or configured Sysmon provider"), "low", ("process", "pid", "parent_pid", "image", "command_line_if_allowed")),
    2: ("Windows Authenticode/WinVerifyTrust, PE metadata, downloaded-file zone identifier", "windows.file_metadata", "Bounded file enrichment on observed executables; no continuous full-disk scan", ("Read access to observed executable files",), "moderate", ("path_or_hash", "signature", "publisher", "file_version", "origin")),
    3: ("Windows Security object-access audit; optional Sysmon ProcessAccess/CreateRemoteThread", "windows.security_eventlog", "Shared event-log stream; detailed memory/thread telemetry requires an optional provider", ("Read Security event log", "Object Access audit policy or configured Sysmon/EDR source"), "moderate", ("source_pid", "target_pid", "requested_access", "operation")),
    4: ("Windows ETW/EDR process-memory telemetry; no general-purpose event-log source", "windows.optional_endpoint_telemetry", "Optional provider adapter; rule correlations reuse process and access events", ("Provider-specific monitoring permission", "Optional EDR or supported ETW provider"), "high", ("process_id", "region_attributes", "access_type", "provider_evidence")),
    5: ("PowerShell Operational, Security process events, WMI Activity, Office security logs", "windows.operational_eventlog", "Shared operational-log readers with provider-specific event filters", ("Read relevant Operational channels", "Script or application logging enabled where applicable"), "low", ("process", "host", "script_metadata_if_enabled", "provider_event_id")),
    6: ("Sysmon image-load/driver events; Windows Code Integrity and System logs", "windows.operational_eventlog", "Shared event-log stream with optional Sysmon enrichment", ("Read relevant event logs", "Sysmon configuration for image-load detail when used"), "moderate", ("process", "module", "signature_state", "driver_service")),
    7: ("Windows Security 4663/4660; NTFS USN change journal; optional minifilter", "windows.filesystem", "Shared audited-file stream or scoped journal watcher; hashes and bulk activity are derived", ("Read Security log", "Object Access audit policy", "Read access to configured monitored paths"), "moderate", ("path_or_hash", "operation", "actor", "access_mask")),
    8: ("NTFS metadata/USN journal, Authenticode, alternate data stream and file inspection APIs", "windows.file_metadata", "Bounded enrichment and derived rules over files already observed", ("Read access to configured monitored files",), "moderate", ("file_hash", "signature", "origin", "stream_name", "file_type")),
    9: ("Security 4657/4697, System 7045, Task Scheduler and WMI Activity logs", "windows.persistence_eventlog", "Shared Security/System/Operational event-log readers; correlate persistence records", ("Read Security, System and relevant Operational logs", "Applicable audit policy enabled"), "low", ("registry_key_or_task_or_service", "operation", "actor_if_logged")),
    10: ("Security registry auditing, Group Policy Operational, hosts file and network configuration", "windows.configuration_watch", "Registry change notifications plus scoped file/config snapshots", ("Read configured registry keys and files", "Read relevant event logs"), "low", ("setting_name", "old_value_hash", "new_value_hash", "actor_if_logged")),
    11: ("Windows boot configuration, Secure Boot/TPM WMI, Code Integrity and System logs", "windows.posture_snapshot", "Read-only posture snapshots plus shared event-log subscriptions", ("Read system posture APIs", "Administrative access may be required for selected details"), "low", ("setting", "state", "measurement", "observed_at")),
    12: ("DNS Client Operational event 3008 and resolver configuration APIs", "windows.dns_eventlog", "Shared DNS Client Operational reader; repeated-failure and address rules are derived", ("Read DNS Client Operational log", "Channel enabled for query visibility"), "low", ("query_hash_or_name", "result", "status", "server", "process_if_available")),
    13: ("Windows Filtering Platform Security events 5156/5157; optional ETW network events", "windows.wfp_eventlog", "Shared WFP/network event source; process mapping and frequency are derived", ("Read Security event log", "Filtering Platform Connection auditing enabled"), "moderate", ("direction", "local_endpoint", "remote_endpoint", "process_if_available", "bytes_if_available")),
    14: ("Windows Firewall log and firewall configuration APIs; VPN/provider operational logs", "windows.firewall_eventlog", "Shared firewall event stream plus low-frequency read-only policy snapshots", ("Read firewall logs and configuration", "Firewall auditing enabled for traffic detail"), "low", ("rule", "direction", "action", "policy_state", "tunnel_state")),
    15: ("Windows SMB, Terminal Services, OpenSSH, DHCP, LDAP and network ETW providers", "windows.protocol_eventlog", "Shared provider-log adapters; payload contents are not inspected", ("Read enabled protocol Operational/Security logs",), "moderate", ("protocol", "connection_metadata", "session_id", "result")),
    16: ("Windows IP Helper, WLAN AutoConfig, NetworkList, PnP and Bluetooth APIs", "windows.network_state", "OS change notifications with low-frequency state reconciliation", ("Read network/device state", "Some device details require elevated access"), "low", ("interface", "address_hash", "gateway", "ssid_if_allowed", "device_class")),
    17: ("Windows Security 4624/4625 and account/group audit events", "windows.security_eventlog", "Shared Security event-log reader; authentication patterns are derived", ("Read Security event log", "Account Logon and Account Management audit policies"), "low", ("account_hash", "logon_type", "source_address", "result", "session_id")),
    18: ("Windows Security 4720/4726/4732/4733/4672 and related account audit events", "windows.security_eventlog", "Shared Security event-log reader; service-account anomalies are derived", ("Read Security event log", "Account Management and Privilege Use audit policies"), "low", ("account_hash", "group", "privilege", "operation", "source_address")),
    19: ("Browser policy/extension metadata, profile metadata when allowed, and download zone identifiers", "windows.browser_integration", "Scoped browser adapter or policy snapshot; privacy-sensitive browsing data requires consent", ("Read permitted browser metadata", "Browser-specific integration or policy access"), "moderate", ("browser", "extension_id", "permission_change", "download_origin")),
    20: ("Microsoft Graph/email security provider audit APIs and collaboration audit logs", "cloud.collaboration_connectors", "Optional tenant integration using explicit least-privilege OAuth scopes", ("Configured provider account", "Read-only OAuth scopes and securely stored credentials"), "moderate", ("provider", "tenant", "principal_hash", "message_or_resource_metadata", "operation")),
    21: ("Windows Installer/AppX deployment events and installed-software inventory", "windows.application_eventlog", "Shared installer/package events with bounded inventory enrichment", ("Read application inventory and relevant event logs",), "low", ("package", "version", "publisher", "install_operation")),
    22: ("Kernel-PnP, DriverFrameworks, DeviceSetupManager and removable-storage events", "windows.device_eventlog", "Shared device event-log reader; sensitive device metadata is minimized", ("Read device Operational logs", "Device details may require elevated access"), "low", ("device_class", "device_id_hash", "mount_state", "permission_state")),
    23: ("Windows Security Center, Defender Operational and security-service state APIs", "windows.security_product", "Shared Defender/security-provider events with read-only posture checks", ("Read Defender and System event logs", "Read Security Center/provider status"), "low", ("product", "service_state", "protection_state", "event_type")),
    24: ("Windows performance counters, System events, WER and storage health APIs", "windows.system_health", "Low-frequency shared health sampling plus relevant system event logs", ("Read system counters and event logs", "Storage details are device-dependent"), "low", ("resource", "value", "threshold", "health_state")),
    25: ("Windows Security 1102/4719, System 104/4616, EventLog service and channel settings", "windows.audit_health", "Shared event-log reader and bounded audit/logging posture checks", ("Read Security and System logs", "Read event-channel configuration"), "low", ("channel", "audit_setting", "change", "loss_count")),
    26: ("Docker/containerd/HCS and Hyper-V event logs/APIs when runtimes are installed", "windows.virtualization_integrations", "Optional runtime adapters sharing provider subscriptions", ("Read configured container/VM runtime APIs and logs",), "moderate", ("runtime", "container_or_vm_id", "image", "policy", "operation")),
    27: ("Linux auditd, eBPF, fanotify, journald and systemd sources", "linux.endpoint_adapters", "Separate Linux agent adapters; no Windows collector", ("Linux audit/eBPF/fanotify permissions as configured", "Root or scoped capabilities may be required"), "moderate", ("process", "filesystem", "authentication", "service_change")),
    28: ("macOS EndpointSecurity, FSEvents, launchd and unified logging", "macos.endpoint_adapters", "Separate signed macOS system-extension/agent adapters", ("EndpointSecurity entitlement and user/system approval", "Required Full Disk Access where applicable"), "moderate", ("process", "file", "mount", "extension", "code_signature")),
    29: ("Android PackageManager, UsageStatsManager, ConnectivityManager and user-approved VpnService", "android.endpoint_adapters", "Separate Android app/service using documented permission-gated APIs", ("Runtime permissions", "Usage Access or user-enabled VpnService where applicable"), "moderate", ("package", "permission", "network_metadata", "device_posture")),
    30: ("Cloud provider audit APIs/logs (CloudTrail, Azure Activity, Google Cloud Audit Logs)", "cloud.audit_connectors", "Provider-specific pull/webhook connectors with durable cursors", ("Configured cloud account", "Read-only audit/log scopes and securely stored credentials"), "moderate", ("provider", "account", "principal_hash", "resource", "operation")),
    31: ("Authorized router/gateway syslog, SNMP or vendor APIs; compatible IDS alerts", "network.infrastructure_connectors", "Configured infrastructure integrations; no host listener can substitute", ("Authorized device/API credentials or syslog subscription",), "moderate", ("device", "source", "event_type", "network_metadata", "health")),
    32: ("SVS-Cyber internal worker, queue, configuration and investigation acknowledgements", "svscyber.internal_health", "In-process counters and explicit stage acknowledgements; no duplicate OS collector", ("Read local agent state and protected configuration metadata",), "low", ("component", "heartbeat", "queue_depth", "drop_count", "stage", "error_code")),
}

_SCHEMA_FIELDS = ("sensor_ids", "timestamp", "event_id", "event_type", "source", "category", "severity", "details")
_PHASE1_STATUS = {
    1: "implemented", 3: "implemented", 17: "partial", 49: "partial",
    50: "partial", 51: "partial", 65: "partial", 67: "partial",
    68: "partial", 89: "partial", 97: "partial", 129: "partial",
    130: "partial", 180: "partial",
}
_DERIVED_IDS = {
    6, 8, 12, 15, 24, 32, 56, 62, 63, 93, 94, 95, 96, 103, 104,
    111, 112, 131, 143, 144, 152, 166, 189, 190, 191, 200,
    249, 250, 251, 252, 253, 254, 255, 256,
}
_POSTURE_IDS = {
    82, 83, 84, 86, 88, 108, 112, 177, 178, 181, 184,
    185, 186, 187, 188, 192, 195, 199, 239, 248,
}
_DERIVED_INPUTS = {
    6: [1, 2], 8: [1, 2], 24: [17, 18, 19, 20, 21, 22, 23],
    32: [25, 26, 27, 28, 29, 30, 31], 56: [49, 50, 51],
    62: [57, 58], 63: [50, 57], 93: [89], 94: [89, 91],
    95: [92], 96: [89, 90], 103: [97, 101], 104: [97],
    111: [99, 100], 112: [107, 108], 131: [130],
    143: [137, 138], 144: [1, 7, 129], 152: [149, 150],
    166: [161, 163], 189: [1, 2], 190: [192], 191: [180],
    200: [196, 199],
}


def _windows_support(sensor_id: int) -> str:
    if 209 <= sensor_id <= 232:
        return "unsupported"
    if 233 <= sensor_id <= 248:
        return "integration_required"
    if 201 <= sensor_id <= 208:
        return "conditional"
    if sensor_id >= 249:
        return "partial" if sensor_id in {249, 251, 252, 256} else "conditional"
    if sensor_id in _PHASE1_STATUS:
        return "partial" if _PHASE1_STATUS[sensor_id] == "partial" else "conditional"
    if 145 <= sensor_id <= 160:
        return "integration_required"
    return "conditional"


def _platform_support(sensor_id: int) -> dict[str, str]:
    support = {"windows": "unsupported", "linux": "unsupported", "macos": "unsupported", "android": "unsupported", "cloud": "not_applicable", "network_infrastructure": "not_applicable"}
    if sensor_id <= 200:
        support.update({"windows": "conditional", "linux": "conditional", "macos": "conditional"})
        if sensor_id in _PHASE1_STATUS:
            support["windows"] = "partial" if _PHASE1_STATUS[sensor_id] == "partial" else "conditional"
        if 145 <= sensor_id <= 160:
            support["windows"] = "integration_required"
        if sensor_id >= 169 and sensor_id <= 176:
            support["android"] = "conditional"
    elif 201 <= sensor_id <= 208:
        support.update({"windows": "conditional", "linux": "conditional", "macos": "conditional"})
    elif 209 <= sensor_id <= 216:
        support["linux"] = "native"
    elif 217 <= sensor_id <= 224:
        support["macos"] = "native"
    elif 225 <= sensor_id <= 232:
        support["android"] = "conditional"
    elif 233 <= sensor_id <= 240:
        support["cloud"] = "integration_required"
    elif 241 <= sensor_id <= 248:
        support["network_infrastructure"] = "integration_required"
    else:
        support.update({"windows": "partial", "linux": "partial", "macos": "partial", "android": "partial"})
    return support


def _kind(sensor_id: int) -> str:
    if 249 <= sensor_id <= 256:
        return "health_check"
    if sensor_id in _DERIVED_IDS:
        return "derived_detection"
    if sensor_id in _POSTURE_IDS:
        return "posture_check"
    if 233 <= sensor_id <= 248 or 145 <= sensor_id <= 160:
        return "external_integration"
    if sensor_id in {9, 10, 12, 13, 14, 15, 16, 43, 44, 45, 48, 57, 58, 62, 63, 166}:
        return "enrichment"
    return "collector"


def _specific_source(sensor_id: int, fallback: str) -> str:
    return {
        1: "Windows Security event 4688 (Process Creation audit); existing audit policy is not changed",
        3: "Windows Security event 4688 parent process fields when emitted by the provider",
        17: "Windows Security event 4656 for ObjectType=Process (partial access evidence)",
        49: "Windows Security event 4663 write/add access (create versus modify can be ambiguous)",
        50: "Windows Security event 4663 audited write/change access",
        51: "Windows Security event 4660 deletion (path may require correlation with 4663)",
        65: "Windows Security event 4657 for allowlisted autorun registry locations",
        67: "Windows Security events 4698/4699/4700/4701/4702 for scheduled tasks",
        68: "Windows Security event 4697 and System event 7045 for service installation",
        89: "DNS Client Operational event 3008 for locally observed DNS query metadata",
        97: "Windows Security event 5156 for WFP-allowed outbound connections",
        129: "Windows Security event 4624 for successful logons",
        130: "Windows Security event 4625 for failed logons",
        180: "Defender Operational event 5007 and System 7036/7040 for selected security services",
    }.get(sensor_id, fallback)


def _load_definitions() -> tuple[dict[str, Any], ...]:
    raw = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    definitions = []
    for item in raw:
        sensor_id = int(item["id"])
        group = (sensor_id - 1) // 8 + 1
        source, collector_id, method, permissions, cost, specific_fields = _PROFILES[group]
        status = _PHASE1_STATUS.get(sensor_id, "registered_only")
        kind = _kind(sensor_id)
        if kind == "derived_detection":
            method = "Derived rule over shared normalized source events; no separate collector"
        elif kind == "posture_check":
            method = "Read-only posture snapshot on a bounded interval; share the platform posture adapter"
        elif kind == "external_integration":
            method = "Optional, explicitly configured integration with least-privilege read-only scopes"
        if 209 <= sensor_id <= 232:
            status = "registered_only"
        details = {
            "id": sensor_id,
            "key": re.sub(r"[^a-z0-9]+", "_", item["name"].casefold()).strip("_"),
            "name": item["name"],
            "description": item["description"],
            "category": item["category"],
            "layer": 1 if sensor_id <= 64 else 2 if sensor_id <= 128 else 3 if sensor_id <= 192 else 4,
            "subcategory_number": group,
            "kind": kind,
            "platform_support": _platform_support(sensor_id),
            "telemetry_source": _specific_source(sensor_id, source),
            "shared_collector_id": collector_id,
            "required_permissions": list(permissions),
            "event_schema": {
                "id": "svs.normalized_sensor_event.v1",
                "required_fields": list(_SCHEMA_FIELDS),
                "specific_fields": list(specific_fields),
                "privacy": "minimize_and_redact_before_durable_storage",
            },
            "collection_method": method,
            "operational_status": status,
            "performance_cost": {"class": cost, "measured": False},
            "test_refs": ["tests/test_sensor_registry.py"] + (["tests/test_windows_sensor_service.py"] if sensor_id in _PHASE1_STATUS else []),
            "coverage_notes": "Source mapping only; runtime support, provider configuration, policy state, and event receipt are reported separately.",
            "derived_from": [],
            "phase1_requested_id": next((phase_id for phase_id, catalog_id in PHASE1_TO_REGISTRY_ID.items() if catalog_id == sensor_id), None),
            "phase1_requested_name": next((_PHASE1_NAMES[phase_id] for phase_id, catalog_id in PHASE1_TO_REGISTRY_ID.items() if catalog_id == sensor_id), None),
        }
        if sensor_id in _DERIVED_IDS:
            details["derived_from"] = _DERIVED_INPUTS.get(sensor_id, [])
        definitions.append(details)
    return tuple(definitions)


SENSOR_REGISTRY: tuple[dict[str, Any], ...] = _load_definitions()
REGISTRY_BY_ID: dict[int, dict[str, Any]] = {entry["id"]: entry for entry in SENSOR_REGISTRY}


def build_runtime_registry(
    platform_name: str,
    runtime_capabilities: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Return catalog metadata with independent current-host runtime evidence."""
    normalized_platform = platform_name.casefold()
    phase1_runtime: dict[int, Mapping[str, Any]] = {}
    for runtime in runtime_capabilities:
        registry_id = runtime.get("registry_id")
        if isinstance(registry_id, int) and 1 <= registry_id <= 256:
            phase1_runtime[registry_id] = runtime
            continue
        phase1_id = runtime.get("id")
        if isinstance(phase1_id, int) and phase1_id in PHASE1_TO_REGISTRY_ID:
            phase1_runtime[PHASE1_TO_REGISTRY_ID[phase1_id]] = runtime

    result = []
    for definition in SENSOR_REGISTRY:
        entry = dict(definition)
        entry["platform_support"] = dict(definition["platform_support"])
        entry["event_schema"] = dict(definition["event_schema"])
        entry["performance_cost"] = dict(definition["performance_cost"])
        entry["runtime_state"] = "registered_only"
        if normalized_platform.startswith("win"):
            entry["host_support"] = _windows_support(entry["id"])
            runtime = phase1_runtime.get(entry["id"])
            if runtime is not None:
                entry["runtime_state"] = str(runtime.get("state") or "unknown")
                entry["runtime_source_state"] = str(runtime.get("source_state") or "unknown")
                entry["runtime_error"] = runtime.get("error")
            elif entry["host_support"] == "unsupported":
                entry["runtime_state"] = "unsupported_on_this_host"
            elif entry["operational_status"] in {"implemented", "partial"}:
                entry["runtime_state"] = "stopped"
        else:
            entry["host_support"] = entry["platform_support"].get(normalized_platform, "not_applicable")
            if entry["operational_status"] in {"implemented", "partial"} and entry["host_support"] in {"native", "partial", "conditional"}:
                entry["runtime_state"] = "adapter_not_implemented_for_this_platform"
            elif entry["host_support"] in {"unsupported", "not_applicable"}:
                entry["runtime_state"] = "unsupported_on_this_host"
        result.append(entry)
    return result


def validate_registry(entries: Optional[Sequence[Mapping[str, Any]]] = None) -> None:
    """Fail fast on missing catalog IDs, duplicate keys, or incomplete metadata."""
    current = SENSOR_REGISTRY if entries is None else entries
    ids = [entry.get("id") for entry in current]
    if sorted(ids) != list(range(1, 257)):
        raise ValueError("Sensor registry must contain each catalog ID from 1 through 256 exactly once")
    keys = [entry.get("key") for entry in current]
    if len(keys) != len(set(keys)):
        raise ValueError("Sensor registry contains duplicate capability keys")
    required = {
        "id", "key", "name", "description", "category", "layer", "kind",
        "platform_support", "telemetry_source", "shared_collector_id",
        "required_permissions", "event_schema", "collection_method",
        "operational_status", "performance_cost", "test_refs",
    }
    for entry in current:
        missing = required - set(entry)
        if missing:
            raise ValueError(f"Sensor {entry.get('id')} missing metadata: {sorted(missing)}")
        if not entry["telemetry_source"] or not entry["required_permissions"] or not entry["event_schema"].get("id"):
            raise ValueError(f"Sensor {entry['id']} has incomplete source, permission, or event schema metadata")


validate_registry()

