"""Windows Event Log based endpoint sensors with a bounded durable queue.

This module never changes Windows audit policy and never installs Sysmon.  It
opens each supported event channel once, then maps that shared stream to the
logical capabilities below.  Event payloads are normalized before they are
written to SQLite; raw XML and unapproved personal fields are not persisted.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import sqlite3
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

from cyber_os.sensors.sensor_registry import PHASE1_TO_REGISTRY_ID


_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_UNAVAILABLE = "Windows Event Log source is unavailable."
_AUDIT_NOTE = "Source can be read; the related Windows audit policy and event coverage are not verified or changed by this service."


@dataclass(frozen=True)
class SensorCapability:
    """A logical sensor capability; several capabilities can share one source."""

    id: int
    key: str
    name: str
    source: str
    channels: tuple[str, ...]
    permissions: tuple[str, ...]
    coverage: str = "event-log"
    registry_id: int = 0


def _capability(request_id: int, name: str, source: str, channels: Sequence[str], permissions: str | Sequence[str], coverage: str = "event-log") -> SensorCapability:
    permission_items = (permissions,) if isinstance(permissions, str) else tuple(permissions)
    return SensorCapability(
        id=request_id,
        key=re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_"),
        name=name,
        source=source,
        channels=tuple(channels),
        permissions=permission_items,
        coverage=coverage,
        registry_id=PHASE1_TO_REGISTRY_ID.get(request_id, 0),
    )


SECURITY = "Security"
SYSTEM = "System"
DNS_CLIENT = "Microsoft-Windows-DNS-Client/Operational"
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
_READ_SECURITY = "Read access to the Security event log; existing audit policy must emit matching events."

CAPABILITIES: tuple[SensorCapability, ...] = (
    _capability(1, "Process Creation", "Windows Security event 4688", (SECURITY,), _READ_SECURITY),
    _capability(3, "Parent-Child Process", "Windows Security event 4688", (SECURITY,), _READ_SECURITY),
    _capability(6, "Cross-Process Access", "Windows Security events 4656/4663", (SECURITY,), _READ_SECURITY, "partial-object-audit"),
    _capability(17, "File Creation", "Windows Security event 4663 (audited create/write access; creation cannot always be distinguished)", (SECURITY,), _READ_SECURITY, "partial-object-audit"),
    _capability(18, "File Modification", "Windows Security event 4663", (SECURITY,), _READ_SECURITY, "partial-object-audit"),
    _capability(19, "File Deletion", "Windows Security event 4660", (SECURITY,), _READ_SECURITY, "partial-object-audit"),
    _capability(25, "Registry Autorun", "Windows Security event 4657 (autorun keys only)", (SECURITY,), _READ_SECURITY, "partial-object-audit"),
    _capability(26, "Scheduled Task", "Windows Security events 4698/4699/4700/4701/4702", (SECURITY,), _READ_SECURITY),
    _capability(27, "Service Installation", "Windows Security event 4697 and System event 7045", (SECURITY, SYSTEM), "Read access to Security and System event logs; service-install events must already be logged."),
    _capability(33, "DNS Query", "DNS Client Operational event 3008", (DNS_CLIENT,), "Read access to the DNS Client Operational event log; channel must already be enabled.", "privacy-redacted-domain"),
    _capability(35, "Outbound Connection", "Windows Security event 5156 (outbound direction only)", (SECURITY,), _READ_SECURITY, "partial-wfp-audit"),
    _capability(49, "Login Success", "Windows Security event 4624", (SECURITY,), _READ_SECURITY),
    _capability(50, "Login Failure", "Windows Security event 4625", (SECURITY,), _READ_SECURITY),
    _capability(58, "Security Service Integrity", "Defender Operational event 5007 and System events 7036/7040 for security services", (DEFENDER, SYSTEM), "Read access to Defender Operational and System event logs; Defender configuration and service state events only."),
)

_PHASE1_EVENT_CAPABILITIES = {
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


@dataclass
class SensorEvent:
    """Privacy-filtered, normalized event compatible with CyberOSEngine."""

    timestamp: str
    event_id: str
    event_type: str
    category: str
    severity: str
    source: str
    details: Dict[str, Any] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)
    sensor_ids: List[int] = field(default_factory=list)
    process: str = ""
    pid: int = 0
    parent_pid: int = 0
    command_line: str = ""
    user: str = ""
    remote_ip: str = ""
    network: Dict[str, Any] = field(default_factory=dict)
    file: Dict[str, Any] = field(default_factory=dict)
    _protection_target: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload.pop("_protection_target", None)
        return payload


@dataclass
class RawWindowsEvent:
    channel: str
    record_id: int
    windows_event_id: int
    timestamp: str
    fields: Dict[str, str]


def _event_fields(xml_text: str) -> tuple[str, int, int, str, Dict[str, str]]:
    root = ET.fromstring(xml_text)
    system = root.find(f"{{{_EVENT_NS}}}System")
    if system is None:
        raise ValueError("Windows event did not contain a System element")
    provider = system.find(f"{{{_EVENT_NS}}}Provider")
    channel_el = system.find(f"{{{_EVENT_NS}}}Channel")
    record_el = system.find(f"{{{_EVENT_NS}}}EventRecordID")
    event_id_el = system.find(f"{{{_EVENT_NS}}}EventID")
    time_el = system.find(f"{{{_EVENT_NS}}}TimeCreated")
    event_data = root.find(f"{{{_EVENT_NS}}}EventData")
    fields: Dict[str, str] = {}
    if event_data is not None:
        for item in event_data.findall(f"{{{_EVENT_NS}}}Data"):
            name = item.attrib.get("Name") or f"data_{len(fields)}"
            fields[name] = item.text or ""
    if provider is not None:
        fields["_provider"] = provider.attrib.get("Name", "")
    timestamp = ""
    if time_el is not None:
        timestamp = time_el.attrib.get("SystemTime", "")
    return (
        channel_el.text if channel_el is not None and channel_el.text else "",
        int(record_el.text) if record_el is not None and record_el.text else 0,
        int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0,
        timestamp,
        fields,
    )


def parse_windows_event(xml_text: str) -> RawWindowsEvent:
    channel, record_id, event_id, timestamp, fields = _event_fields(xml_text)
    if not channel or not record_id or not event_id:
        raise ValueError("Windows event XML is missing channel, record ID, or event ID")
    return RawWindowsEvent(channel, record_id, event_id, timestamp, fields)


def _normalized_timestamp(value: str) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    return value


def _int_field(fields: Mapping[str, str], *names: str) -> int:
    for name in names:
        value = fields.get(name, "")
        if value:
            try:
                return int(value, 0)
            except (TypeError, ValueError):
                try:
                    return int(value)
                except (TypeError, ValueError):
                    pass
    return 0


def _first(fields: Mapping[str, str], *names: str) -> str:
    for name in names:
        value = fields.get(name)
        if value:
            return str(value)
    return ""


def _basename(value: str) -> str:
    return value.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _digest(value: str) -> str:
    return hashlib.sha256(value.casefold().encode("utf-8", errors="replace")).hexdigest()


def _is_autorun_registry_key(value: str) -> bool:
    normalized = value.replace("/", "\\").casefold()
    return any(
        marker in normalized
        for marker in (
            "\\software\\microsoft\\windows\\currentversion\\run",
            "\\software\\microsoft\\windows\\currentversion\\runonce",
            "\\software\\microsoft\\windows nt\\currentversion\\winlogon",
            "\\system\\currentcontrolset\\services\\",
        )
    )


def _is_security_service(fields: Mapping[str, str]) -> bool:
    candidate = " ".join(
        fields.get(name, "")
        for name in ("param1", "ServiceName", "Service", "serviceName", "Name", "DisplayName")
    ).casefold()
    return any(
        marker in candidate
        for marker in (
            "defender", "windefend", "sense", "security center", "securityhealthservice",
            "windows firewall", "mpssvc", "base filtering engine", "bfe",
        )
    )


def normalize_windows_event(
    raw: RawWindowsEvent,
    *,
    collect_file_paths: bool = False,
    collect_dns_names: bool = False,
    collect_command_lines: bool = False,
) -> Optional[SensorEvent]:
    """Map one raw Windows event to one normalized event, or ignore it.

    A raw event can advertise several logical capability labels (for example,
    event 4688 supports both Process Creation and Parent-Child Process). It is
    still emitted and deduplicated exactly once.
    """

    channel = raw.channel
    event_id = raw.windows_event_id
    values = raw.fields
    capability_names: List[str] = []
    event_type = ""
    category = "security"
    severity = "INFO"
    process = ""
    user = ""
    pid = 0
    parent_pid = 0
    remote_ip = ""
    network: Dict[str, Any] = {}
    file_data: Dict[str, Any] = {}
    protection_target = ""
    details: Dict[str, Any] = {"windows_event_id": event_id, "record_id": raw.record_id}

    if channel == SECURITY and event_id == 4688:
        capability_names = ["Process Creation", "Parent-Child Process"]
        event_type, category = "process_creation", "process"
        image = _first(values, "NewProcessName", "ProcessName")
        parent_image = _first(values, "ParentProcessName", "CreatorProcessName")
        process = _basename(image)
        pid = _int_field(values, "NewProcessId", "ProcessId")
        parent_pid = _int_field(values, "ProcessId", "CreatorProcessId")
        if pid == parent_pid:
            parent_pid = _int_field(values, "CreatorProcessId", "ParentProcessId")
        details.update({"name": process, "pid": pid, "ppid": parent_pid, "parent_name": _basename(parent_image)})
        if collect_command_lines:
            command_line = _first(values, "CommandLine")[:2048]
            details["cmdline"] = command_line
        severity = "INFO"
    elif channel == SECURITY and event_id in {4656, 4663}:
        object_type = _first(values, "ObjectType").casefold()
        if object_type == "process":
            capability_names = ["Cross-Process Access"]
            event_type, category = "cross_process_access", "security"
            details.update({"source_pid": _int_field(values, "ProcessId"), "object_name_present": bool(_first(values, "ObjectName"))})
            severity = "LOW"
        elif object_type in {"file", "directory"} and event_id == 4663:
            access_mask = _int_field(values, "AccessMask")
            # WriteData/AddFile (0x2) is the only built-in signal that can
            # indicate creation. Windows object auditing does not reliably
            # distinguish a new file from a write to an existing file.
            if access_mask & 0x2:
                capability_names = ["File Creation", "File Modification"]
                details["file_operation"] = "create_or_modify"
            elif access_mask & (0x4 | 0x10 | 0x100):
                capability_names = ["File Modification"]
                details["file_operation"] = "modify"
            if capability_names:
                event_type, category = "file_activity", "file"
                path = _first(values, "ObjectName")
                protection_target = path
                file_data = {"path_hash": _digest(path) if path else ""}
                if collect_file_paths and path:
                    file_data.update({"path": path, "filename": _basename(path)})
                    details.update({"filepath": path, "filename": _basename(path)})
                else:
                    details["path_hash"] = file_data["path_hash"]
                details["access_mask"] = f"0x{access_mask:x}"
                severity = "INFO"
    elif channel == SECURITY and event_id == 4660:
        capability_names = ["File Deletion"]
        event_type, category = "file_deletion", "file"
        handle = _first(values, "HandleId")
        details.update({"process_id": _int_field(values, "ProcessId"), "handle_id": handle})
        severity = "INFO"
    elif channel == SECURITY and event_id == 4657:
        object_name = _first(values, "ObjectName")
        if _is_autorun_registry_key(object_name):
            capability_names = ["Registry Autorun"]
            event_type, category, severity = "registry_autorun_change", "persistence", "MEDIUM"
            details["registry_path_hash"] = _digest(object_name)
            details["value_name_hash"] = _digest(_first(values, "ObjectValueName")) if _first(values, "ObjectValueName") else ""
    elif channel == SECURITY and event_id in {4698, 4699, 4700, 4701, 4702}:
        capability_names = ["Scheduled Task"]
        event_type, category = "scheduled_task_change", "persistence"
        details.update({"task_name_hash": _digest(_first(values, "TaskName")) if _first(values, "TaskName") else "", "operation": event_id})
        severity = "MEDIUM"
    elif (channel == SECURITY and event_id == 4697) or (channel == SYSTEM and event_id == 7045):
        capability_names = ["Service Installation"]
        event_type, category, severity = "service_installation", "service", "MEDIUM"
        details.update({"service_name_hash": _digest(_first(values, "ServiceName", "param1")) if _first(values, "ServiceName", "param1") else ""})
    elif channel == DNS_CLIENT and event_id == 3008:
        capability_names = ["DNS Query"]
        event_type, category = "dns_query", "dns"
        query = _first(values, "QueryName", "QueryNameText")
        details["query_name_hash"] = _digest(query) if query else ""
        if collect_dns_names and query:
            details["query_name"] = query[:253]
        severity = "INFO"
    elif channel == SECURITY and event_id == 5156:
        direction = _first(values, "Direction").casefold()
        if direction in {"%%14593", "outbound", "2"}:
            capability_names = ["Outbound Connection"]
            event_type, category = "outbound_connection", "network"
            remote_ip = _first(values, "DestAddress", "DestinationAddress")
            network = {
                "remote_ip": remote_ip,
                "remote_port": _int_field(values, "DestPort", "DestinationPort"),
                "local_port": _int_field(values, "SourcePort"),
                "protocol": _first(values, "Protocol"),
                "direction": "outbound",
            }
            details.update({"remote_ip": remote_ip, "remote_port": network["remote_port"], "process_id": _int_field(values, "ProcessID", "ProcessId")})
            severity = "INFO"
    elif channel == SECURITY and event_id == 4624:
        capability_names = ["Login Success"]
        event_type, category = "successful_logon", "security"
        details.update({"logon_type": _first(values, "LogonType"), "target_user_present": bool(_first(values, "TargetUserName"))})
        severity = "INFO"
    elif channel == SECURITY and event_id == 4625:
        capability_names = ["Login Failure"]
        event_type, category, severity = "failed_logon", "auth", "MEDIUM"
        user = _first(values, "TargetUserName")
        ip = _first(values, "IpAddress")
        user = _digest(user) if user else ""
        details.update({"target_user_hash": user, "source_ip": ip if ip and ip not in {"-", "::1", "127.0.0.1"} else ""})
    elif (channel == DEFENDER and event_id == 5007) or (channel == SYSTEM and event_id in {7036, 7040}):
        if channel == DEFENDER or _is_security_service(values):
            capability_names = ["Security Service Integrity"]
            event_type, category, severity = "security_service_integrity", "security", "MEDIUM"
            details["change_kind"] = "defender_configuration" if event_id == 5007 else "service_state" if event_id == 7036 else "service_start_type"
            details["service_name_hash"] = _digest(_first(values, "param1", "ServiceName")) if _first(values, "param1", "ServiceName") else ""

    if not capability_names:
        return None

    details["source_channel"] = channel
    if process:
        category = "process"
    return SensorEvent(
        timestamp=_normalized_timestamp(raw.timestamp),
        event_id=f"winlog:{channel}:{raw.record_id}:{_normalized_timestamp(raw.timestamp)}",
        event_type=event_type,
        category=category,
        severity=severity,
        source=f"Windows Event Log:{channel}",
        details=details,
        capabilities=capability_names,
        sensor_ids=sorted({
            PHASE1_TO_REGISTRY_ID[phase1_id]
            for phase1_id, capability in _PHASE1_EVENT_CAPABILITIES.items()
            if capability in capability_names
        }),
        process=process,
        pid=pid,
        parent_pid=parent_pid,
        command_line=details.get("cmdline", ""),
        user=user,
        remote_ip=remote_ip,
        network=network,
        file=file_data,
        _protection_target=protection_target,
    )


def _error_kind(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, RuntimeError) and str(exc) in {
        "pywin32 is not installed; Windows event source unavailable",
        "pywin32 Event Log APIs are unavailable",
    }:
        return "unavailable", str(exc)
    code = getattr(exc, "winerror", None)
    if code is None and getattr(exc, "args", None):
        first = exc.args[0]
        code = first if isinstance(first, int) else getattr(first, "winerror", None)
    if code in {5, 1314}:
        return "permission_denied", "Permission denied opening Windows Event Log source."
    if code in {15007, 15002, 15011}:
        return "unavailable", "Windows Event Log channel is missing or disabled."
    return "unavailable", f"Windows Event Log source could not be opened: {type(exc).__name__}."


class WindowsEventLogSource:
    """Bounded Event Log polling with a record-ID cursor per channel."""

    def __init__(self, channels: Sequence[str] | None = None):
        self.channels = list(channels or (SECURITY, SYSTEM, DNS_CLIENT, DEFENDER))
        self._last_record_id: Dict[str, int] = {}
        self._filters: Dict[str, set[int]] = {}
        self.channel_status: Dict[str, Dict[str, str]] = {}
        self._lock = threading.RLock()
        self._channel_cursor = 0
        self._load_checkpoint: Optional[Callable[[str], Optional[int]]] = None
        self._save_checkpoint: Optional[Callable[[str, int], None]] = None

    def set_checkpoint_callbacks(
        self,
        load_checkpoint: Callable[[str], Optional[int]],
        save_checkpoint: Callable[[str, int], None],
    ) -> None:
        self._load_checkpoint = load_checkpoint
        self._save_checkpoint = save_checkpoint

    @staticmethod
    def _win32evtlog():
        if os.name != "nt":
            raise OSError("Windows Event Log is only supported on Windows")
        try:
            import win32evtlog
        except ImportError as exc:
            raise RuntimeError("pywin32 is not installed; Windows event source unavailable") from exc
        if not all(hasattr(win32evtlog, name) for name in ("EvtQuery", "EvtNext", "EvtRender", "EvtClose")):
            raise RuntimeError("pywin32 Event Log APIs are unavailable")
        return win32evtlog

    def open(self) -> None:
        try:
            evt = self._win32evtlog()
        except Exception as exc:
            state, error = _error_kind(exc)
            if isinstance(exc, RuntimeError) or os.name != "nt":
                state = "unsupported"
            self.channel_status = {channel: {"state": state, "error": error} for channel in self.channels}
            return

        channel_filters: Dict[str, set[int]] = {
            SECURITY: {4688, 4656, 4663, 4660, 4657, 4698, 4699, 4700, 4701, 4702, 4697, 5156, 4624, 4625},
            SYSTEM: {7045, 7036, 7040},
            DNS_CLIENT: {3008},
            DEFENDER: {5007},
        }
        self._filters = channel_filters
        for channel in self.channels:
            wanted = sorted(channel_filters.get(channel, ()))
            try:
                # Establish a baseline only on first install. Thereafter the
                # durable record-ID checkpoint preserves records across restarts.
                latest_record = self._latest_record_id(evt, channel)
                checkpoint = self._load_checkpoint(channel) if self._load_checkpoint else None
                if checkpoint is None:
                    checkpoint = latest_record
                    if self._save_checkpoint:
                        self._save_checkpoint(channel, checkpoint)
                elif latest_record < checkpoint:
                    # A cleared event log resets record IDs. Reset its cursor
                    # so newly written records are not silently ignored.
                    checkpoint = latest_record
                    if self._save_checkpoint:
                        self._save_checkpoint(channel, checkpoint)
                self._last_record_id[channel] = int(checkpoint)
                self.channel_status[channel] = {"state": "available", "error": ""}
            except Exception as exc:
                state, error = _error_kind(exc)
                self.channel_status[channel] = {"state": state, "error": error}

    @staticmethod
    def _latest_record_id(evt: Any, channel: str) -> int:
        tail = evt.EvtQuery(channel, evt.EvtQueryChannelPath | evt.EvtQueryReverseDirection, "*")
        try:
            latest = evt.EvtNext(tail, 1, 1000, 0)
            if not latest:
                return 0
            try:
                return _event_fields(evt.EvtRender(latest[0], evt.EvtRenderEventXml))[1]
            finally:
                evt.EvtClose(latest[0])
        finally:
            evt.EvtClose(tail)

    def read_events(self, limit: int = 128) -> List[RawWindowsEvent]:
        try:
            evt = self._win32evtlog()
        except Exception:
            return []
        result: List[RawWindowsEvent] = []
        with self._lock:
            channels = [channel for channel in self.channels if self.channel_status.get(channel, {}).get("state") == "available"]
            if not channels:
                return result
            start = self._channel_cursor % len(channels)
            channels = channels[start:] + channels[:start]
            self._channel_cursor = (start + 1) % len(channels)
            base_quota, extra = divmod(max(0, limit), len(channels))
            for index, channel in enumerate(channels):
                remaining = limit - len(result)
                if remaining <= 0:
                    break
                wanted = sorted(self._filters.get(channel, ()))
                selector = " or ".join(f"EventID={item}" for item in wanted)
                record_id = self._last_record_id.get(channel, 0)
                query = f"*[System[EventRecordID > {record_id} and ({selector})]]" if selector else f"*[System[EventRecordID > {record_id}]]"
                handle = None
                try:
                    handle = evt.EvtQuery(channel, evt.EvtQueryChannelPath | evt.EvtQueryForwardDirection, query)
                    quota = min(remaining, base_quota + (1 if index < extra else 0))
                    if quota <= 0:
                        quota = min(remaining, 1)
                    items = evt.EvtNext(handle, quota, 100, 0)
                    for item in items:
                        try:
                            result.append(parse_windows_event(evt.EvtRender(item, evt.EvtRenderEventXml)))
                        finally:
                            evt.EvtClose(item)
                    if not items:
                        # Advance past unrelated records so an idle channel
                        # does not repeatedly scan the same retained log.
                        latest_record = self._latest_record_id(evt, channel)
                        if latest_record < record_id:
                            # Handle a log clear while the service is already
                            # running, where Windows has restarted record IDs.
                            self._last_record_id[channel] = latest_record
                            if self._save_checkpoint:
                                self._save_checkpoint(channel, latest_record)
                        elif latest_record > record_id:
                            self.commit_checkpoint(channel, latest_record)
                except Exception as exc:
                    state, error = _error_kind(exc)
                    self.channel_status[channel] = {"state": state, "error": error}
                finally:
                    if handle is not None:
                        try:
                            evt.EvtClose(handle)
                        except Exception:
                            pass
        return result

    def commit_checkpoint(self, channel: str, record_id: int) -> None:
        with self._lock:
            current = self._last_record_id.get(channel, 0)
            committed = max(current, int(record_id))
            self._last_record_id[channel] = committed
            if self._save_checkpoint:
                self._save_checkpoint(channel, committed)

    def close(self) -> None:
        with self._lock:
            self._last_record_id.clear()


class WindowsSensorService:
    """Owns shared Windows log readers and dispatches durable sensor events.

    Public surface: ``start()``, ``stop(timeout=...)`` and ``get_status()``.
    Callbacks execute synchronously on the service worker. An event remains in
    SQLite until the callback returns successfully; consumers should treat its
    stable event ID idempotently in case the process exits between handling and
    queue acknowledgement.
    """

    def __init__(
        self,
        callback: Optional[Callable[[SensorEvent], None]] = None,
        *,
        database_path: Optional[str] = None,
        source_factory: Optional[Callable[[], Any]] = None,
        queue_capacity: int = 10_000,
        poll_interval: float = 0.5,
        privacy: Optional[Mapping[str, bool]] = None,
    ):
        self.callback = callback
        self.database_path = database_path or os.path.join("cyber_db", "windows_sensor_queue.sqlite3")
        self.queue_capacity = max(1, int(queue_capacity))
        self.poll_interval = max(0.05, float(poll_interval))
        self.source_factory = source_factory or WindowsEventLogSource
        self.privacy = {
            "collect_file_paths": False,
            "collect_dns_names": False,
            "collect_command_lines": False,
        }
        if privacy:
            self.privacy.update({key: bool(value) for key, value in privacy.items() if key in self.privacy})
        self.platform = platform.system()
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._source: Any = None
        self._transient_targets: Dict[str, str] = {}
        self._last_event_time = ""
        self._last_error = ""
        self._channel_status: Dict[str, Dict[str, str]] = {}
        self._capability_status: Dict[str, Dict[str, Any]] = {
            item.key: {
                "id": item.id,
                "registry_id": item.registry_id,
                "key": item.key,
                "name": item.name,
                "state": "stopped",
                "source": item.source,
                "permissions": list(item.permissions),
                "error": "",
            }
            for item in CAPABILITIES
        }
        self._init_database()

    def _connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(os.path.abspath(self.database_path)), exist_ok=True)
        conn = sqlite3.connect(self.database_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @contextmanager
    def _connection(self):
        """Commit or roll back a SQLite transaction and always close it."""
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_database(self) -> None:
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("CREATE TABLE IF NOT EXISTS queued_events (event_id TEXT PRIMARY KEY, enqueued_at TEXT NOT NULL, payload TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS seen_events (event_id TEXT PRIMARY KEY, seen_at TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS source_checkpoints (channel TEXT PRIMARY KEY, record_id INTEGER NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS sensor_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            for key in ("dropped", "deduplicated", "backpressure"):
                conn.execute("INSERT OR IGNORE INTO sensor_meta(key, value) VALUES(?, '0')", (key,))

    def _load_source_checkpoint(self, channel: str) -> Optional[int]:
        with self._connection() as conn:
            row = conn.execute("SELECT record_id FROM source_checkpoints WHERE channel=?", (channel,)).fetchone()
        return int(row["record_id"]) if row else None

    def _save_source_checkpoint(self, channel: str, record_id: int) -> None:
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO source_checkpoints(channel, record_id) VALUES(?, ?) "
                "ON CONFLICT(channel) DO UPDATE SET record_id=excluded.record_id",
                (channel, int(record_id)),
            )

    def _meta_int(self, conn: sqlite3.Connection, key: str) -> int:
        row = conn.execute("SELECT value FROM sensor_meta WHERE key=?", (key,)).fetchone()
        return int(row["value"]) if row else 0

    def _increment(self, conn: sqlite3.Connection, key: str) -> None:
        conn.execute("UPDATE sensor_meta SET value=? WHERE key=?", (str(self._meta_int(conn, key) + 1), key))

    def _enqueue_result(self, event: SensorEvent) -> str:
        payload = json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":"))
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM seen_events WHERE event_id=?", (event.event_id,)).fetchone():
                self._increment(conn, "deduplicated")
                conn.commit()
                return "duplicate"
            depth = conn.execute("SELECT COUNT(*) AS n FROM queued_events").fetchone()["n"]
            if depth >= self.queue_capacity:
                # Preserve the source cursor so the record can be retried once
                # downstream backpressure clears. This is not a dropped event.
                self._increment(conn, "backpressure")
                conn.commit()
                return "backpressure"
            conn.execute("INSERT INTO queued_events(event_id, enqueued_at, payload) VALUES(?, ?, ?)", (event.event_id, now, payload))
            conn.execute("INSERT INTO seen_events(event_id, seen_at) VALUES(?, ?)", (event.event_id, now))
            # Keep a bounded replay window so long-running installations do
            # not accumulate every event ID forever.
            conn.execute(
                "DELETE FROM seen_events WHERE event_id IN (SELECT event_id FROM seen_events ORDER BY seen_at DESC LIMIT -1 OFFSET ?)",
                (max(self.queue_capacity * 4, 10_000),),
            )
            conn.execute("INSERT OR REPLACE INTO sensor_meta(key, value) VALUES('last_event_time', ?)", (event.timestamp,))
            conn.commit()
        with self._lock:
            self._last_event_time = event.timestamp
            if event._protection_target:
                self._transient_targets[event.event_id] = event._protection_target
        return "enqueued"

    def _enqueue(self, event: SensorEvent) -> bool:
        """Compatibility helper: true only when newly durably enqueued."""
        return self._enqueue_result(event) == "enqueued"

    def start(self) -> bool:
        """Start once; repeated calls while running are no-ops."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop_event.clear()
            self._last_error = ""
            self._thread = threading.Thread(target=self._run, name="windows-sensor-service", daemon=True)
            self._thread.start()
            return True

    def stop(self, timeout: float = 5.0) -> bool:
        """Stop idempotently and wait at most ``timeout`` seconds."""
        with self._lock:
            thread = self._thread
            if thread is None:
                self._set_stopped_status()
                return True
            self._stop_event.set()
        if thread is not threading.current_thread():
            thread.join(timeout=max(0.0, timeout))
        finished = not thread.is_alive()
        if finished:
            with self._lock:
                self._thread = None
                self._set_stopped_status()
        return finished

    def _set_stopped_status(self) -> None:
        for status in self._capability_status.values():
            if status["state"] not in {"unsupported", "unavailable", "permission_denied"}:
                status["state"] = "stopped"

    def _refresh_capability_status(self, source: Any) -> None:
        raw_status = getattr(source, "channel_status", {}) or {}
        self._channel_status = dict(raw_status)
        for capability in CAPABILITIES:
            sources = [raw_status.get(channel, {}) for channel in capability.channels]
            states = [item.get("state", "unavailable") for item in sources]
            errors = [item.get("error", "") for item in sources if item.get("error")]
            if all(state == "available" for state in states):
                state = "available"
                privacy_notes = []
                if capability.key == "dns_query" and not self.privacy["collect_dns_names"]:
                    privacy_notes.append("Domain names are stored as SHA-256 hashes by default.")
                if capability.key in {"file_creation", "file_modification", "file_deletion", "cross_process_access"} and not self.privacy["collect_file_paths"]:
                    privacy_notes.append("Object paths are omitted or hashed by default.")
                if capability.key in {"process_creation", "parent_child_process"} and not self.privacy["collect_command_lines"]:
                    privacy_notes.append("Command lines are omitted by default.")
                error = " ".join([_AUDIT_NOTE, *privacy_notes])
            elif "permission_denied" in states:
                state = "permission_denied" if all(item == "permission_denied" for item in states) else "partial"
                error = "; ".join(errors)
            elif any(item == "available" for item in states):
                state = "partial"
                error = "; ".join(errors) or "One or more required channels are unavailable."
            elif states and all(item == "unsupported" for item in states):
                state, error = "unsupported", "; ".join(errors) or _UNAVAILABLE
            else:
                state = "unavailable"
                error = "; ".join(errors) or _UNAVAILABLE
            self._capability_status[capability.key].update({"state": state, "error": error})

    def _run(self) -> None:
        source = self.source_factory()
        if hasattr(source, "set_checkpoint_callbacks"):
            source.set_checkpoint_callbacks(self._load_source_checkpoint, self._save_source_checkpoint)
        with self._lock:
            self._source = source
        try:
            source.open()
            self._refresh_capability_status(source)
            while not self._stop_event.is_set():
                delivered = self.drain_pending(limit=128)
                if delivered < 128 and self._queue_depth() < self.queue_capacity:
                    try:
                        raw_events = source.read_events(limit=min(128, self.queue_capacity - self._queue_depth()))
                        for raw in raw_events:
                            if self._stop_event.is_set():
                                break
                            event = normalize_windows_event(raw, **self.privacy)
                            if event is not None and self._enqueue_result(event) == "backpressure":
                                # Do not checkpoint this or later records in the
                                # batch. The source will replay them after queue
                                # capacity becomes available.
                                break
                            if hasattr(source, "commit_checkpoint"):
                                source.commit_checkpoint(raw.channel, raw.record_id)
                        self._refresh_capability_status(source)
                    except Exception as exc:
                        self._last_error = f"Collector read failed ({type(exc).__name__})."
                self._stop_event.wait(self.poll_interval)
        except Exception as exc:
            self._last_error = f"Collector startup failed ({type(exc).__name__})."
            if not getattr(source, "channel_status", None):
                self._refresh_capability_status(source)
        finally:
            try:
                source.close()
            except Exception as exc:
                self._last_error = f"Collector shutdown failed ({type(exc).__name__})."
            with self._lock:
                self._source = None
                self._set_stopped_status()

    def _queue_depth(self) -> int:
        with self._connection() as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM queued_events").fetchone()["n"])

    def drain_pending(self, limit: int = 128) -> int:
        """Deliver queued events and acknowledge only successful callbacks."""
        if self.callback is None:
            return 0
        with self._connection() as conn:
            rows = conn.execute("SELECT event_id, payload FROM queued_events ORDER BY enqueued_at, rowid LIMIT ?", (max(0, int(limit)),)).fetchall()
        delivered = 0
        for row in rows:
            try:
                payload = json.loads(row["payload"])
                event = SensorEvent(**payload)
                with self._lock:
                    event._protection_target = self._transient_targets.get(event.event_id, "")
                self.callback(event)
            except Exception as exc:
                self._last_error = f"Event callback failed ({type(exc).__name__})."
                break
            with self._connection() as conn:
                conn.execute("DELETE FROM queued_events WHERE event_id=?", (row["event_id"],))
            with self._lock:
                self._transient_targets.pop(event.event_id, None)
            delivered += 1
        return delivered

    def get_status(self) -> Dict[str, Any]:
        """Return a JSON-safe status snapshot for API/UI consumers."""
        with self._lock:
            # A stop request is not a completed stop if a worker is still
            # draining a callback. Keep reporting it as running until it exits.
            running = bool(self._thread is not None and self._thread.is_alive())
            capabilities = [dict(value) for value in self._capability_status.values()]
            last_event_time = self._last_event_time
            last_error = self._last_error
        with self._connection() as conn:
            depth = int(conn.execute("SELECT COUNT(*) AS n FROM queued_events").fetchone()["n"])
            dropped = self._meta_int(conn, "dropped")
            deduplicated = self._meta_int(conn, "deduplicated")
            backpressure = self._meta_int(conn, "backpressure")
            last_row = conn.execute("SELECT value FROM sensor_meta WHERE key='last_event_time'").fetchone()
        if not last_event_time and last_row:
            last_event_time = str(last_row["value"])
        return {
            "running": running,
            "platform": self.platform,
            "capabilities": capabilities,
            "queue": {"depth": depth, "capacity": self.queue_capacity, "dropped": dropped, "deduplicated": deduplicated, "backpressure": backpressure},
            "last_event_time": last_event_time or None,
            "last_error": last_error or None,
            "privacy": dict(self.privacy),
        }

