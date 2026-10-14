"""Strict, bounded contracts for WFP and process telemetry.

These models describe evidence and policy intent. They do not call WFP, apply
policy, or treat observations as malware verdicts.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar, Mapping


class ModelValidationError(ValueError):
    """Raised when a telemetry or policy payload violates its schema."""


_MAX_U64 = (1 << 64) - 1
_MAX_U32 = (1 << 32) - 1
_MAX_PORT = 65535
_EVENT_SOURCES = {"wfp_net_event", "wfp_callout"}
_EVENT_TYPES = {"connect_authorize", "recv_accept_authorize", "flow_established"}
_DIRECTIONS = {"inbound", "outbound", "unknown"}
_IP_FAMILIES = {"IPv4", "IPv6", "unknown"}
_PROTOCOLS = {"TCP", "UDP", "unknown"}
_EVENT_ACTIONS = {"observed", "continue", "permit", "block", "unknown"}
_CAPTURE_STATES = {"complete", "partial", "unavailable"}
_ATTRIBUTION_STATES = {"verified", "unverified", "unavailable", "stale"}
_LAYERS = {
    "ALE_AUTH_CONNECT_V4",
    "ALE_AUTH_CONNECT_V6",
    "ALE_AUTH_RECV_ACCEPT_V4",
    "ALE_AUTH_RECV_ACCEPT_V6",
    "ALE_FLOW_ESTABLISHED_V4",
    "ALE_FLOW_ESTABLISHED_V6",
}
_WFP_FIELDS = {
    "timestamp_utc",
    "direction",
    "ip_family",
    "protocol",
    "local_address",
    "local_port",
    "remote_address",
    "remote_port",
    "process_id",
    "application_id",
    "layer",
    "action",
    "reason",
    "compartment_id",
    "interface_index",
    "flow_id",
}
_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _fail(message: str) -> None:
    raise ModelValidationError(message)


def _exact_mapping(value: Any, expected: set[str], *, model: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{model} must be an object")
    if any(not isinstance(key, str) for key in value):
        _fail(f"{model} field names must be strings")
    actual = set(value)
    missing = expected - actual
    extra = actual - expected
    if missing:
        _fail(f"{model} is missing required fields: {', '.join(sorted(missing))}")
    if extra:
        _fail(f"{model} contains unknown fields: {', '.join(sorted(extra))}")
    return value


def _json_bytes(value: Any, *, limit: int, model: str) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ModelValidationError(f"{model} is not JSON serializable") from exc
    if len(encoded) > limit:
        _fail(f"{model} exceeds the {limit}-byte limit")
    return encoded


def _string(value: Any, name: str, *, max_length: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        _fail(f"{name} must be a string")
    if (not value and not allow_empty) or len(value) > max_length or "\x00" in value:
        _fail(f"{name} must contain 1 to {max_length} characters without NULs")
    return value


def _enum(value: Any, name: str, choices: set[str]) -> str:
    candidate = _string(value, name, max_length=64)
    if candidate not in choices:
        _fail(f"{name} must be one of: {', '.join(sorted(choices))}")
    return candidate


def _integer(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        _fail(f"{name} must be between {minimum} and {maximum}")
    return value


def _optional_integer(value: Any, name: str, *, minimum: int, maximum: int) -> int | None:
    if value is None:
        return None
    return _integer(value, name, minimum=minimum, maximum=maximum)


def _finite_number(value: Any, name: str, *, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{name} must be a number")
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise ModelValidationError(f"{name} must be finite and at least {minimum}") from exc
    if not math.isfinite(number) or number < minimum:
        _fail(f"{name} must be finite and at least {minimum}")
    return number


def _utc_timestamp(value: Any, name: str = "timestamp_utc") -> str:
    candidate = _string(value, name, max_length=40)
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ModelValidationError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _fail(f"{name} must include a UTC timezone")
    return candidate


def _optional_text(value: Any, name: str, *, max_length: int) -> str | None:
    if value is None:
        return None
    return _string(value, name, max_length=max_length)


def _event_id(value: Any) -> str:
    candidate = _string(value, "event_id", max_length=128)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", candidate):
        _fail("event_id contains unsupported characters")
    return candidate


def process_identity(process_id: int, process_create_time: float) -> str:
    """Return a stable identity key; PID alone is unsafe across PID reuse."""
    pid = _integer(process_id, "process_id", minimum=0, maximum=_MAX_U32)
    created = _finite_number(process_create_time, "process_create_time")
    return f"{pid}:{created.hex()}"


def _check_schema_version(value: Any, model: str) -> int:
    version = _integer(value, "schema_version", minimum=1, maximum=1)
    if version != 1:
        _fail(f"unsupported {model} schema_version {version}")
    return version


@dataclass(frozen=True)
class NetworkEvent:
    """A bounded WFP connection observation; no payload or byte totals."""

    sequence: int
    event_id: str
    timestamp_utc: str
    source: str
    event_type: str
    layer: str | None
    direction: str
    ip_family: str
    protocol: str
    local_address: str | None
    local_port: int | None
    remote_address: str | None
    remote_port: int | None
    process_id: int | None
    process_create_time: float | None
    application_id: str | None
    compartment_id: int | None
    interface_index: int | None
    flow_id: int | None
    reauthorization: bool
    action: str
    reason: str
    capture_status: str
    attribution_status: str
    schema_version: int = 1

    MAX_JSON_BYTES: ClassVar[int] = 4096

    def __post_init__(self) -> None:
        _check_schema_version(self.schema_version, "network event")
        _integer(self.sequence, "sequence", minimum=1, maximum=_MAX_U64)
        _event_id(self.event_id)
        _utc_timestamp(self.timestamp_utc)
        _enum(self.source, "source", _EVENT_SOURCES)
        event_type = _enum(self.event_type, "event_type", _EVENT_TYPES)
        direction = _enum(self.direction, "direction", _DIRECTIONS)
        family = _enum(self.ip_family, "ip_family", _IP_FAMILIES)
        _enum(self.protocol, "protocol", _PROTOCOLS)
        if self.layer is not None:
            layer = _enum(self.layer, "layer", _LAYERS)
            if layer.endswith("_V4") and family != "IPv4" or layer.endswith("_V6") and family != "IPv6":
                _fail("layer does not match IP family")
            if event_type == "connect_authorize" and not layer.startswith("ALE_AUTH_CONNECT_"):
                _fail("layer does not match connect_authorize event_type")
            if event_type == "recv_accept_authorize" and not layer.startswith("ALE_AUTH_RECV_ACCEPT_"):
                _fail("layer does not match recv_accept_authorize event_type")
            if event_type == "flow_established" and not layer.startswith("ALE_FLOW_ESTABLISHED_"):
                _fail("layer does not match flow_established event_type")
        if event_type == "connect_authorize" and direction != "outbound":
            _fail("direction for connect_authorize must be outbound")
        if event_type == "recv_accept_authorize" and direction != "inbound":
            _fail("direction for recv_accept_authorize must be inbound")
        if not isinstance(self.reauthorization, bool):
            _fail("reauthorization must be a boolean")
        _enum(self.action, "action", _EVENT_ACTIONS)
        if self.source == "wfp_callout":
            if self.layer is None:
                _fail("wfp_callout events require a layer")
            if self.action not in {"observed", "continue", "unknown"}:
                _fail("observation callout events can only report observation or continue actions")
        if self.source == "wfp_net_event" and self.action == "continue":
            _fail("continue is a callout action and is invalid for a net-event source")
        if event_type == "flow_established" and self.action == "block":
            _fail("flow-established observations cannot report a block action")
        _string(self.reason, "reason", max_length=512, allow_empty=True)
        _enum(self.capture_status, "capture_status", _CAPTURE_STATES)
        attribution = _enum(self.attribution_status, "attribution_status", _ATTRIBUTION_STATES)

        parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for name in ("local_address", "remote_address"):
            address = getattr(self, name)
            if address is None:
                continue
            address = _string(address, name, max_length=45)
            if "%" in address:
                _fail(f"{name} must not contain an IPv6 scope suffix")
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError as exc:
                raise ModelValidationError(f"{name} must be an IPv4 or IPv6 address") from exc
            if family == "IPv4" and parsed.version != 4 or family == "IPv6" and parsed.version != 6:
                _fail(f"{name} does not match ip_family")
            parsed_addresses.append(parsed)
        if parsed_addresses and family == "unknown":
            _fail("ip_family cannot be unknown when an address is present")
        if len(parsed_addresses) == 2 and parsed_addresses[0].version != parsed_addresses[1].version:
            _fail("local_address and remote_address must use the same address family")

        _optional_integer(self.local_port, "local_port", minimum=0, maximum=_MAX_PORT)
        _optional_integer(self.remote_port, "remote_port", minimum=0, maximum=_MAX_PORT)
        _optional_integer(self.process_id, "process_id", minimum=0, maximum=_MAX_U32)
        if self.process_create_time is not None:
            if self.process_id is None:
                _fail("process_create_time requires process_id")
            _finite_number(self.process_create_time, "process_create_time")
        if attribution == "verified" and (self.process_id is None or self.process_create_time is None):
            _fail("verified attribution requires process_id and process_create_time")
        _optional_text(self.application_id, "application_id", max_length=2048)
        if self.application_id is not None and any(char in self.application_id for char in "*?"):
            _fail("application_id must be an exact identity without wildcards")
        _optional_integer(self.compartment_id, "compartment_id", minimum=0, maximum=_MAX_U32)
        _optional_integer(self.interface_index, "interface_index", minimum=0, maximum=_MAX_U32)
        _optional_integer(self.flow_id, "flow_id", minimum=0, maximum=_MAX_U64)
        _json_bytes(self.to_dict(), limit=self.MAX_JSON_BYTES, model="network event")

    @property
    def process_identity(self) -> str | None:
        if self.process_id is None or self.process_create_time is None:
            return None
        return process_identity(self.process_id, self.process_create_time)

    def to_dict(self) -> dict[str, Any]:
        payload = {field.name: getattr(self, field.name) for field in fields(self)}
        payload["process_identity"] = self.process_identity
        return payload

    def to_json(self) -> str:
        return _json_bytes(self.to_dict(), limit=self.MAX_JSON_BYTES, model="network event").decode("utf-8")

    @classmethod
    def from_dict(cls, value: Any) -> "NetworkEvent":
        expected = {field.name for field in fields(cls)} | {"process_identity"}
        payload = _exact_mapping(value, expected, model="network event")
        _json_bytes(payload, limit=cls.MAX_JSON_BYTES, model="network event")
        identity = payload["process_identity"]
        arguments = {key: payload[key] for key in expected if key != "process_identity"}
        try:
            event = cls(**arguments)
        except TypeError as exc:
            raise ModelValidationError("network event has invalid fields") from exc
        if identity != event.process_identity:
            _fail("process_identity does not match process_id and process_create_time")
        return event

    @classmethod
    def from_json(cls, value: str | bytes) -> "NetworkEvent":
        parsed = _decode_json(value, limit=cls.MAX_JSON_BYTES, model="network event")
        return cls.from_dict(parsed)


@dataclass(frozen=True)
class ProcessEvent:
    """A process lifecycle or snapshot record keyed by PID and creation time."""

    sequence: int
    event_id: str
    timestamp_utc: str
    source: str
    event_type: str
    process_id: int
    parent_process_id: int | None
    process_create_time: float | None
    process_name: str | None
    image_path: str | None
    command_line: str | None
    metadata_status: str
    schema_version: int = 1

    MAX_JSON_BYTES: ClassVar[int] = 12 * 1024

    def __post_init__(self) -> None:
        _check_schema_version(self.schema_version, "process event")
        _integer(self.sequence, "sequence", minimum=1, maximum=_MAX_U64)
        _event_id(self.event_id)
        _utc_timestamp(self.timestamp_utc)
        source = _enum(self.source, "source", {"etw", "snapshot"})
        event_type = _enum(self.event_type, "event_type", {"start", "stop", "snapshot"})
        if event_type == "snapshot" and source != "snapshot":
            _fail("snapshot event_type requires snapshot source")
        if event_type in {"start", "stop"} and source != "etw":
            _fail("start and stop event_types require etw source")
        pid = _integer(self.process_id, "process_id", minimum=0, maximum=_MAX_U32)
        _optional_integer(self.parent_process_id, "parent_process_id", minimum=0, maximum=_MAX_U32)
        if self.parent_process_id == pid:
            _fail("parent_process_id cannot equal process_id")
        if self.process_create_time is not None:
            _finite_number(self.process_create_time, "process_create_time")
        if self.metadata_status == "complete" and self.process_create_time is None:
            _fail("complete process metadata requires process_create_time")
        _enum(self.metadata_status, "metadata_status", {"complete", "partial", "unavailable"})
        _optional_text(self.process_name, "process_name", max_length=260)
        _optional_text(self.image_path, "image_path", max_length=2048)
        _optional_text(self.command_line, "command_line", max_length=8192)
        _json_bytes(self.to_dict(), limit=self.MAX_JSON_BYTES, model="process event")

    @property
    def process_identity(self) -> str | None:
        if self.process_create_time is None:
            return None
        return process_identity(self.process_id, self.process_create_time)

    @property
    def identity_status(self) -> str:
        return "verified" if self.process_identity is not None else "unavailable"

    def to_dict(self) -> dict[str, Any]:
        payload = {field.name: getattr(self, field.name) for field in fields(self)}
        payload["process_identity"] = self.process_identity
        payload["identity_status"] = self.identity_status
        return payload

    @classmethod
    def from_dict(cls, value: Any) -> "ProcessEvent":
        expected = {field.name for field in fields(cls)} | {"process_identity", "identity_status"}
        payload = _exact_mapping(value, expected, model="process event")
        _json_bytes(payload, limit=cls.MAX_JSON_BYTES, model="process event")
        identity = payload["process_identity"]
        identity_status = payload["identity_status"]
        arguments = {key: payload[key] for key in expected if key not in {"process_identity", "identity_status"}}
        try:
            event = cls(**arguments)
        except TypeError as exc:
            raise ModelValidationError("process event has invalid fields") from exc
        if identity != event.process_identity or identity_status != event.identity_status:
            _fail("process identity fields do not match process_id and process_create_time")
        return event

    @classmethod
    def from_json(cls, value: str | bytes) -> "ProcessEvent":
        parsed = _decode_json(value, limit=cls.MAX_JSON_BYTES, model="process event")
        return cls.from_dict(parsed)


@dataclass(frozen=True)
class NetworkPolicyRule:
    """An exact, bounded policy selector; references are not authorization proof."""

    rule_id: str
    action: str
    application_id: str | None
    remote_address: str | None
    direction: str
    protocol: str
    remote_port: int | None
    ttl_seconds: int
    reason: str
    evidence_ref: str | None
    approval_ref: str | None
    evidence_confidence: str | None = None

    MAX_TTL_SECONDS: ClassVar[int] = 86400

    def __post_init__(self) -> None:
        rule_id = _string(self.rule_id, "rule_id", max_length=64)
        if not _RULE_ID_RE.fullmatch(rule_id):
            _fail("rule_id contains unsupported characters")
        _enum(self.action, "action", {"observe", "allow", "block"})
        app_id = _optional_text(self.application_id, "application_id", max_length=2048)
        if app_id is not None and any(char in app_id for char in "*?"):
            _fail("application_id must be an exact identity without wildcards")
        if (app_id is None) == (self.remote_address is None):
            _fail("exactly one of application_id or remote_address is required")
        if self.remote_address is not None:
            address_text = _string(self.remote_address, "remote_address", max_length=45)
            if "/" in address_text or "%" in address_text:
                _fail("remote_address must be one exact IP address")
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError as exc:
                raise ModelValidationError("remote_address must be an exact IPv4 or IPv6 address") from exc
            if address.is_loopback or address.is_unspecified or address.is_multicast:
                _fail("remote_address cannot target loopback, unspecified, or multicast addresses")
        _enum(self.direction, "direction", {"inbound", "outbound", "any"})
        _enum(self.protocol, "protocol", {"TCP", "UDP", "any"})
        _optional_integer(self.remote_port, "remote_port", minimum=0, maximum=_MAX_PORT)
        _integer(self.ttl_seconds, "ttl_seconds", minimum=1, maximum=self.MAX_TTL_SECONDS)
        _string(self.reason, "reason", max_length=256)
        evidence = _optional_reference(self.evidence_ref, "evidence_ref")
        approval = _optional_reference(self.approval_ref, "approval_ref")
        confidence = None if self.evidence_confidence is None else _enum(
            self.evidence_confidence, "evidence_confidence", {"low", "medium", "high"}
        )
        if evidence is None and confidence is not None:
            _fail("evidence_confidence requires evidence_ref")
        if self.action == "block" and approval is None and not (evidence is not None and confidence == "high"):
            _fail("block action requires high confidence evidence or explicit approval authorization")
        if self.action == "allow" and approval is None:
            _fail("allow action requires an approval_ref")

    def to_dict(self) -> dict[str, Any]:
        return {field.name: getattr(self, field.name) for field in fields(self)}

    @classmethod
    def from_dict(cls, value: Any) -> "NetworkPolicyRule":
        expected = {field.name for field in fields(cls)}
        payload = _exact_mapping(value, expected, model="network policy rule")
        try:
            return cls(**payload)
        except TypeError as exc:
            raise ModelValidationError("network policy rule has invalid fields") from exc


@dataclass(frozen=True)
class NetworkPolicy:
    """A bounded policy request which defaults to observation-only.

    ``enforcement_requested`` is a request shape, not proof that a user,
    evidence source, or service authorization check approved the rules. The
    policy manager must authenticate/resolve references before applying any
    non-observation action; a decoded model alone is never authorization.
    """

    mode: str = "observe_only"
    rules: tuple[NetworkPolicyRule, ...] = ()
    schema_version: int = 1

    MAX_RULES: ClassVar[int] = 256
    MAX_JSON_BYTES: ClassVar[int] = 65536

    def __post_init__(self) -> None:
        _check_schema_version(self.schema_version, "network policy")
        mode = _enum(self.mode, "mode", {"observe_only", "enforcement_requested"})
        if not isinstance(self.rules, (tuple, list)):
            _fail("rules must be a list or tuple")
        rules = tuple(self.rules)
        if len(rules) > self.MAX_RULES:
            _fail(f"policy rule limit is {self.MAX_RULES}")
        if any(not isinstance(rule, NetworkPolicyRule) for rule in rules):
            _fail("rules must contain NetworkPolicyRule objects")
        ids = [rule.rule_id for rule in rules]
        if len(ids) != len(set(ids)):
            _fail("policy rule IDs must be unique")
        if mode == "observe_only" and any(rule.action != "observe" for rule in rules):
            _fail("observe_only policy cannot contain allow or block rules")
        object.__setattr__(self, "rules", rules)
        _json_bytes(self.to_dict(), limit=self.MAX_JSON_BYTES, model="network policy")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "rules": [rule.to_dict() for rule in self.rules],
        }

    @classmethod
    def from_dict(cls, value: Any) -> "NetworkPolicy":
        payload = _exact_mapping(value, {"schema_version", "mode", "rules"}, model="network policy")
        _json_bytes(payload, limit=cls.MAX_JSON_BYTES, model="network policy")
        raw_rules = payload["rules"]
        if not isinstance(raw_rules, list):
            _fail("rules must be a JSON array")
        rules = tuple(NetworkPolicyRule.from_dict(rule) for rule in raw_rules)
        try:
            return cls(mode=payload["mode"], rules=rules, schema_version=payload["schema_version"])
        except TypeError as exc:
            raise ModelValidationError("network policy has invalid fields") from exc

    def to_json(self) -> str:
        return _json_bytes(self.to_dict(), limit=self.MAX_JSON_BYTES, model="network policy").decode("utf-8")

    @classmethod
    def from_json(cls, value: str | bytes) -> "NetworkPolicy":
        return cls.from_dict(_decode_json(value, limit=cls.MAX_JSON_BYTES, model="network policy"))


def _optional_reference(value: Any, name: str) -> str | None:
    if value is None:
        return None
    candidate = _string(value, name, max_length=128)
    if not _REFERENCE_RE.fullmatch(candidate):
        _fail(f"{name} contains unsupported characters")
    return candidate


def _decode_json(value: str | bytes, *, limit: int, model: str) -> Any:
    if isinstance(value, bytes):
        if len(value) > limit:
            _fail(f"{model} exceeds the {limit}-byte limit")
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ModelValidationError(f"{model} JSON must be UTF-8") from exc
    elif isinstance(value, str):
        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ModelValidationError(f"{model} JSON must be valid UTF-8") from exc
        if len(raw) > limit:
            _fail(f"{model} exceeds the {limit}-byte limit")
        text = value
    else:
        _fail(f"{model} JSON must be text or bytes")
    try:
        return json.loads(text, parse_constant=lambda token: _fail(f"invalid JSON constant {token}"))
    except json.JSONDecodeError as exc:
        raise ModelValidationError(f"{model} JSON is malformed") from exc


@dataclass(frozen=True)
class WfpCapabilityReport:
    """Evidence-backed status for the user-mode WFP event subscription."""

    platform_supported: bool
    bfe_state: str
    engine_state: str
    subscription_state: str
    events_observed: bool
    observed_fields: tuple[str, ...]
    required_fields: tuple[str, ...]
    max_event_latency_ms: float | None
    latency_budget_ms: float
    callout_state: str
    last_error: str | None
    schema_version: int = 1

    MAX_JSON_BYTES: ClassVar[int] = 16384

    def __post_init__(self) -> None:
        _check_schema_version(self.schema_version, "WFP capability report")
        for name in ("platform_supported", "events_observed"):
            if not isinstance(getattr(self, name), bool):
                _fail(f"{name} must be a boolean")
        bfe = _enum(self.bfe_state, "bfe_state", {"running", "stopped", "unknown"})
        engine = _enum(self.engine_state, "engine_state", {"open", "denied", "unavailable", "closed"})
        subscription = _enum(self.subscription_state, "subscription_state", {"active", "failed", "unsupported", "not_started"})
        callout = _enum(self.callout_state, "callout_state", {"not_evaluated", "not_required", "required_unavailable", "ready", "failed"})
        observed = _field_tuple(self.observed_fields, "observed_fields")
        required = _field_tuple(self.required_fields, "required_fields")
        budget = _finite_number(self.latency_budget_ms, "latency_budget_ms", minimum=0.001)
        latency = None if self.max_event_latency_ms is None else _finite_number(
            self.max_event_latency_ms, "max_event_latency_ms"
        )
        _optional_text(self.last_error, "last_error", max_length=512)

        source_ready = self.platform_supported and bfe == "running" and engine == "open" and subscription == "active"
        if self.events_observed:
            if not source_ready:
                _fail("observed events require a supported platform, running BFE, open engine, and active subscription")
            if latency is None:
                _fail("observed events require a measured max_event_latency_ms")
        elif observed or latency is not None:
            _fail("observed_fields and max_event_latency_ms require events_observed")

        proof_gap = False
        proof_sufficient = False
        if self.events_observed:
            proof_gap = not set(required).issubset(observed) or latency > budget
            proof_sufficient = not proof_gap
        if callout == "required_unavailable" and not proof_gap:
            _fail("callout cannot be required_unavailable without a proven event-field or latency gap")
        if callout in {"ready", "failed"} and not proof_gap:
            _fail("callout state requires a proven event-field or latency gap")
        if callout == "not_required" and not proof_sufficient:
            _fail("callout cannot be marked not_required until event coverage and latency are proven sufficient")
        object.__setattr__(self, "observed_fields", observed)
        object.__setattr__(self, "required_fields", required)
        _json_bytes(self.to_dict(), limit=self.MAX_JSON_BYTES, model="WFP capability report")

    @property
    def proof_state(self) -> str:
        if not self.platform_supported:
            return "unsupported"
        if self.bfe_state != "running" or self.engine_state != "open" or self.subscription_state != "active":
            return "unavailable"
        if not self.events_observed:
            return "unproven"
        if not set(self.required_fields).issubset(self.observed_fields) or self.max_event_latency_ms > self.latency_budget_ms:
            return "proven_gap"
        return "proven_sufficient"

    @property
    def health_state(self) -> str:
        if not self.platform_supported:
            return "unsupported"
        if self.bfe_state != "running" or self.engine_state in {"unavailable", "closed"}:
            return "unavailable"
        if self.engine_state == "denied" or self.subscription_state in {"failed", "unsupported", "not_started"}:
            return "degraded"
        if self.proof_state == "unproven":
            return "unproven"
        if self.proof_state == "proven_gap" and self.callout_state != "ready":
            return "degraded"
        return "ready"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "platform_supported": self.platform_supported,
            "bfe_state": self.bfe_state,
            "engine_state": self.engine_state,
            "subscription_state": self.subscription_state,
            "events_observed": self.events_observed,
            "observed_fields": list(self.observed_fields),
            "required_fields": list(self.required_fields),
            "max_event_latency_ms": self.max_event_latency_ms,
            "latency_budget_ms": self.latency_budget_ms,
            "callout_state": self.callout_state,
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "WfpCapabilityReport":
        expected = {
            "schema_version", "platform_supported", "bfe_state", "engine_state",
            "subscription_state", "events_observed", "observed_fields", "required_fields",
            "max_event_latency_ms", "latency_budget_ms", "callout_state", "last_error",
        }
        payload = _exact_mapping(value, expected, model="WFP capability report")
        _json_bytes(payload, limit=cls.MAX_JSON_BYTES, model="WFP capability report")
        observed = payload["observed_fields"]
        required = payload["required_fields"]
        if not isinstance(observed, list) or not isinstance(required, list):
            _fail("observed_fields and required_fields must be JSON arrays")
        try:
            return cls(
                schema_version=payload["schema_version"],
                platform_supported=payload["platform_supported"],
                bfe_state=payload["bfe_state"],
                engine_state=payload["engine_state"],
                subscription_state=payload["subscription_state"],
                events_observed=payload["events_observed"],
                observed_fields=tuple(observed),
                required_fields=tuple(required),
                max_event_latency_ms=payload["max_event_latency_ms"],
                latency_budget_ms=payload["latency_budget_ms"],
                callout_state=payload["callout_state"],
                last_error=payload["last_error"],
            )
        except TypeError as exc:
            raise ModelValidationError("WFP capability report has invalid fields") from exc

    def to_json(self) -> str:
        return _json_bytes(self.to_dict(), limit=self.MAX_JSON_BYTES, model="WFP capability report").decode("utf-8")

    @classmethod
    def from_json(cls, value: str | bytes) -> "WfpCapabilityReport":
        return cls.from_dict(_decode_json(value, limit=cls.MAX_JSON_BYTES, model="WFP capability report"))


def _field_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        _fail(f"{name} must be a list or tuple")
    fields = tuple(_string(item, name, max_length=64) for item in value)
    if len(fields) != len(set(fields)):
        _fail(f"{name} entries must be unique")
    invalid = set(fields) - _WFP_FIELDS
    if invalid:
        _fail(f"{name} contains unsupported fields: {', '.join(sorted(invalid))}")
    return tuple(sorted(fields))
