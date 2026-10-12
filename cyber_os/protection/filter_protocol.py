"""Versioned Filter Manager communication protocol for STAI minifilter."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Literal

from .models import ScanVerdict


PROTOCOL_VERSION = 1
MAX_PAYLOAD_SIZE = 64 * 1024
MAX_PATH_UTF16_CHARS = 32767
MAX_RULE_ID_UTF16_CHARS = 255

class Operation:
    CREATE = 1
    IMAGE_MAPPING = 2

OperationLiteral = Literal["create", "image_mapping"]

VERDICT_ALLOW = 0
VERDICT_BLOCK = 1
VERDICT_UNKNOWN = 2


class ProtocolError(ValueError):
    """Raised when a protocol frame is malformed or invalid."""


@dataclass(frozen=True, slots=True)
class FilterRequest:
    request_id: int
    operation: OperationLiteral
    path: str


@dataclass(frozen=True, slots=True)
class FilterReply:
    request_id: int
    verdict: ScanVerdict


@dataclass(frozen=True, slots=True)
class FilterCompletion:
    request_id: int
    final_io_status: str


def _operation_to_int(op: OperationLiteral) -> int:
    return Operation.CREATE if op == "create" else Operation.IMAGE_MAPPING


def _int_to_operation(value: int) -> OperationLiteral:
    if value == Operation.CREATE:
        return "create"
    if value == Operation.IMAGE_MAPPING:
        return "image_mapping"
    raise ProtocolError(f"invalid operation: {value}")


def _verdict_to_int(verdict: ScanVerdict) -> int:
    if verdict.action == "block":
        return VERDICT_BLOCK
    if verdict.status == "unknown":
        return VERDICT_UNKNOWN
    return VERDICT_ALLOW


def _int_to_verdict(value: int, rule_id: str | None, rule_version: str) -> ScanVerdict:
    if value == VERDICT_BLOCK:
        return ScanVerdict(
            status="detected",
            action="block",
            rule_id=rule_id,
            rule_version=rule_version,
            sha256=None,
            reason="high-confidence block rule matched",
        )
    if value == VERDICT_UNKNOWN:
        return ScanVerdict(
            status="unknown",
            action="allow",
            rule_id=None,
            rule_version=rule_version,
            sha256=None,
            reason="verdict unknown",
        )
    return ScanVerdict(
        status="clean",
        action="allow",
        rule_id=None,
        rule_version=rule_version,
        sha256=None,
        reason="no rule matched",
    )


def encode_filter_request(request: FilterRequest) -> bytes:
    path_utf16 = request.path.encode("utf-16-le")
    path_len = len(path_utf16) // 2
    if path_len > MAX_PATH_UTF16_CHARS:
        raise ProtocolError("path exceeds maximum length")
    
    header = struct.pack("<IQII", PROTOCOL_VERSION, request.request_id,
                         _operation_to_int(request.operation), path_len)
    payload = header + path_utf16
    size = len(payload) + 4
    
    if size > MAX_PAYLOAD_SIZE:
        raise ProtocolError("encoded request exceeds 64 KiB")
    
    return struct.pack("<I", size) + payload


def encode_filter_reply(reply: FilterReply) -> bytes:
    verdict_int = _verdict_to_int(reply.verdict)
    rule_id_utf16 = (reply.verdict.rule_id or "").encode("utf-16-le")
    rule_id_len = len(rule_id_utf16) // 2
    rule_version_utf16 = reply.verdict.rule_version.encode("utf-16-le")
    rule_version_len = len(rule_version_utf16) // 2
    if rule_id_len > MAX_RULE_ID_UTF16_CHARS:
        raise ProtocolError("rule_id exceeds maximum length")
    if rule_version_len > 63:
        raise ProtocolError("rule_version exceeds maximum length")
    
    header = struct.pack("<IQIIH", PROTOCOL_VERSION, reply.request_id,
                         verdict_int, rule_id_len, rule_version_len)
    payload = header + rule_id_utf16 + rule_version_utf16
    size = len(payload) + 4
    
    if size > MAX_PAYLOAD_SIZE:
        raise ProtocolError("encoded reply exceeds 64 KiB")
    
    return struct.pack("<I", size) + payload


def encode_filter_completion(completion: FilterCompletion) -> bytes:
    payload = struct.pack("<IQI", PROTOCOL_VERSION,
                          completion.request_id, _io_status_to_int(completion.final_io_status))
    size = len(payload) + 4
    return struct.pack("<I", size) + payload


def decode_filter_request(payload: bytes) -> FilterRequest:
    if len(payload) < 4:
        raise ProtocolError("payload too small for size field")
    
    size = struct.unpack("<I", payload[:4])[0]
    if size != len(payload):
        raise ProtocolError(f"size mismatch: declared {size}, actual {len(payload)}")
    if size > MAX_PAYLOAD_SIZE:
        raise ProtocolError("payload exceeds 64 KiB")
    
    if len(payload) < 24:
        raise ProtocolError("payload too small for request header")
    
    version, request_id, operation, path_len = struct.unpack("<IQII", payload[4:24])
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version: {version}")
    if operation not in (Operation.CREATE, Operation.IMAGE_MAPPING):
        raise ProtocolError(f"invalid operation: {operation}")
    if path_len > MAX_PATH_UTF16_CHARS:
        raise ProtocolError("path length exceeds maximum")
    
    expected_min = 24 + path_len * 2
    if len(payload) < expected_min:
        raise ProtocolError("payload truncated")
    
    path_utf16 = payload[24:24 + path_len * 2]
    try:
        path = path_utf16.decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"invalid UTF-16 in path: {exc}") from exc
    
    return FilterRequest(
        request_id=request_id,
        operation=_int_to_operation(operation),
        path=path,
    )


def decode_filter_reply(payload: bytes) -> FilterReply:
    if len(payload) < 4:
        raise ProtocolError("payload too small for size field")
    
    size = struct.unpack("<I", payload[:4])[0]
    if size != len(payload):
        raise ProtocolError(f"size mismatch: declared {size}, actual {len(payload)}")
    if size > MAX_PAYLOAD_SIZE:
        raise ProtocolError("payload exceeds 64 KiB")
    
    if len(payload) < 26:  # 4 (size) + 22 (header with rule_version_len)
        raise ProtocolError("payload too small for reply header")
    
    version, request_id, verdict, rule_id_len, rule_version_len = struct.unpack("<IQIIH", payload[4:26])
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version: {version}")
    if verdict > VERDICT_UNKNOWN:
        raise ProtocolError(f"invalid verdict: {verdict}")
    if rule_id_len > MAX_RULE_ID_UTF16_CHARS:
        raise ProtocolError("rule_id length exceeds maximum")
    if rule_version_len > 63:
        raise ProtocolError("rule_version length exceeds maximum")
    
    expected_len = 26 + rule_id_len * 2 + rule_version_len * 2
    if len(payload) != expected_len:
        raise ProtocolError(
            f"reply body length mismatch: need {expected_len}, got {len(payload)}"
        )

    offset = 26
    rule_id_utf16 = payload[offset:offset + rule_id_len * 2]
    offset += rule_id_len * 2
    rule_version_utf16 = payload[offset:offset + rule_version_len * 2]
    
    try:
        rule_id = rule_id_utf16.decode("utf-16-le") if rule_id_len > 0 else None
        rule_version = rule_version_utf16.decode("utf-16-le") if rule_version_len > 0 else "unknown"
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"invalid UTF-16 in reply strings: {exc}") from exc
    
    verdict_obj = _int_to_verdict(verdict, rule_id, rule_version)
    return FilterReply(request_id=request_id, verdict=verdict_obj)


def decode_filter_completion(payload: bytes) -> FilterCompletion:
    if len(payload) != 20:
        raise ProtocolError(f"completion size mismatch: expected 20, got {len(payload)}")
    
    size = struct.unpack("<I", payload[:4])[0]
    if size != 20:
        raise ProtocolError(f"completion size field mismatch: {size}")
    
    version, request_id, final_io_status = struct.unpack("<IQI", payload[4:20])
    if version != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported protocol version: {version}")
    
    return FilterCompletion(
        request_id=request_id,
        final_io_status=_int_to_io_status(final_io_status),
    )


def _io_status_to_int(status: str) -> int:
    status_map = {
        "STATUS_SUCCESS": 0x00000000,
        "STATUS_ACCESS_DENIED": 0xC0000022,
        "STATUS_FILE_LOCK_CONFLICT": 0xC0000054,
        "STATUS_SHARING_VIOLATION": 0xC0000043,
        "STATUS_OBJECT_NAME_NOT_FOUND": 0xC0000034,
        "STATUS_OBJECT_PATH_NOT_FOUND": 0xC000003A,
        "STATUS_DELETE_PENDING": 0xC0000056,
    }
    return status_map.get(status, 0xFFFFFFFF)


def _int_to_io_status(value: int) -> str:
    reverse_map = {
        0x00000000: "STATUS_SUCCESS",
        0xC0000022: "STATUS_ACCESS_DENIED",
        0xC0000054: "STATUS_FILE_LOCK_CONFLICT",
        0xC0000043: "STATUS_SHARING_VIOLATION",
        0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
        0xC0000056: "STATUS_DELETE_PENDING",
    }
    return reverse_map.get(value, f"0x{value:08X}")