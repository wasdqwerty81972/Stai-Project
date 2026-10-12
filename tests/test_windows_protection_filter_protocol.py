from __future__ import annotations

import struct
from pathlib import Path
import pytest

from cyber_os.protection.filter_protocol import (
    FilterRequest,
    FilterReply,
    FilterCompletion,
    decode_filter_request,
    decode_filter_reply,
    decode_filter_completion,
    encode_filter_request,
    encode_filter_reply,
    encode_filter_completion,
    ProtocolError,
)
from cyber_os.protection.models import ScanVerdict


def test_protocol_round_trip_preserves_request_id() -> None:
    request = FilterRequest(
        request_id=42,
        operation="create",
        path=r"C:\Users\test\file.exe",
    )
    encoded = encode_filter_request(request)
    decoded = decode_filter_request(encoded)
    assert decoded.request_id == 42
    assert decoded.operation == "create"
    assert decoded.path == r"C:\Users\test\file.exe"


def test_protocol_rejects_wrong_version_and_length() -> None:
    # Wrong version (not 1) - encode a valid request then modify version
    request = FilterRequest(request_id=1, operation="create", path=r"C:\test.exe")
    encoded = encode_filter_request(request)
    # Modify version byte (at offset 4)
    bad_version = bytearray(encoded)
    bad_version[4] = 2  # Change version to 2
    with pytest.raises(ProtocolError, match="version"):
        decode_filter_request(bytes(bad_version))

    # Mismatched length (size field doesn't match actual payload)
    bad_length = b"\x10\x00\x00\x00" + b"\x00" * 100  # size=16 but payload is 100 bytes
    with pytest.raises(ProtocolError, match="mismatch"):
        decode_filter_request(bad_length)

    # Invalid operation - construct a valid-sized payload with invalid operation
    # Header: version(4) + request_id(8) + operation(4) + path_len(4) = 20 bytes
    # Path: 4 chars = 8 bytes
    # Total payload: 28 bytes, size field = 28
    invalid_op = (
        b"\x1c\x00\x00\x00"  # size = 28 bytes
        b"\x01\x00\x00\x00"  # version = 1
        b"\x2a\x00\x00\x00"  # request_id = 42
        b"\x00\x00\x00\x00"  # padding for request_id upper 32 bits
        b"\x05\x00\x00\x00"  # operation = 5 (invalid)
        b"\x04\x00\x00\x00"  # path length = 4
        b"test"  # path (8 bytes UTF-16)
    )
    with pytest.raises(ProtocolError, match="operation"):
        decode_filter_request(invalid_op)


def test_protocol_rejects_payload_over_64_kib() -> None:
    # Create a payload that exceeds 64 KiB manually
    large_payload = b"\x01\x00\x00\x00" + b"\x00" * (64 * 1024 + 100)
    large_payload = struct.pack("<I", len(large_payload)) + large_payload[4:]
    with pytest.raises(ProtocolError, match="64 KiB"):
        decode_filter_request(large_payload)


def test_unknown_verdict_serializes_as_allow() -> None:
    verdict = ScanVerdict(
        status="unknown",
        action="allow",
        rule_id=None,
        rule_version="test-1",
        sha256=None,
        reason="timeout",
    )
    reply = FilterReply(
        request_id=42,
        verdict=verdict,
    )
    encoded = encode_filter_reply(reply)
    decoded_reply = decode_filter_reply(encoded)
    assert decoded_reply.verdict.action == "allow"
    assert decoded_reply.verdict.status == "unknown"


def test_completion_frame_carries_final_io_status() -> None:
    completion = FilterCompletion(
        request_id=42,
        final_io_status="STATUS_ACCESS_DENIED",
    )
    encoded = encode_filter_completion(completion)
    decoded = decode_filter_completion(encoded)
    assert decoded.request_id == 42
    assert decoded.final_io_status == "STATUS_ACCESS_DENIED"


def test_reply_round_trip_preserves_verdict() -> None:
    verdict = ScanVerdict(
        status="detected",
        action="block",
        rule_id="hash-1",
        rule_version="test-1",
        sha256="a" * 64,
        reason="high-confidence block rule matched",
    )
    reply = FilterReply(request_id=100, verdict=verdict)
    encoded = encode_filter_reply(reply)
    decoded = decode_filter_reply(encoded)
    assert decoded.request_id == 100
    assert decoded.verdict.action == "block"
    assert decoded.verdict.rule_id == "hash-1"
    assert decoded.verdict.rule_version == "test-1"


def test_completion_round_trip_various_statuses() -> None:
    for status in [
        "STATUS_SUCCESS",
        "STATUS_ACCESS_DENIED",
        "STATUS_FILE_LOCK_CONFLICT",
        "STATUS_SHARING_VIOLATION",
        "STATUS_OBJECT_NAME_NOT_FOUND",
        "STATUS_OBJECT_PATH_NOT_FOUND",
        "STATUS_DELETE_PENDING",
    ]:
        completion = FilterCompletion(request_id=1, final_io_status=status)
        encoded = encode_filter_completion(completion)
        decoded = decode_filter_completion(encoded)
        assert decoded.final_io_status == status


def test_encode_decode_allow_verdict() -> None:
    verdict = ScanVerdict(
        status="clean",
        action="allow",
        rule_id=None,
        rule_version="test-1",
        sha256="a" * 64,
        reason="no signed rule matched",
    )
    reply = FilterReply(request_id=1, verdict=verdict)
    encoded = encode_filter_reply(reply)
    decoded = decode_filter_reply(encoded)
    assert decoded.verdict.action == "allow"
    assert decoded.verdict.status == "clean"


def test_reply_rejects_truncated_body() -> None:
    # Header declares a 10-char rule_id but no body bytes follow.
    header = struct.pack("<IQIIH", 1, 1, 1, 10, 0)  # verdict=1 (block), rule_id_len=10
    frame = struct.pack("<I", len(header) + 4) + header
    with pytest.raises(ProtocolError):
        decode_filter_reply(frame)


def test_reply_rejects_payload_over_64_kib() -> None:
    big = b"\x01\x00\x00\x00" + b"\x00" * (64 * 1024 + 50)
    big = struct.pack("<I", len(big)) + big[4:]
    with pytest.raises(ProtocolError, match="64 KiB"):
        decode_filter_reply(big)


def test_reply_rejects_wrong_version() -> None:
    verdict = ScanVerdict(
        status="detected",
        action="block",
        rule_id="hash-1",
        rule_version="test-1",
        sha256="a" * 64,
        reason="match",
    )
    encoded = bytearray(encode_filter_reply(FilterReply(request_id=1, verdict=verdict)))
    encoded[4] = 2  # corrupt version field
    with pytest.raises(ProtocolError, match="version"):
        decode_filter_reply(bytes(encoded))


def test_request_rejects_truncated_path() -> None:
    # Declared path_len (10 chars => 20 bytes) exceeds the bytes actually present.
    header = struct.pack("<IQII", 1, 1, 1, 10)
    payload = header + b"\x41\x00"  # only one UTF-16 char provided
    frame = struct.pack("<I", len(payload) + 4) + payload
    with pytest.raises(ProtocolError):
        decode_filter_request(frame)


def test_completion_rejects_wrong_size() -> None:
    with pytest.raises(ProtocolError):
        decode_filter_completion(b"\x10\x00\x00\x00" + b"\x00" * 12)  # 16 bytes, not 20