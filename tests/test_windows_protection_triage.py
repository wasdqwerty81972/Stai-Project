"""Behavior tests for bounded, privacy-filtered protection triage."""

from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path

import pytest

from cyber_os.protection.store import DetectionRecord, ProtectionStore
from cyber_os.protection.triage import (
    DetectionNotFound,
    InvalidAgentMessage,
    ProtectionTriage,
    SessionConflict,
    UnavailableTriageProvider,
)


class RecordingProvider:
    available = True

    def __init__(self, *, entered: threading.Event | None = None, release: threading.Event | None = None) -> None:
        self.entered = entered
        self.release = release
        self.contexts: list[dict[str, object]] = []
        self.messages: list[tuple[dict[str, object], list[dict[str, str]], str]] = []
        self.calls = 0

    def analyze(self, context: dict[str, object]) -> str:
        self.calls += 1
        self.contexts.append(context)
        if self.entered:
            self.entered.set()
        if self.release:
            assert self.release.wait(2)
        return "The signed high-confidence rule matched; review the event in the protection console."

    def respond(
        self,
        context: dict[str, object],
        history: list[dict[str, str]],
        message: str,
    ) -> str:
        self.messages.append((context, history, message))
        return "This event matches the configured rule. The protection service remains in control of enforcement."


def _record(
    detection_id: str,
    *,
    action: str = "block",
    path: str = r"C:\Users\Alice\Desktop\sample.exe",
) -> DetectionRecord:
    return DetectionRecord(
        detection_id=detection_id,
        sha256="a" * 64,
        rule_id="hash-1",
        rule_version="rules-7",
        action=action,  # type: ignore[arg-type]
        confidence="high",
        severity="critical",
        file_type=".exe",
        size_bytes=4096,
        file_path=path,
        created_at="2026-10-12T10:00:00",
        triage_enqueued=False,
    )


def _wait_for_status(store: ProtectionStore, detection_id: str, status: str) -> object:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        result = store.get_triage(detection_id)
        if result is not None and result.status == status:
            return result
        time.sleep(0.01)
    pytest.fail(f"triage did not reach {status!r}")


def test_provider_receives_only_allowlisted_coarse_detection_context(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    detection_id = str(uuid.uuid4())
    store.record_detection(_record(detection_id))
    provider = RecordingProvider()
    triage = ProtectionTriage(store, provider)

    record = triage.request(detection_id)
    completed = _wait_for_status(store, detection_id, "completed")

    assert record.detection_id == detection_id
    assert completed.summary.startswith("The signed high-confidence rule matched")
    assert provider.contexts == [
        {
            "rule_id": "hash-1",
            "rule_version": "rules-7",
            "severity": "critical",
            "confidence": "high",
            "action": "block",
            "file_category": "executable",
            "size_band": "under_1_mib",
        }
    ]
    assert "C:\\Users" not in repr(provider.contexts)
    assert "Alice" not in repr(provider.contexts)
    assert "a" * 64 not in repr(provider.contexts)


def test_duplicate_requests_share_one_async_triage_job(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    detection_id = str(uuid.uuid4())
    store.record_detection(_record(detection_id))
    entered = threading.Event()
    release = threading.Event()
    provider = RecordingProvider(entered=entered, release=release)
    triage = ProtectionTriage(store, provider, max_workers=1, max_pending=2)

    first = triage.request(detection_id)
    assert entered.wait(1)
    second = triage.request(detection_id)

    assert first.detection_id == second.detection_id == detection_id
    assert provider.calls == 1
    assert store.count_triage_jobs() == 1

    release.set()
    _wait_for_status(store, detection_id, "completed")


def test_pending_triage_capacity_is_bounded(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    first_id, second_id = str(uuid.uuid4()), str(uuid.uuid4())
    store.record_detection(_record(first_id))
    store.record_detection(_record(second_id))
    entered = threading.Event()
    release = threading.Event()
    provider = RecordingProvider(entered=entered, release=release)
    triage = ProtectionTriage(store, provider, max_workers=1, max_pending=1)

    triage.request(first_id)
    assert entered.wait(1)
    rejected = triage.request(second_id)

    assert rejected.status == "rejected"
    assert rejected.error == "triage capacity is full"
    assert provider.calls == 1

    release.set()
    _wait_for_status(store, first_id, "completed")

    retried = triage.request(second_id)
    assert retried.status in {"queued", "running", "completed"}
    _wait_for_status(store, second_id, "completed")
    assert provider.calls == 2


def test_unavailable_provider_returns_honest_state_without_calling_out(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    detection_id = str(uuid.uuid4())
    store.record_detection(_record(detection_id))
    triage = ProtectionTriage(store, UnavailableTriageProvider())

    result = triage.request(detection_id)

    assert result.status == "unavailable"
    assert result.error == "triage provider is unavailable"
    assert result.summary is None
    assert store.count_triage_jobs() == 1


def test_unavailable_triage_can_be_retried_when_provider_becomes_available(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    detection_id = str(uuid.uuid4())
    store.record_detection(_record(detection_id))

    class SwitchableProvider(RecordingProvider):
        available = False

    provider = SwitchableProvider()
    triage = ProtectionTriage(store, provider)
    first = triage.request(detection_id)
    provider.available = True
    retried = triage.request(detection_id)
    completed = _wait_for_status(store, detection_id, "completed")

    assert first.status == "unavailable"
    assert retried.status in {"queued", "running", "completed"}
    assert completed.summary
    assert provider.calls == 1


def test_failed_triage_retry_is_atomic_and_deduplicated(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    detection_id = str(uuid.uuid4())
    store.record_detection(_record(detection_id))
    entered = threading.Event()
    release = threading.Event()

    class FailOnceProvider(RecordingProvider):
        def analyze(self, context):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("provider unavailable")
            self.contexts.append(context)
            entered.set()
            assert release.wait(2)
            return "Recovered and analyzed."

    provider = FailOnceProvider()
    triage = ProtectionTriage(store, provider, max_workers=1, max_pending=2)
    triage.request(detection_id)
    _wait_for_status(store, detection_id, "failed")

    retry_results: list[object] = []
    barrier = threading.Barrier(3)

    def retry() -> None:
        barrier.wait()
        retry_results.append(triage.request(detection_id))

    threads = [threading.Thread(target=retry) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(1)

    assert entered.wait(1)
    assert provider.calls == 2
    assert store.count_triage_jobs() == 1
    release.set()
    assert _wait_for_status(store, detection_id, "completed").summary == "Recovered and analyzed."


def test_triage_output_is_stored_separately_from_level_one_verdict(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    detection_id = str(uuid.uuid4())
    store.record_detection(_record(detection_id))
    triage = ProtectionTriage(store, RecordingProvider())

    triage.request(detection_id)
    _wait_for_status(store, detection_id, "completed")
    detection = store.get_detection(detection_id)

    assert detection is not None
    assert (detection.action, detection.confidence, detection.rule_id) == ("block", "high", "hash-1")
    assert detection.triage_enqueued is False


def test_agent_chat_is_redacted_and_investigation_scoped(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    detection_id = str(uuid.uuid4())
    other_detection_id = str(uuid.uuid4())
    store.record_detection(_record(detection_id))
    store.record_detection(_record(other_detection_id, path=r"D:\Users\Bob\Downloads\other.exe"))
    provider = RecordingProvider()
    triage = ProtectionTriage(store, provider)
    session_id = str(uuid.uuid4())

    response = triage.send_message(
        session_id=session_id,
        detection_id=detection_id,
        message=r"Is this dangerous? C:\Users\Alice\Desktop\sample.exe password=supersecret and relative folder/payload.exe",
    )

    assert response["tool_calls"] == []
    assert response["response_action"] is None
    assert "C:\\Users" not in repr(provider.messages)
    assert "Alice" not in repr(provider.messages)
    assert "supersecret" not in repr(provider.messages)
    assert "folder/payload.exe" not in repr(provider.messages)
    assert "a" * 64 not in repr(provider.messages)
    assert store.get_triage_session_detection(session_id) == detection_id
    assert len(triage.history(session_id)) == 2

    with pytest.raises(SessionConflict):
        triage.send_message(
            session_id=session_id,
            detection_id=other_detection_id,
            message="Please explain this alert.",
        )


def test_agent_chat_redacts_bearer_and_common_api_token_shapes(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    detection_id = str(uuid.uuid4())
    store.record_detection(_record(detection_id))
    provider = RecordingProvider()
    triage = ProtectionTriage(store, provider)

    triage.send_message(
        session_id="token-check",
        detection_id=detection_id,
        message="Is this safe? Bearer sample-token-value and ghp_abcdefghijklmnopqrstuvwxyz123456",
    )

    provider_input = repr(provider.messages)
    assert "sample-token-value" not in provider_input
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in provider_input


def test_agent_chat_redacts_slash_and_spaced_windows_paths_from_provider_and_history(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    detection_id = str(uuid.uuid4())
    store.record_detection(_record(detection_id))
    provider = RecordingProvider()
    triage = ProtectionTriage(store, provider)
    slash_path = "C:/Users/Alice Smith/Desktop/sample.exe"
    spaced_backslash_path = r"C:\Users\Bob Jones\Downloads\payload.exe"
    session_id = "windows-path-check"

    triage.send_message(
        session_id=session_id,
        detection_id=detection_id,
        message=f"Review these: {slash_path}; and {spaced_backslash_path}",
    )

    provider_input = repr(provider.messages)
    persisted_history = repr(triage.history(session_id))
    for sensitive_path in (slash_path, "Alice Smith", "sample.exe", "Bob Jones", "payload.exe"):
        assert sensitive_path not in provider_input
        assert sensitive_path not in persisted_history


def test_agent_chat_rejects_embedded_command_lines(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    detection_id = str(uuid.uuid4())
    store.record_detection(_record(detection_id))
    triage = ProtectionTriage(store, RecordingProvider())

    with pytest.raises(InvalidAgentMessage, match="command-line text"):
        triage.send_message(
            session_id="command-check",
            detection_id=detection_id,
            message=r"I ran powershell.exe -ExecutionPolicy Bypass -File C:\Users\Alice\Desktop\fix.ps1",
        )


def test_agent_chat_requires_an_existing_detection_for_new_session(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    triage = ProtectionTriage(store, RecordingProvider())

    with pytest.raises(DetectionNotFound):
        triage.send_message(
            session_id="new-session",
            detection_id="missing",
            message="Please explain this alert.",
        )


def test_store_reopens_with_triage_result_separate_from_detection_verdict(tmp_path: Path) -> None:
    database = tmp_path / "protection.db"
    detection_id = str(uuid.uuid4())
    store = ProtectionStore(database)
    store.record_detection(_record(detection_id))
    triage = ProtectionTriage(store, RecordingProvider())
    triage.request(detection_id)
    _wait_for_status(store, detection_id, "completed")

    reopened = ProtectionStore(database)
    result = reopened.get_triage(detection_id)
    detection = reopened.get_detection(detection_id)

    assert result is not None
    assert result.status == "completed"
    assert result.summary.startswith("The signed high-confidence rule matched")
    assert detection is not None and detection.action == "block"
