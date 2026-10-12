"""Isolated, bounded Level 2 analysis for Level 1 protection detections.

The default provider is intentionally unavailable. A caller must inject an
analysis-only provider; this module never creates a network client or executes
commands or remediation suggested by model text.
"""

from __future__ import annotations

import re
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Protocol

from .store import ProtectionStore, TriageRecord


_RULE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
_SESSION_TOKEN = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_WINDOWS_PATH = re.compile(
    r"(?i)(?:\b[a-z]:[\\/]|\\\\)(?:[^\\/:*?\"<>|\r\n]+[\\/])*?"
    r"[^\\/:*?\"<>|\r\n]*?\.[A-Za-z0-9]{1,16}\b"
)
_WINDOWS_ROOTED_PATH = re.compile(
    r"(?i)(?<![A-Za-z0-9])[a-z]:[\\/](?:[^\\/:*?\"<>|\s]+[\\/])*[^\\/:*?\"<>|\s]+"
)
_UNC_PATH = re.compile(r"(?i)(?<![A-Za-z0-9])\\\\[^\\/\s]+(?:\\[^\\/\s]+)+")
_POSIX_PATH = re.compile(r"(?<!:)\/(?:[A-Za-z0-9_.~-]+\/)+[A-Za-z0-9_.~-]+(?:\.[A-Za-z0-9_.~-]+)?")
_RELATIVE_PATH = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9_.~-]+\s+)?[A-Za-z0-9_.~-]+"
    r"(?:[\\/][A-Za-z0-9_.~-]+)+\.[A-Za-z0-9]{1,16}\b"
)
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passphrase|secret|token|api[_-]?key|authorization)\b\s*[:=]\s*[^\s,;]+"
)
_SECRET_PHRASE = re.compile(
    r"(?i)\b(?:my\s+)?(?:password|passphrase|secret|token|api[_-]?key|authorization)\b"
    r"\s+(?:is|was)\b[^,;.!?]*"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*")
_TOKEN_SHAPE = re.compile(
    r"(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-(?:live_)?[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{20,}|"
    r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
)
_COMMAND_LINE_MARKER = re.compile(
    r"(?i)\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|bash|sh|curl|wget|"
    r"invoke-webrequest|remove-item|format(?:\.com)?|reg(?:\.exe)?|del|erase|rm|whoami|"
    r"ipconfig|taskkill|schtasks|wevtutil|certutil|bitsadmin)\b|(?:&&|\|\||[|])"
)
_UNSAFE_FILE_CATEGORY = {
    ".exe": "executable", ".dll": "executable", ".sys": "executable",
    ".bat": "script", ".cmd": "script", ".ps1": "script", ".vbs": "script", ".js": "script",
    ".doc": "document", ".docx": "document", ".xls": "document", ".xlsx": "document",
    ".pdf": "document", ".rtf": "document",
    ".zip": "archive", ".7z": "archive", ".rar": "archive", ".iso": "archive",
}

MAX_TURN_CHARS = 2000
MAX_PROVIDER_OUTPUT_CHARS = 4000


class TriageProvider(Protocol):
    """Injected analysis provider. Implementations must not expose tools/actions."""

    available: bool

    def analyze(self, context: dict[str, Any]) -> str: ...

    def respond(
        self,
        context: dict[str, Any],
        history: list[dict[str, str]],
        message: str,
    ) -> str: ...


class UnavailableTriageProvider:
    """Safe default until a provider is explicitly configured by the host."""

    available = False

    def analyze(self, context: dict[str, Any]) -> str:
        raise RuntimeError("triage provider is unavailable")

    def respond(self, context: dict[str, Any], history: list[dict[str, str]], message: str) -> str:
        raise RuntimeError("triage provider is unavailable")


class DetectionNotFound(LookupError):
    """The requested detection does not exist in the local Level 1 store."""


class SessionNotFound(LookupError):
    """The requested investigation session does not exist."""


class SessionConflict(ValueError):
    """An investigation session was reused for a different detection."""


class InvalidAgentMessage(ValueError):
    """The message is empty, oversized, or contains command/code text."""


class ProtectionTriage:
    """Deduplicated bounded triage with detection-scoped, tool-free chat."""

    def __init__(
        self,
        store: ProtectionStore,
        provider: TriageProvider | None = None,
        *,
        max_workers: int = 2,
        max_pending: int = 16,
    ) -> None:
        if max_workers < 1 or max_pending < max_workers:
            raise ValueError("triage capacity must allow at least one worker")
        self.store = store
        self.provider = provider or UnavailableTriageProvider()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="stai-triage")
        self._capacity = threading.BoundedSemaphore(max_pending)
        self._closed = False

    def close(self) -> None:
        """Stop accepting work, revoke provider access, and drain active jobs."""
        if self._closed:
            return
        self._closed = True
        close_provider = getattr(self.provider, "close", None)
        try:
            if callable(close_provider):
                close_provider()
        finally:
            self._executor.shutdown(wait=True, cancel_futures=True)
            self.store.fail_pending_triage("protection service stopped before triage completed")

    def request(self, detection_id: str) -> TriageRecord:
        """Enqueue one analysis per detection, returning durable current state."""
        if self._closed:
            raise RuntimeError("protection triage is stopping")
        existing = self.store.get_triage(detection_id)
        retryable = {"unavailable", "rejected", "failed"}
        if existing is not None and existing.status not in retryable:
            return existing
        if self.store.get_triage_source(detection_id) is None:
            raise DetectionNotFound(detection_id)

        if not self._provider_available():
            if existing is None:
                record, _ = self.store.create_triage(
                    detection_id, status="unavailable", error="triage provider is unavailable"
                )
                return record
            self.store.defer_triage_retry(
                detection_id, status="unavailable", error="triage provider is unavailable"
            )
            return self.store.get_triage(detection_id) or existing

        if not self._capacity.acquire(blocking=False):
            if existing is None:
                record, _ = self.store.create_triage(
                    detection_id, status="rejected", error="triage capacity is full"
                )
                return record
            self.store.defer_triage_retry(
                detection_id, status="rejected", error="triage capacity is full"
            )
            return self.store.get_triage(detection_id) or existing

        try:
            if existing is None:
                record, created = self.store.create_triage(detection_id, status="queued")
                if not created:
                    self._capacity.release()
                    return record
            else:
                if not self.store.retry_triage(detection_id):
                    self._capacity.release()
                    return self.store.get_triage(detection_id) or existing
                record = self.store.get_triage(detection_id) or existing
            self._executor.submit(self._analyze, detection_id)
            return self.store.get_triage(detection_id) or record
        except Exception:
            self._capacity.release()
            raise

    def get(self, detection_id: str) -> TriageRecord | None:
        return self.store.get_triage(detection_id)

    def _analyze(self, detection_id: str) -> None:
        try:
            self.store.update_triage(detection_id, status="running")
            source = self.store.get_triage_source(detection_id)
            if source is None:
                raise DetectionNotFound(detection_id)
            output = self.provider.analyze(self._build_context(source))
            summary = self._provider_text(output)
            self.store.update_triage(detection_id, status="completed", summary=summary)
        except Exception as exc:
            self.store.update_triage(
                detection_id,
                status="failed",
                error=f"triage analysis failed ({type(exc).__name__})",
            )
        finally:
            self._capacity.release()

    def send_message(
        self,
        *,
        session_id: str,
        message: str,
        detection_id: str | None = None,
    ) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError("protection triage is stopping")
        session_id = self._validate_session_id(session_id)
        safe_message = self._sanitize_user_message(message)

        bound_detection = self.store.get_triage_session_detection(session_id)
        if bound_detection is None:
            if not detection_id:
                raise SessionNotFound(session_id)
            if self.store.get_triage_source(detection_id) is None:
                raise DetectionNotFound(detection_id)
            if not self.store.create_triage_session(session_id, detection_id):
                bound_detection = self.store.get_triage_session_detection(session_id)
                if bound_detection != detection_id:
                    raise SessionConflict("session belongs to another detection")
            bound_detection = bound_detection or detection_id
        elif detection_id is not None and detection_id != bound_detection:
            raise SessionConflict("session belongs to another detection")

        assert bound_detection is not None
        source = self.store.get_triage_source(bound_detection)
        if source is None:
            raise DetectionNotFound(bound_detection)
        context = self._build_context(source)
        history = self.store.list_triage_messages(session_id, limit=40)
        # Keep only local/redacted text in the durable conversation and provider input.
        history = [{"role": item["role"], "content": self._sanitize_for_provider(item["content"])} for item in history]
        self.store.record_triage_message(session_id, "user", safe_message)

        if not self._provider_available() or not callable(getattr(self.provider, "respond", None)):
            response = "Protection triage provider is unavailable."
            status = "unavailable"
        elif getattr(self.provider, "async_responses", False):
            if not self._capacity.acquire(blocking=False):
                response = "Protection analysis is busy. Try again shortly."
                status = "rejected"
            else:
                try:
                    self._executor.submit(
                        self._respond_async,
                        session_id,
                        context,
                        history,
                        safe_message,
                    )
                    return {
                        "session_id": session_id,
                        "detection_id": bound_detection,
                        "message": "Protection analysis is processing your question.",
                        "tool_calls": [],
                        "response_action": None,
                        "status": "queued",
                    }
                except Exception:
                    self._capacity.release()
                    response = "Protection triage could not queue this response."
                    status = "failed"
        else:
            try:
                response = self._provider_text(self.provider.respond(context, history, safe_message))
                status = "completed"
            except Exception:
                response = "Protection triage could not complete this response."
                status = "failed"
        self.store.record_triage_message(session_id, "assistant", response)
        return {
            "session_id": session_id,
            "detection_id": bound_detection,
            "message": response,
            "tool_calls": [],
            "response_action": None,
            "status": status,
        }

    def _respond_async(
        self,
        session_id: str,
        context: dict[str, Any],
        history: list[dict[str, str]],
        message: str,
    ) -> None:
        try:
            response = self._provider_text(self.provider.respond(context, history, message))
        except Exception:
            response = "Protection triage could not complete this response."
        try:
            self.store.record_triage_message(session_id, "assistant", response)
        finally:
            self._capacity.release()

    def history(self, session_id: str) -> list[dict[str, str]]:
        session_id = self._validate_session_id(session_id)
        if self.store.get_triage_session_detection(session_id) is None:
            raise SessionNotFound(session_id)
        return self.store.list_triage_messages(session_id, limit=40)

    def session_detection(self, session_id: str) -> str:
        session_id = self._validate_session_id(session_id)
        detection_id = self.store.get_triage_session_detection(session_id)
        if detection_id is None:
            raise SessionNotFound(session_id)
        return detection_id

    def _provider_available(self) -> bool:
        try:
            return self.provider.available is True
        except Exception:
            return False

    @staticmethod
    def _build_context(source: dict[str, Any]) -> dict[str, Any]:
        """Project raw Level 1 metadata into a strict, non-identifying allowlist."""
        rule_id = source.get("rule_id")
        version = source.get("rule_version")
        severity = source.get("severity")
        confidence = source.get("confidence")
        action = source.get("action")
        extension = source.get("file_type")
        size = source.get("size_bytes")
        if not isinstance(rule_id, str) or not _RULE_TOKEN.fullmatch(rule_id):
            rule_id = "unknown"
        if not isinstance(version, str) or not _RULE_TOKEN.fullmatch(version):
            version = "unknown"
        if severity not in {"critical", "high", "medium", "low", "info"}:
            severity = "unknown"
        if confidence not in {"high", "medium", "low"}:
            confidence = "unknown"
        if action not in {"allow", "block"}:
            action = "unknown"
        if not isinstance(extension, str):
            category = "other"
        else:
            category = _UNSAFE_FILE_CATEGORY.get(extension.lower(), "other")
        if not isinstance(size, int) or size < 0:
            size_band = "unknown"
        elif size < 1024 * 1024:
            size_band = "under_1_mib"
        elif size < 10 * 1024 * 1024:
            size_band = "1_to_10_mib"
        elif size < 100 * 1024 * 1024:
            size_band = "10_to_100_mib"
        else:
            size_band = "100_mib_or_more"
        return {
            "rule_id": rule_id,
            "rule_version": version,
            "severity": severity,
            "confidence": confidence,
            "action": action,
            "file_category": category,
            "size_band": size_band,
        }

    @staticmethod
    def _validate_session_id(session_id: str) -> str:
        if not isinstance(session_id, str) or not _SESSION_TOKEN.fullmatch(session_id):
            raise InvalidAgentMessage("session_id must contain only letters, digits, underscore, or hyphen")
        return session_id

    @staticmethod
    def _sanitize_user_message(message: str) -> str:
        if not isinstance(message, str) or not message.strip():
            raise InvalidAgentMessage("message must not be empty")
        if len(message) > MAX_TURN_CHARS:
            raise InvalidAgentMessage("message exceeds the size limit")
        if "\n" in message or "\r" in message or "```" in message or "`" in message:
            raise InvalidAgentMessage("code blocks and multiline messages are not accepted")
        if _COMMAND_LINE_MARKER.search(message) or re.match(r"^\s*(?:PS\s*>|[A-Za-z]:\\[^\r\n>]*>)", message, re.I):
            raise InvalidAgentMessage("command-line text is not accepted")
        return ProtectionTriage._sanitize_for_provider(message)

    @staticmethod
    def _sanitize_for_provider(message: str) -> str:
        text = _WINDOWS_PATH.sub("[redacted path]", message)
        text = _WINDOWS_ROOTED_PATH.sub("[redacted path]", text)
        text = _UNC_PATH.sub("[redacted path]", text)
        text = _POSIX_PATH.sub("[redacted path]", text)
        text = _RELATIVE_PATH.sub("[redacted path]", text)
        text = _SECRET_ASSIGNMENT.sub("[redacted secret]", text)
        text = _SECRET_PHRASE.sub("[redacted secret]", text)
        text = _BEARER.sub("[redacted credential]", text)
        text = _TOKEN_SHAPE.sub("[redacted credential]", text)
        text = _EMAIL.sub("[redacted identity]", text)
        text = re.sub(r"(?i)\b(?:user(?:name)?|account)\s*[:=]\s*[^\s,;]+", "[redacted identity]", text)
        return text.strip()[:MAX_TURN_CHARS]

    @staticmethod
    def _provider_text(value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("provider returned an empty response")
        return value.strip()[:MAX_PROVIDER_OUTPUT_CHARS]
