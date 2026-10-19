"""Exercise chat serialization and redaction at the outbound HTTP boundary."""

from __future__ import annotations

import io
import json

import pytest

from cyber_os.protection import ai_provider
from cyber_os.protection.triage import ProtectionTriage


class RecordingTransport:
    def open(self, request, timeout):
        self.body = json.loads(request.data)
        return io.BytesIO(
            b'{"candidates":[{"content":{"parts":[{"text":"Review the local evidence."}]}}]}'
        )


def test_chat_serializes_assistant_history_as_gemini_model_role(monkeypatch):
    transport = RecordingTransport()
    monkeypatch.setattr(ai_provider, "_no_redirect_opener", lambda: transport)
    provider = ai_provider.GeminiProtectionProvider(api_key="test-key", enabled=True)

    result = provider.respond(
        {},
        [{"role": "user", "content": "What happened?"},
         {"role": "assistant", "content": "A rule matched."}],
        "What should I review?",
    )

    assert result == "Review the local evidence."
    assert [turn["role"] for turn in transport.body["contents"]] == ["user", "model", "user"]


def test_chat_redacts_sensitive_history_and_question_at_network_boundary(monkeypatch):
    transport = RecordingTransport()
    monkeypatch.setattr(ai_provider, "_no_redirect_opener", lambda: transport)
    provider = ai_provider.GeminiProtectionProvider(api_key="test-key", enabled=True)
    digest = "0123456789abcdef" * 4

    provider.respond(
        {},
        [{"role": "user", "content": r"Inspect C:\Users\Alice\private.exe"},
         {"role": "assistant", "content": "Contact alice@example.com token=private-token"}],
        "Is this SHA256 relevant: " + digest,
    )

    payload = json.dumps(transport.body)
    for sensitive in ("Alice", "private.exe", "alice@example.com", "private-token", digest):
        assert sensitive not in payload
    assert "[redacted" in payload


def test_triage_redacts_file_hashes_before_durable_chat_storage():
    digest = "0123456789abcdef" * 4
    assert digest not in ProtectionTriage._sanitize_user_message("Please explain " + digest)


@pytest.mark.parametrize("text,secret", [
    ('password="correct horse battery staple"', "battery staple"),
    ("api_key='secret value with spaces'", "with spaces"),
    ("Authorization: Bearer opaque-session-credential", "opaque-session-credential"),
])
def test_privacy_filter_removes_entire_quoted_or_bearer_secret(text, secret):
    assert secret not in ProtectionTriage._sanitize_user_message("Please explain " + text)
