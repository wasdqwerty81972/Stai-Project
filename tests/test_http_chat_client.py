"""Offline contract tests for ``HttpChatClient`` (Idea #10, Phase 1).

The live bridge's default ``ChatClient`` POSTs to the running UI's ``POST /api/chat``
(``ui/api_server.py``). Its own docstring notes it is "not exercised by the offline
unit tests" — this file pins that contract without any network: ``urllib`` is faked.

Covers: the exact request (method/URL/Content-Type/JSON body), the success path that
extracts ``message``, the ``{"status": "error"}`` path that must raise (never silently
return an error string as if it were the agent's reply), and non-dict bodies.
"""

from __future__ import annotations

import io
import json

import pytest

from stai_messaging.http_chat_client import DEFAULT_BASE_URL, HttpChatClient


class _FakeResponse(io.BytesIO):
    """A context-manager response whose ``read()`` returns the canned bytes."""

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc) -> None:
        return None


class _RecordingUrlopen:
    """Stand-in for ``urllib.request.urlopen`` that records the request and returns JSON."""

    def __init__(self, body: object, *, raw: bytes | None = None) -> None:
        self._body = body
        self._raw = raw
        self.requests: list[tuple[str, bytes, float | None]] = []

    def __call__(self, request, timeout=None):  # noqa: ANN001 - mirrors urlopen signature
        self.requests.append((request.full_url, request.data, timeout))
        content = self._raw if self._raw is not None else json.dumps(self._body).encode("utf-8")
        return _FakeResponse(content)


@pytest.fixture
def patch_urlopen(monkeypatch):
    """Return a factory that installs a recording urlopen and hands it back."""
    import stai_messaging.http_chat_client as mod

    def install(body: object, *, raw: bytes | None = None) -> _RecordingUrlopen:
        recorder = _RecordingUrlopen(body, raw=raw)
        monkeypatch.setattr(mod.urllib.request, "urlopen", recorder)
        return recorder

    return install


def test_default_base_url_points_at_local_ui():
    assert DEFAULT_BASE_URL == "http://127.0.0.1:8000"


def test_chat_posts_the_api_chat_contract(patch_urlopen):
    recorder = patch_urlopen({"status": "completed", "message": "Answer", "session_id": "s1"})
    client = HttpChatClient("http://127.0.0.1:8000")

    reply = client.chat("scan 10.0.0.1", "session-7")

    assert reply == "Answer"
    assert len(recorder.requests) == 1
    url, data, timeout = recorder.requests[0]
    assert url == "http://127.0.0.1:8000/api/chat"
    assert json.loads(data.decode("utf-8")) == {
        "message": "scan 10.0.0.1",
        "session_id": "session-7",
    }
    assert timeout == client._timeout


def test_base_url_trailing_slash_is_normalized(patch_urlopen):
    recorder = patch_urlopen({"message": "ok"})
    HttpChatClient("http://host:9000/").chat("hi", "s")

    assert recorder.requests[0][0] == "http://host:9000/api/chat"


def test_error_status_raises_and_never_returns_the_error_as_a_reply(patch_urlopen):
    patch_urlopen({"status": "error", "message": "A non-empty message is required"})
    client = HttpChatClient()

    with pytest.raises(RuntimeError, match="non-empty message"):
        client.chat("", "s")


def test_error_status_without_message_still_raises(patch_urlopen):
    patch_urlopen({"status": "error"})
    client = HttpChatClient()

    with pytest.raises(RuntimeError):
        client.chat("hi", "s")


def test_missing_message_field_yields_empty_string_not_a_crash(patch_urlopen):
    patch_urlopen({"status": "completed"})
    assert HttpChatClient().chat("hi", "s") == ""


def test_non_dict_body_yields_empty_string(patch_urlopen):
    # A malformed/proxied response must not crash the adapter with AttributeError.
    patch_urlopen(None, raw=b"[1, 2, 3]")
    assert HttpChatClient().chat("hi", "s") == ""


def test_empty_body_yields_empty_string(patch_urlopen):
    patch_urlopen(None, raw=b"{}")
    assert HttpChatClient().chat("hi", "s") == ""
