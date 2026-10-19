"""Offline regression tests for bounded, credential-safe feed transport."""

import io
from types import SimpleNamespace
import urllib.request
import zipfile

import pytest
import requests

import cyber_threat_intel as intel


def test_feed_fetch_installs_redirect_refusal(monkeypatch):
    handlers = []

    def opener(*items):
        handlers.extend(items)
        return SimpleNamespace(open=lambda *a, **k: io.BytesIO(b"metadata"))

    monkeypatch.setattr(urllib.request, "build_opener", opener)
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b"metadata"))
    assert intel.http_fetch("https://feeds.example/metadata", {"Auth-Key": "secret"}) == b"metadata"
    redirects = [handler for handler in handlers if isinstance(handler, urllib.request.HTTPRedirectHandler)]
    assert redirects, "credential-bearing feed fetch must explicitly disable redirects"
    request = urllib.request.Request("https://feeds.example/metadata")
    assert redirects[0].redirect_request(request, None, 302, "redirect", {},
                                         "https://other.example/metadata") is None


def test_feed_fetch_reads_only_limit_plus_one(monkeypatch):
    sizes = []

    class Response(io.BytesIO):
        def read(self, size=-1):
            sizes.append(size)
            return super().read(size)

    def response(*a, **k):
        return Response(b"123456789")

    monkeypatch.setattr(intel, "_MAX_FEED_DOWNLOAD_BYTES", 8, raising=False)
    monkeypatch.setattr(urllib.request, "urlopen", response)
    monkeypatch.setattr(urllib.request, "build_opener", lambda *a: SimpleNamespace(open=response))
    with pytest.raises(ValueError, match="ceiling"):
        intel.http_fetch("https://feeds.example/metadata")
    assert sizes == [9]


def test_zip_refuses_missing_requested_member():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("unexpected.txt", b"unexpected records")
    with pytest.raises(ValueError, match="member"):
        intel.unzip_feed_member(buffer.getvalue(), "expected.txt")


def test_zip_limits_actual_stream_read(monkeypatch):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("expected.txt", b"a")
    sizes = []

    class Stream(io.BytesIO):
        def read(self, size=-1):
            sizes.append(size)
            return super().read(size)

    monkeypatch.setattr(intel, "_MAX_FEED_MEMBER_BYTES", 8)
    monkeypatch.setattr(zipfile.ZipFile, "open", lambda *a, **k: Stream(b"123456789"))
    with pytest.raises(ValueError, match="ceiling"):
        intel.unzip_feed_member(buffer.getvalue(), "expected.txt")
    assert sizes == [9]


def test_lookup_disables_redirects(monkeypatch):
    captured = {}

    def get(*a, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(status_code=302, text="redirect")

    monkeypatch.setattr(intel, "_throttle", lambda *a: None)
    monkeypatch.setattr(requests, "get", get)
    result = intel._get("test", "https://provider.example/metadata", {"x-apikey": "secret"}, "secret")
    assert captured.get("allow_redirects") is False
    assert result["verdict"] == "unknown"


def test_lookup_scrubs_exception_credentials(monkeypatch, caplog):
    def fail(*a, **k):
        raise requests.ConnectionError("request contained lookup-secret")

    monkeypatch.setattr(intel, "_throttle", lambda *a: None)
    monkeypatch.setattr(requests, "get", fail)
    result = intel._get("test", "https://provider.example/metadata", {}, "lookup-secret")
    assert "lookup-secret" not in str(result)
    assert "lookup-secret" not in caplog.text


def test_ingestion_scrubs_exception_credentials(monkeypatch, caplog):
    failures = []
    store = SimpleNamespace(start_feed_run=lambda *a: "run",
                            finish_feed_run=lambda *a, **k: failures.append(k))

    def fail(*a, **k):
        raise OSError("request contained feed-secret")

    result = intel.ingest_feed(
        "fixture", store, fetcher=fail, auth_key="feed-secret",
        feed_definition={"url": "https://feeds.example/metadata", "format": "urlhaus_text",
                         "auth": "Auth-Key header", "env_var": "FIXTURE_KEY"},
    )
    assert "feed-secret" not in str(result)
    assert "feed-secret" not in str(failures)
    assert "feed-secret" not in caplog.text
