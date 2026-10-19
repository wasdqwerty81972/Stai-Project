"""Concrete ChatClient: POST a message to the running STAI UI's ``/api/chat``.

Stdlib only (``urllib``) so the bridge pulls in no new dependency. Not exercised by
the offline unit tests; live use is Phase 2. The endpoint contract is the existing
one in ``ui/api_server.py``: body ``{"message", "session_id"}`` -> ``{"status", "message"}``.
"""

from __future__ import annotations

import json
import urllib.request

DEFAULT_BASE_URL = "http://127.0.0.1:8000"


class HttpChatClient:
    """A ``ChatClient`` backed by the STAI UI's HTTP API."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL, timeout: float = 120.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def chat(self, message: str, session_id: str) -> str:
        payload = json.dumps({"message": message, "session_id": session_id}).encode("utf-8")
        request = urllib.request.Request(
            f"{self._base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self._timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
        if isinstance(body, dict) and body.get("status") == "error":
            raise RuntimeError(str(body.get("message", "chat request failed")))
        return str(body.get("message", "")) if isinstance(body, dict) else ""
