"""Startup readiness for the backend and the Next.js frontend.

The launcher's gate decided "is this process serving?" by asking urlopen for a
2xx-4xx status. urlopen raises HTTPError for anything >= 400 and HTTPError
subclasses URLError, so the status comparison could only ever see 2xx/3xx and
the 4xx half was dead code: a Next.js dev server that answered every request
with 404 was indistinguishable from one refusing connections, and the launcher
polled to its 360s timeout and then tore the stack down. That is what happened
to the frontend probe, which was pointed at /robots.txt.

These tests pin the behaviour the gate is supposed to have, without binding it
to any real port.
"""

from __future__ import annotations

import io
import os
import sys
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_main import _http_responded  # noqa: E402


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "http://127.0.0.1:6763/", code, "status", {}, io.BytesIO(b"")
    )


class HttpRespondedTests(unittest.TestCase):
    """Any HTTP response means the process is listening."""

    def test_a_404_counts_as_listening(self) -> None:
        # The regression: a 404 used to be swallowed by the same except clause
        # as a refused connection, so the gate never accepted a server that was
        # plainly up and answering.
        with mock.patch.object(
            urllib.request, "urlopen", side_effect=_http_error(404)
        ):
            self.assertTrue(_http_responded("http://127.0.0.1:6763/robots.txt"))

    def test_a_403_also_counts_as_listening(self) -> None:
        with mock.patch.object(
            urllib.request, "urlopen", side_effect=_http_error(403)
        ):
            self.assertTrue(_http_responded("http://127.0.0.1:6763/"))

    def test_a_500_still_counts_as_listening(self) -> None:
        # Whether the app is healthy is not this probe's question. Reporting the
        # process as absent on a 5xx would reintroduce the same hang, just with
        # a different status code.
        with mock.patch.object(
            urllib.request, "urlopen", side_effect=_http_error(500)
        ):
            self.assertTrue(_http_responded("http://127.0.0.1:6763/"))

    def test_a_200_is_listening(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with mock.patch.object(urllib.request, "urlopen", return_value=response):
            self.assertTrue(_http_responded("http://127.0.0.1:6763/"))

    def test_a_refused_connection_is_not_listening(self) -> None:
        with mock.patch.object(
            urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            self.assertFalse(_http_responded("http://127.0.0.1:6763/"))

    def test_a_timeout_is_not_listening(self) -> None:
        with mock.patch.object(urllib.request, "urlopen", side_effect=TimeoutError()):
            self.assertFalse(_http_responded("http://127.0.0.1:6763/"))

    def test_a_dns_failure_is_not_listening(self) -> None:
        with mock.patch.object(
            urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("name resolution failed"),
        ):
            self.assertFalse(_http_responded("http://127.0.0.1:6763/"))


class FrontendProbeTargetTests(unittest.TestCase):
    """The probe must not depend on a route unrelated to the UI."""

    def test_launcher_does_not_gate_on_robots_txt(self) -> None:
        source_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "cyber_main.py",
        )
        source = open(source_path, encoding="utf-8").read()
        self.assertNotIn(
            'wait_ready(\n                    f"{frontend_url}/robots.txt"',
            source,
            "frontend readiness still gates on /robots.txt, so a 404 there "
            "blocks startup for the full timeout",
        )
        self.assertIn('f"{frontend_url}/"', source)


if __name__ == "__main__":
    unittest.main()
