"""Startup readiness for the backend and the Next.js frontend.

`cyber_main._http_ready` decides "is this route actually serving?" It returns
True only for a 2xx/3xx response and False for everything else -- a 4xx/5xx, a
refused connection, a timeout, or a DNS failure all mean "not ready".

This is deliberately stricter than an earlier version of the probe, which
treated *any* HTTP response (including 404/500) as "the process is up". That
leniency existed to work around a probe pointed at /robots.txt: a Next.js dev
server answers 404 there, so a strict check would have hung the launcher for
its full 360s timeout. The launcher now probes routes that return 2xx when the
service is genuinely ready -- `/health` for the backend and `/` for the
frontend (see cyber_main.main) -- so the probe can hold out for a real success
and correctly reject a server that is listening but whose readiness route is
broken.

These tests pin that contract without binding it to any real port.
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

from cyber_main import _http_ready  # noqa: E402


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "http://127.0.0.1:6763/", code, "status", {}, io.BytesIO(b"")
    )


def _response(status: int) -> mock.MagicMock:
    """A urlopen() context manager yielding a response with the given status."""
    response = mock.MagicMock()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    response.status = status
    return response


def _patch_open(**kwargs: object) -> "mock._patch":
    """Patch the seam `_http_ready` actually calls.

    `_http_ready` builds an opener and calls `opener.open(...)`, so patching
    `urllib.request.urlopen` intercepts nothing: the probe would reach the real
    network and every assertion would be decided by whether localhost happened
    to be listening. Patch `OpenerDirector.open`, which is what
    `build_opener().open` resolves to.
    """
    return mock.patch.object(urllib.request.OpenerDirector, "open", **kwargs)


class HttpReadyTests(unittest.TestCase):
    """Only a 2xx/3xx response means the route is ready to serve."""

    def test_the_probe_does_not_reach_the_network(self) -> None:
        # Regression guard for the mock seam itself. If `_http_ready` is ever
        # reimplemented on a different transport, this fails loudly instead of
        # letting the suite silently make real connections and pass by luck.
        with _patch_open(return_value=_response(200)) as opened:
            self.assertTrue(_http_ready("http://127.0.0.1:6764/health"))
        self.assertEqual(opened.call_count, 1)

    def test_a_200_is_ready(self) -> None:
        with _patch_open(return_value=_response(200)):
            self.assertTrue(_http_ready("http://127.0.0.1:6764/health"))

    def test_a_3xx_is_ready(self) -> None:
        # The gate accepts anything below 400 (`200 <= status < 400`), so a
        # redirect surfaced by the opener still counts as the server responding.
        with _patch_open(return_value=_response(302)):
            self.assertTrue(_http_ready("http://127.0.0.1:6764/health"))

    def test_a_404_is_not_ready(self) -> None:
        # Reversed from the old lenient probe: a listening server whose
        # readiness route is missing is no longer accepted as ready. This is
        # safe because the launcher now probes /health and / (both answer 2xx
        # when ready), not an incidental route like /robots.txt that 404s.
        with _patch_open(side_effect=_http_error(404)):
            self.assertFalse(_http_ready("http://127.0.0.1:6763/"))

    def test_a_403_is_not_ready(self) -> None:
        with _patch_open(side_effect=_http_error(403)):
            self.assertFalse(_http_ready("http://127.0.0.1:6763/"))

    def test_a_500_is_not_ready(self) -> None:
        # Whether the server is merely listening is no longer enough: a 5xx on
        # the readiness route means the service is not actually serving yet.
        with _patch_open(side_effect=_http_error(500)):
            self.assertFalse(_http_ready("http://127.0.0.1:6763/"))

    def test_a_refused_connection_is_not_ready(self) -> None:
        with _patch_open(side_effect=urllib.error.URLError("connection refused")):
            self.assertFalse(_http_ready("http://127.0.0.1:6763/"))

    def test_a_timeout_is_not_ready(self) -> None:
        with _patch_open(side_effect=TimeoutError()):
            self.assertFalse(_http_ready("http://127.0.0.1:6763/"))

    def test_a_dns_failure_is_not_ready(self) -> None:
        with _patch_open(side_effect=urllib.error.URLError("name resolution failed")):
            self.assertFalse(_http_ready("http://127.0.0.1:6763/"))


class RedirectHandlingTests(unittest.TestCase):
    """`follow_redirects=False` treats a 3xx as "the route answered"."""

    def test_an_unfollowed_redirect_is_ready(self) -> None:
        # With redirects suppressed the opener raises instead of returning a
        # response, so the 3xx arrives on the HTTPError path and must still
        # count as the server serving that route.
        with _patch_open(side_effect=_http_error(302)):
            self.assertTrue(
                _http_ready("http://127.0.0.1:6764/health", follow_redirects=False)
            )

    def test_an_unfollowed_404_is_still_not_ready(self) -> None:
        with _patch_open(side_effect=_http_error(404)):
            self.assertFalse(
                _http_ready("http://127.0.0.1:6764/health", follow_redirects=False)
            )


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
