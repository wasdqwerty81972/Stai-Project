"""A WMI notification timeout must not kill process-event telemetry.

``SWbemEventSource.NextEvent(1000)`` raises wbemErrTimedout every time its
one-second window closes with no process starting or stopping -- the normal
case on an idle machine. pywin32 delivers that as ``DISP_E_EXCEPTION``
(0x80020009) with the real WBEM code (0x80043001) in ``excepinfo[5]``.

The watcher previously compared ``com_error.hresult`` against 0x80041069 --
both the wrong field and a code a live provider never puts there. The check
never matched, so the first idle second was misread as "subscription failed",
the watcher thread broke out of its loop, and the protection service
permanently reported ``event_source: unavailable`` with a misleading error.

tests/test_windows_process_events.py already covered a *synthetic* flat
``.hresult``, which is why this survived. These tests pin the exception shape a
real Windows 11 host actually produces.
"""

from __future__ import annotations

from types import SimpleNamespace

from ui.windows_process_events import _is_wmi_timeout


class _ComError(Exception):
    """Mirrors pywintypes.com_error: (hresult, strerror, excepinfo, argerror)."""

    def __init__(self, hresult, strerror, excepinfo, argerror=None):
        super().__init__(hresult, strerror, excepinfo, argerror)
        self.hresult = hresult
        self.strerror = strerror
        self.excepinfo = excepinfo
        self.argerror = argerror


def _observed_timeout() -> _ComError:
    """The exact error this host produced from Win32_ProcessStartTrace."""
    return _ComError(
        -2147352567,  # 0x80020009 DISP_E_EXCEPTION
        "Exception occurred.",
        (0, "SWbemEventSource", "Timed out ", None, 0, -2147209215),  # 0x80043001
        None,
    )


def test_the_real_host_timeout_is_recognised() -> None:
    assert _is_wmi_timeout(_observed_timeout()) is True


def test_timeout_reported_directly_on_hresult_is_recognised() -> None:
    # Some providers surface wbemErrTimedout without the DISP_E_EXCEPTION wrapper.
    assert _is_wmi_timeout(_ComError(-2147209215, "Timed out", None)) is True


def test_a_description_only_timeout_is_recognised() -> None:
    # DISP_E_EXCEPTION with no usable scode, but the description says timed out.
    error = _ComError(
        -2147352567,
        "Exception occurred.",
        (0, "SWbemEventSource", "Timed out ", None, 0, None),
    )

    assert _is_wmi_timeout(error) is True


def test_a_genuine_subscription_failure_is_not_swallowed() -> None:
    # Access denied must still tear the watcher down and surface an error --
    # the fix must not turn every COM failure into "keep waiting", or a real
    # permission problem would masquerade as healthy telemetry.
    access_denied = _ComError(
        -2147352567,
        "Exception occurred.",
        (0, "SWbemEventSource", "Access denied", None, 0, -2147217405),  # 0x80041003
    )

    assert _is_wmi_timeout(access_denied) is False


def test_an_unrelated_exception_is_not_a_timeout() -> None:
    assert _is_wmi_timeout(RuntimeError("boom")) is False
    assert _is_wmi_timeout(SimpleNamespace()) is False  # type: ignore[arg-type]


def test_a_malformed_excepinfo_does_not_raise() -> None:
    # Defensive: a short or non-sequence excepinfo must not crash the watcher.
    assert _is_wmi_timeout(_ComError(-2147352567, "x", (0, "src"))) is False
    assert _is_wmi_timeout(_ComError(-2147352567, "x", "not-a-tuple")) is False
