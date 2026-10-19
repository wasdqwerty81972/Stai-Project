"""Reliability: absent driver / absent service / absent YARA must DEGRADE.

Agent 7 (QA/Reliability) baseline guard for the three ways this product meets
a real machine it does not fully own:

  1. the minifilter driver is not loaded (no admin, install not run, driver
     blocked by another AV),
  2. the protection service host has no backing service,
  3. the optional YARA runtime is not installed.

In every case the requirement is the same and it is a *safety* requirement, not
a convenience one: the product must stay up, must answer, and must NOT claim to
be protecting the machine. Silently reporting "active" with no driver attached
is worse than crashing, because the user stops looking.

Scope note: everything here runs against in-memory stand-ins for the *native*
transport. It is NOT kernel or driver integration coverage and must never be
reported as such -- it pins the user-mode degradation contract only.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Any, Optional

import pytest


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_os.protection.filter_client import (  # noqa: E402
    FilterClient,
    NativeFilterClient,
    NativeFilterMessage,
    create_filter_client,
    fail_open_verdict,
)
from cyber_os.protection.models import DetectionRule, RuleSet  # noqa: E402
from cyber_os.protection.scanner import scan_path  # noqa: E402
from cyber_os.protection.store import ProtectionStore  # noqa: E402


class _UnavailableNative(NativeFilterClient):
    """A Filter Manager port that is simply not there -- the honest default.

    This is what the user-mode client sees on a machine where the driver was
    never installed, failed to load, or was blocked.
    """

    def __init__(self) -> None:
        self.close_calls = 0

    def connect(self, port_name: str, timeout_ms: int) -> bool:
        return False

    def receive(self, timeout_ms: int) -> Optional[NativeFilterMessage]:
        return None

    def send(self, data: bytes) -> bool:
        return False

    def reply(self, message_id: int, data: bytes) -> bool:
        return False

    def close(self) -> None:
        self.close_calls += 1


# ---------------------------------------------------------------------------
# 1. Driver absent
# ---------------------------------------------------------------------------


def test_filter_client_reports_not_connected_when_the_driver_is_absent() -> None:
    """connect() must return False, not raise, when there is no port."""
    client = FilterClient(native_client=_UnavailableNative())
    assert client.connect() is False
    assert bool(getattr(client, "connected", getattr(client, "_connected", False))) is False


def test_filter_client_close_is_idempotent_with_no_driver() -> None:
    """Shutdown must be safe to call on a client that never connected."""
    client = FilterClient(native_client=_UnavailableNative())
    client.close()
    client.close()  # must not raise on the second pass


def test_create_filter_client_is_constructible_offline() -> None:
    """Building the client must not require a loaded driver or elevation."""
    client = create_filter_client(native_client=_UnavailableNative())
    assert client is not None
    assert bool(getattr(client, "connected", getattr(client, "_connected", False))) is False


def test_fail_open_verdict_can_never_deny_io() -> None:
    """The degraded verdict must allow I/O and must be labelled unknown.

    A minifilter that denies on failure bricks the OS, so fail-open is correct.
    What matters is that it is *observably* unknown rather than a clean allow.
    """
    verdict = fail_open_verdict("driver unavailable")
    assert verdict.action == "allow"
    assert verdict.status == "unknown", (
        "a fail-open verdict reported as anything other than 'unknown' would "
        "let a degraded scan masquerade as a clean result"
    )
    assert verdict.rule_id is None


# ---------------------------------------------------------------------------
# 2. Status must not claim protection while degraded
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("driver_state", "service_state"),
    [
        ("stopped", "running"),
        ("running", "stopped"),
        ("stopped", "stopped"),
        ("error", "running"),
        ("unknown", "unknown"),
    ],
)
def test_status_never_reports_active_unless_driver_and_service_both_run(
    tmp_path: Path, driver_state: str, service_state: str
) -> None:
    """Partial availability must surface as 'degraded', never as 'active'."""
    store = ProtectionStore(tmp_path / "protection.sqlite3")
    status = store.get_status(
        driver_state=driver_state,  # type: ignore[arg-type]
        service_state=service_state,  # type: ignore[arg-type]
    )

    assert status.state != "active", (
        f"driver_state={driver_state!r} service_state={service_state!r} was "
        f"reported as {status.state!r}. The product must not claim active "
        "protection unless the driver AND the service are both running."
    )
    assert status.state == "degraded"


def test_status_reports_active_only_when_everything_is_running(tmp_path: Path) -> None:
    """The positive case, so the assertion above cannot pass by always failing."""
    store = ProtectionStore(tmp_path / "protection.sqlite3")
    status = store.get_status(driver_state="running", service_state="running")
    assert status.state == "active"


def test_degraded_status_cannot_fabricate_a_blocked_count(tmp_path: Path) -> None:
    """With no confirmed driver denial, Threats Blocked must be zero."""
    store = ProtectionStore(tmp_path / "protection.sqlite3")
    status = store.get_status(driver_state="stopped", service_state="stopped")
    assert status.counts["blocked"] == 0, (
        "Threats Blocked must count only confirmed STATUS_ACCESS_DENIED filter "
        "completions reported by the driver; with no driver it cannot be > 0"
    )


class _InertPipeServer:
    """Pipe server stand-in: the host must not need a real named pipe to answer."""

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None


def test_service_host_status_is_answerable_with_no_driver_and_no_service(
    tmp_path: Path,
) -> None:
    """get_status() must return a usable dict, bare-metal, and not claim active."""
    windows_service = importlib.import_module("cyber_os.protection.windows_service")
    host = windows_service.ProtectionServiceHost(
        store=ProtectionStore(tmp_path / "protection.sqlite3"),
        service=None,
        filter_client=None,
        pipe_server=_InertPipeServer(),
        rules_trusted=False,
        windows_security_reader=lambda: None,
        health_refresh_seconds=3600,
    )
    try:
        status = host.get_status()
    finally:
        host.stop()

    assert isinstance(status, dict)
    assert status["driver_state"] == "stopped", (
        f"with filter_client=None the host reported driver_state="
        f"{status['driver_state']!r}; an absent driver must read as stopped"
    )
    assert status["state"] != "active", (
        f"host with no driver and no service reported state={status['state']!r}"
    )
    assert status["rules_trusted"] is False
    assert status["rule_count"] == 0


def test_service_host_start_stop_is_idempotent_with_nothing_attached(
    tmp_path: Path,
) -> None:
    """Repeated start/stop with no driver or service must not raise."""
    windows_service = importlib.import_module("cyber_os.protection.windows_service")
    host = windows_service.ProtectionServiceHost(
        store=ProtectionStore(tmp_path / "protection.sqlite3"),
        service=None,
        filter_client=None,
        pipe_server=_InertPipeServer(),
        rules_trusted=False,
        windows_security_reader=lambda: None,
        health_refresh_seconds=3600,
    )
    host.start()
    host.start()
    host.stop()
    host.stop()


# ---------------------------------------------------------------------------
# 3. YARA runtime absent
# ---------------------------------------------------------------------------


_YARA_RULE = DetectionRule(
    id="yara-reliability-1",
    kind="yara",
    value='rule marker { strings: $a = "STAI_RELIABILITY_MARKER" condition: $a }',
    action="block",
    confidence="high",
)


def test_scan_with_an_unevaluable_yara_rule_degrades_observably(tmp_path: Path) -> None:
    """A YARA rule that cannot run must yield unknown/allow WITH a reason.

    This is the honesty invariant for the scanner: when the YARA runtime is
    missing the engine cannot evaluate the rule, so it must not return a clean
    allow. It must return 'unknown' and say why, so the UI can show degraded
    rather than protected.
    """
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"STAI_RELIABILITY_MARKER payload")

    verdict = scan_path(sample, RuleSet(version="reliability-1", rules=(_YARA_RULE,)))

    if verdict.status == "detected":
        # YARA is installed and the rule really matched: that is the good path.
        assert verdict.action == "block"
        return

    assert verdict.status == "unknown", (
        f"a YARA rule that could not be evaluated produced status="
        f"{verdict.status!r}; an unevaluable rule must never read as clean"
    )
    assert verdict.action == "allow"
    assert getattr(verdict, "reason_code", None), (
        "a degraded verdict must carry a machine-readable reason_code so the "
        "UI can distinguish 'scanned and clean' from 'could not scan'"
    )


def test_scanner_does_not_crash_when_the_yara_runtime_is_missing(tmp_path: Path) -> None:
    """An absent optional engine must degrade, not propagate an ImportError."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"benign content")
    verdict = scan_path(sample, RuleSet(version="reliability-2", rules=(_YARA_RULE,)))
    assert verdict is not None
    assert verdict.action == "allow"


def test_signed_hash_rules_still_detect_while_yara_is_unavailable(tmp_path: Path) -> None:
    """Losing the YARA engine must not take the sha256 path down with it."""
    import hashlib

    content = b"STAI_RELIABILITY_MARKER hash path must survive"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(content)
    hash_rule = DetectionRule(
        id="sha256-reliability-1",
        kind="sha256",
        value=hashlib.sha256(content).hexdigest(),
        action="block",
        confidence="high",
    )

    verdict = scan_path(
        sample, RuleSet(version="reliability-3", rules=(hash_rule, _YARA_RULE))
    )

    assert (verdict.status, verdict.action, verdict.rule_id) == (
        "detected",
        "block",
        "sha256-reliability-1",
    )


# ---------------------------------------------------------------------------
# 4. Shipping-readiness gate: the real engine must actually be present
# ---------------------------------------------------------------------------


def test_yara_runtime_is_installed_so_yara_rules_are_enforceable() -> None:
    """requirements-windows-protection.txt pins yara-python; it must import.

    This is NOT a duplicate of the degradation tests above. Those prove the
    product survives without YARA. This one proves the product SHIPS with it.
    Without the runtime every `kind == "yara"` rule silently resolves to
    unknown/allow -- the scanner fails open on the entire YARA ruleset while
    the suite stays green, because the only real YARA test in
    tests/test_windows_protection_scanner.py is an importorskip.
    """
    try:
        import yara  # noqa: F401
    except ImportError as exc:
        pytest.fail(
            "the YARA runtime is not importable, so every YARA detection rule "
            f"fails open to unknown/allow on this machine ({exc}). "
            "requirements-windows-protection.txt pins yara-python==4.5.4 -- "
            "install it (pip install yara-python==4.5.4) or the product ships "
            "with its YARA ruleset unenforced."
        )
