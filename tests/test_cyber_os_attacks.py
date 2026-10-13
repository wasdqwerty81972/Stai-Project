"""Regression coverage for the inert CyberOS attack demonstration harness."""

from __future__ import annotations

import os
from types import SimpleNamespace
from pathlib import Path

import pytest

from cyber_os import cyber_os_attacks
from cyber_os.cyber_os_attacks import launch_attack
from cyber_os.engine import CyberOSEngine, ThreatAlert
from cyber_os.cyber_os_dashboard import launch_attack as dashboard_launch_attack


def test_dashboard_import_resolves_to_inert_demo_harness() -> None:
    assert dashboard_launch_attack is launch_attack


@pytest.mark.parametrize(
    ("attack_type", "expected_alert_type"),
    [
        ("bruteforce", "brute_force"),
        ("powershell", "suspicious_powershell"),
        ("portscan", "port_scan"),
        ("ransomware", "ransomware_behavior"),
    ],
)
def test_demo_attack_injects_one_synthetic_alert_without_host_side_effects(
    attack_type: str,
    expected_alert_type: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "cyber_db").mkdir()
    engine = CyberOSEngine(config_path="missing-config.json")
    engine.running = True

    def forbidden(*_args, **_kwargs):
        raise AssertionError("demo attacks must not execute commands or touch host files/network")

    monkeypatch.setattr(cyber_os_attacks, "subprocess", SimpleNamespace(run=forbidden), raising=False)
    monkeypatch.setattr(cyber_os_attacks, "socket", SimpleNamespace(socket=forbidden), raising=False)
    monkeypatch.setattr(cyber_os_attacks, "shutil", SimpleNamespace(copy2=forbidden), raising=False)
    monkeypatch.setattr(
        cyber_os_attacks,
        "os",
        SimpleNamespace(
            path=os.path,
            rename=forbidden,
            remove=forbidden,
            listdir=forbidden,
        ),
        raising=False,
    )
    monkeypatch.setattr(cyber_os_attacks, "open", forbidden, raising=False)

    result = launch_attack(attack_type, engine)

    assert isinstance(result, ThreatAlert)
    assert engine.alerts[-1] is result
    assert engine.ui_queue.get_nowait() is result
    assert engine.alert_queue.get_nowait() is result
    assert result.alert_type == expected_alert_type
    assert result.threat_score >= 8
    assert result.event_id in engine.event_index
    assert "Synthetic demonstration event" in result.evidence[0]
    approval_id = engine._request_response_approval(result)
    assert engine.has_pending_response_approval(approval_id)
