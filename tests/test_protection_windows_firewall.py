from __future__ import annotations

from dataclasses import dataclass

import pytest

from cyber_os.protection.windows_firewall import GROUPING, WindowsFirewallManager


@dataclass
class Rule:
    Name: str = ""
    Description: str = ""
    Grouping: str = ""
    Enabled: bool = False
    Direction: int = 0
    Action: int = 0
    Protocol: int = 0
    RemoteAddresses: str = ""
    Profiles: int = 0x7FFFFFFF
    ApplicationName: str = ""


class Rules:
    def __init__(self):
        self.values = {}

    def __iter__(self):
        return iter(self.values.values())

    def Item(self, name):
        return self.values[name]

    def Add(self, rule):
        if rule.Name in self.values:
            raise ValueError("duplicate")
        self.values[rule.Name] = rule

    def Remove(self, name):
        del self.values[name]


class Policy:
    CurrentProfileTypes = 7

    def __init__(self):
        self.Rules = Rules()

    def FirewallEnabled(self, _profile):
        return True

    def DefaultInboundAction(self, _profile):
        return 0

    def DefaultOutboundAction(self, _profile):
        return 1


def test_firewall_snapshot_reports_effective_profiles_and_only_managed_rules():
    policy = Policy()
    policy.Rules.values["other-rule"] = Rule(Name="other-rule", Grouping="Third party")
    result = WindowsFirewallManager(lambda: policy).snapshot()
    assert result["state"] == "active"
    assert [profile["name"] for profile in result["profiles"]] == ["domain", "private", "public"]
    assert result["managed_rules"] == []


def test_block_rule_is_narrow_owned_idempotent_and_verified():
    policy = Policy()
    manager = WindowsFirewallManager(lambda: policy, Rule)
    first = manager.block_remote_ip("8.8.8.8")
    second = manager.block_remote_ip("8.8.8.8")
    rule = policy.Rules.Item(first["rule_id"])
    assert first["success"] is True and first["created"] is True
    assert second["success"] is True and second["created"] is False
    assert rule.Grouping == GROUPING
    assert rule.Direction == 2 and rule.Action == 0 and rule.Enabled is True
    assert rule.RemoteAddresses == "8.8.8.8"


@pytest.mark.parametrize("address", ["not-an-ip", "127.0.0.1", "192.168.1.2", "224.0.0.1", "ff02::1", "203.0.113.4"])
def test_rejects_invalid_or_non_host_destinations(address):
    manager = WindowsFirewallManager(lambda: Policy(), Rule)
    with pytest.raises(ValueError):
        manager.block_remote_ip(address)


def test_cannot_remove_non_owned_firewall_rules():
    policy = Policy()
    rule_id = WindowsFirewallManager.rule_id_for_ip("8.8.4.4")
    policy.Rules.values[rule_id] = Rule(Name=rule_id, Grouping="Windows Defender")
    with pytest.raises(Exception, match="not owned"):
        WindowsFirewallManager(lambda: policy).remove_managed_rule(rule_id)


def test_cannot_remove_spoofed_rule_with_svs_grouping_marker():
    policy = Policy()
    rule_id = WindowsFirewallManager.rule_id_for_ip("8.8.4.4")
    spoofed = Rule(Name=rule_id, Grouping=GROUPING, Enabled=True, Direction=1, Action=1,
                   Protocol=6, RemoteAddresses="*")
    policy.Rules.values[rule_id] = spoofed
    with pytest.raises(Exception, match="not owned by SVS Cyber"):
        WindowsFirewallManager(lambda: policy).remove_managed_rule(rule_id)
    assert policy.Rules.Item(rule_id) is spoofed


def test_does_not_treat_unexpected_same_named_rule_as_idempotent():
    policy = Policy()
    rule_id = WindowsFirewallManager.rule_id_for_ip("8.8.8.8")
    policy.Rules.values[rule_id] = Rule(
        Name=rule_id, Grouping=GROUPING, Enabled=True, Direction=1, Action=1,
        Protocol=256, RemoteAddresses="*",
    )
    with pytest.raises(Exception, match="unexpected firewall rule"):
        WindowsFirewallManager(lambda: policy, Rule).block_remote_ip("8.8.8.8")
