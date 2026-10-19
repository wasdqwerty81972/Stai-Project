"""Rule metadata reads must not serialize sensors or query protection stores."""

import json
from types import SimpleNamespace

import pytest

from cyber_os.protection.models import DetectionRule, RuleSet
from cyber_os.protection.rule_package import rule_set_fingerprint
from cyber_os.protection.windows_service import ProtectionServiceHost, _validate_pipe_request, PipeProtocolError


def test_rule_metadata_operation_is_allowlisted_with_empty_payload_only():
    request = {"version": 1, "request_id": "a" * 32, "operation": "get_rule_metadata", "payload": {}}
    assert _validate_pipe_request(request) == ("a" * 32, "get_rule_metadata", {})
    with pytest.raises(PipeProtocolError, match="payload fields"):
        _validate_pipe_request({**request, "payload": {"include_sensors": True}})


def test_metadata_dispatch_returns_only_authenticated_rule_identity():
    rules = RuleSet("signed-test", (DetectionRule("test-hash", "sha256", "a" * 64, "block", "high"),
        DetectionRule("test-yara", "yara", "rule test { condition: true }", "observe", "medium")))
    def expensive_status():
        raise AssertionError("metadata read invoked full status")
    host = ProtectionServiceHost(store=SimpleNamespace(), service=SimpleNamespace(rules=rules),
        rules_trusted=True, sensor_service=SimpleNamespace(get_status=expensive_status))
    host.get_status = expensive_status
    response = json.loads(host.handle_request(json.dumps({"version": 1, "request_id": "a" * 32,
        "operation": "get_rule_metadata", "payload": {}}).encode()))
    assert response["ok"] is True
    assert response["data"] == {"rules_trusted": True, "rules_version": "signed-test", "rule_count": 2,
        "sha256_rule_count": 1, "yara_rule_count": 1, "rules_fingerprint": rule_set_fingerprint(rules)}


def test_untrusted_rules_do_not_publish_fingerprint_or_counts():
    rules = RuleSet("untrusted", (DetectionRule("test", "sha256", "a" * 64, "block", "high"),))
    host = ProtectionServiceHost(store=SimpleNamespace(), service=SimpleNamespace(rules=rules), rules_trusted=False)
    assert host.dispatch("get_rule_metadata", {}) == {"rules_trusted": False, "rules_version": "unknown",
        "rule_count": 0, "sha256_rule_count": 0, "yara_rule_count": 0, "rules_fingerprint": None}
