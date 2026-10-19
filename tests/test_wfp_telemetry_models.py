from __future__ import annotations

from dataclasses import replace

import pytest

from cyber_os.network_telemetry.models import (
    ModelValidationError,
    NetworkEvent,
    NetworkPolicy,
    NetworkPolicyRule,
    ProcessEvent,
    WfpCapabilityReport,
)


def _network_event(**overrides):
    values = {
        "sequence": 1,
        "event_id": "wfp:1",
        "timestamp_utc": "2026-10-14T10:11:12.123Z",
        "source": "wfp_net_event",
        "event_type": "connect_authorize",
        "layer": "ALE_AUTH_CONNECT_V4",
        "direction": "outbound",
        "ip_family": "IPv4",
        "protocol": "TCP",
        "local_address": "192.0.2.10",
        "local_port": 53000,
        "remote_address": "198.51.100.25",
        "remote_port": 443,
        "process_id": 1234,
        "process_create_time": 100.5,
        "application_id": r"\device\harddiskvolume3\apps\sample.exe",
        "compartment_id": 1,
        "interface_index": 7,
        "flow_id": 99,
        "reauthorization": False,
        "action": "observed",
        "reason": "WFP net event notification",
        "capture_status": "complete",
        "attribution_status": "verified",
    }
    values.update(overrides)
    return NetworkEvent(**values)


def test_network_event_round_trip_is_versioned_and_byte_bounded():
    event = _network_event()

    payload = event.to_dict()
    restored = NetworkEvent.from_dict(payload)

    assert payload["schema_version"] == 1
    assert restored == event
    assert len(event.to_json().encode("utf-8")) <= NetworkEvent.MAX_JSON_BYTES


def test_network_event_keeps_unavailable_metadata_explicitly_unknown():
    event = _network_event(
        event_type="flow_established",
        layer=None,
        direction="unknown",
        ip_family="unknown",
        protocol="unknown",
        local_address=None,
        local_port=None,
        remote_address=None,
        remote_port=None,
        process_id=None,
        process_create_time=None,
        application_id=None,
        compartment_id=None,
        interface_index=None,
        flow_id=None,
        attribution_status="unavailable",
        capture_status="partial",
    )

    assert event.process_identity is None
    assert event.to_dict()["remote_address"] is None
    assert "bytes_sent" not in event.to_dict()


def test_verified_network_attribution_requires_pid_and_creation_time():
    with pytest.raises(ModelValidationError, match="verified attribution"):
        _network_event(
            attribution_status="verified",
            process_id=None,
            process_create_time=None,
            application_id=r"\device\harddiskvolume3\apps\sample.exe",
        )
    with pytest.raises(ModelValidationError, match="verified attribution"):
        _network_event(attribution_status="verified", process_create_time=None)

    # An application identity alone is useful evidence, but does not prove a
    # PID-to-process-instance join across PID reuse.
    assert _network_event(
        attribution_status="unverified",
        process_id=1234,
        process_create_time=None,
    ).process_identity is None


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": 2},
        {"sequence": True},
        {"sequence": 0},
        {"event_id": ""},
        {"timestamp_utc": "2026-10-14T10:11:12"},
        {"source": "kernel_memory_scan"},
        {"event_type": "arbitrary"},
        {"action": "execute"},
        {"reauthorization": 1},
        {"reason": "x" * 513},
        {"application_id": "*"},
    ],
)
def test_network_event_rejects_invalid_or_overlong_values(change):
    with pytest.raises(ModelValidationError):
        _network_event(**change)


def test_network_event_rejects_mismatched_layer_family_and_direction():
    with pytest.raises(ModelValidationError, match="layer"):
        _network_event(layer="ALE_AUTH_CONNECT_V6")
    with pytest.raises(ModelValidationError, match="direction"):
        _network_event(
            event_type="recv_accept_authorize",
            layer="ALE_AUTH_RECV_ACCEPT_V4",
            direction="outbound",
        )
    with pytest.raises(ModelValidationError, match="address"):
        _network_event(remote_address="2001:db8::1")
    with pytest.raises(ModelValidationError, match="ip_family"):
        _network_event(layer=None, ip_family="unknown", remote_address="198.51.100.25")
    with pytest.raises(ModelValidationError, match="observation or continue"):
        _network_event(source="wfp_callout", action="permit")
    with pytest.raises(ModelValidationError, match="require a layer"):
        _network_event(source="wfp_callout", layer=None)


@pytest.mark.parametrize("action", ["observed", "continue", "unknown"])
def test_inspection_callout_actions_are_non_terminating(action):
    assert _network_event(source="wfp_callout", action=action).action == action


@pytest.mark.parametrize("action", ["permit", "block"])
def test_inspection_callout_cannot_claim_a_terminating_action(action):
    with pytest.raises(ModelValidationError, match="observation callout"):
        _network_event(source="wfp_callout", action=action)


def test_wfp_net_event_does_not_use_callout_continue_action():
    with pytest.raises(ModelValidationError, match="net-event source"):
        _network_event(source="wfp_net_event", action="continue")


def test_network_event_decoder_rejects_extra_and_missing_fields():
    payload = _network_event().to_dict()
    with pytest.raises(ModelValidationError, match="unknown"):
        NetworkEvent.from_dict({**payload, "bytes_sent": 1})
    payload.pop("remote_address")
    with pytest.raises(ModelValidationError, match="missing"):
        NetworkEvent.from_dict(payload)


def test_process_event_derives_identity_from_pid_and_creation_time():
    event = ProcessEvent(
        sequence=3,
        event_id="process:3",
        timestamp_utc="2026-10-14T10:11:12Z",
        source="etw",
        event_type="start",
        process_id=1234,
        parent_process_id=1200,
        process_create_time=100.5,
        process_name="sample.exe",
        image_path=r"C:\Apps\sample.exe",
        command_line=None,
        metadata_status="partial",
    )

    assert event.process_identity == f"1234:{100.5.hex()}"
    assert ProcessEvent.from_dict(event.to_dict()) == event


def test_process_event_rejects_pid_reuse_identity_mismatch_and_unbounded_metadata():
    payload = ProcessEvent(
        sequence=1,
        event_id="process:1",
        timestamp_utc="2026-10-14T10:11:12Z",
        source="snapshot",
        event_type="snapshot",
        process_id=8,
        parent_process_id=None,
        process_create_time=1.0,
        process_name="sample.exe",
        image_path=None,
        command_line=None,
        metadata_status="complete",
    ).to_dict()
    with pytest.raises(ModelValidationError, match="identity"):
        ProcessEvent.from_dict({**payload, "process_identity": "8:0x1.0000000000000p+1"})
    with pytest.raises(ModelValidationError):
        ProcessEvent.from_dict({**payload, "command_line": "x" * 8193})


def test_process_event_rejects_payload_over_serialized_frame_limit():
    with pytest.raises(ModelValidationError, match="byte limit"):
        ProcessEvent(
            sequence=1,
            event_id="process:large",
            timestamp_utc="2026-10-14T10:11:12Z",
            source="etw",
            event_type="start",
            process_id=8,
            parent_process_id=None,
            process_create_time=1.0,
            process_name="x" * 260,
            image_path="x" * 2048,
            command_line="€" * 8192,
            metadata_status="complete",
        )


def test_observation_only_policy_is_default_and_serializes_strictly():
    policy = NetworkPolicy()

    assert policy.mode == "observe_only"
    assert policy.rules == ()
    assert NetworkPolicy.from_dict(policy.to_dict()) == policy


def test_policy_rejects_block_rules_without_explicit_enablement_and_evidence():
    rule = NetworkPolicyRule(
        rule_id="block-bad-endpoint",
        action="block",
        application_id=None,
        remote_address="198.51.100.25",
        direction="outbound",
        protocol="TCP",
        remote_port=443,
        ttl_seconds=300,
        reason="confirmed malicious endpoint",
        evidence_ref="finding:123",
        approval_ref=None,
        evidence_confidence="high",
    )

    with pytest.raises(ModelValidationError, match="observe_only"):
        NetworkPolicy(rules=(rule,))
    with pytest.raises(ModelValidationError, match="authorization"):
        NetworkPolicy(
            mode="enforcement_requested",
            rules=(replace(rule, evidence_ref=None, evidence_confidence=None),),
        )
    requested = NetworkPolicy(mode="enforcement_requested", rules=(rule,))
    assert requested.rules == (rule,)
    assert requested.to_dict()["mode"] == "enforcement_requested"
    assert "authorized" not in requested.to_dict()
    with pytest.raises(ModelValidationError, match="mode"):
        NetworkPolicy(mode="authorized", rules=(rule,))


@pytest.mark.parametrize("confidence", [None, "low", "medium"])
def test_block_evidence_requires_high_confidence_or_explicit_approval(confidence):
    values = {
        "rule_id": "block-bad-endpoint",
        "action": "block",
        "application_id": None,
        "remote_address": "198.51.100.25",
        "direction": "outbound",
        "protocol": "TCP",
        "remote_port": 443,
        "ttl_seconds": 300,
        "reason": "evidence has not reached a high-confidence threshold",
        "evidence_ref": "finding:123",
        "approval_ref": None,
        "evidence_confidence": confidence,
    }
    with pytest.raises(ModelValidationError, match="high confidence"):
        NetworkPolicyRule(**values)
    approved = NetworkPolicyRule(**{**values, "approval_ref": "approval:human-123"})
    assert approved.approval_ref == "approval:human-123"


def test_policy_evidence_confidence_requires_an_evidence_reference():
    with pytest.raises(ModelValidationError, match="requires evidence_ref"):
        NetworkPolicyRule(
            rule_id="observe-without-evidence",
            action="observe",
            application_id="app-id:sample",
            remote_address=None,
            direction="outbound",
            protocol="any",
            remote_port=None,
            ttl_seconds=300,
            reason="observation",
            evidence_ref=None,
            approval_ref=None,
            evidence_confidence="high",
        )


@pytest.mark.parametrize(
    "change",
    [
        {"application_id": None, "remote_address": None},
        {"application_id": r"C:\Apps\*.exe", "remote_address": None},
        {"application_id": None, "remote_address": "198.51.100.0/24"},
        {"application_id": None, "remote_address": "127.0.0.1"},
        {"remote_port": 65536},
        {"ttl_seconds": 0},
        {"ttl_seconds": 86401},
        {"rule_id": "Bad Rule ID"},
    ],
)
def test_policy_rule_rejects_ambiguous_broad_or_unbounded_targets(change):
    values = {
        "rule_id": "safe-rule",
        "action": "observe",
        "application_id": None,
        "remote_address": "198.51.100.25",
        "direction": "outbound",
        "protocol": "TCP",
        "remote_port": 443,
        "ttl_seconds": 300,
        "reason": "test observation",
        "evidence_ref": None,
        "approval_ref": None,
    }
    values.update(change)
    with pytest.raises(ModelValidationError):
        NetworkPolicyRule(**values)


def test_policy_rejects_unknown_fields_and_more_than_rule_limit():
    with pytest.raises(ModelValidationError, match="unknown"):
        NetworkPolicy.from_dict({"schema_version": 1, "mode": "observe_only", "rules": [], "permit_all": True})
    rule = NetworkPolicyRule(
        rule_id="observe",
        action="observe",
        application_id="app-id:sample",
        remote_address=None,
        direction="outbound",
        protocol="any",
        remote_port=None,
        ttl_seconds=300,
        reason="test",
        evidence_ref=None,
        approval_ref=None,
    )
    with pytest.raises(ModelValidationError, match="rule limit"):
        NetworkPolicy(rules=(rule,) * (NetworkPolicy.MAX_RULES + 1))


def test_policy_rejects_serialized_document_over_frame_limit():
    rules = tuple(
        NetworkPolicyRule(
            rule_id=f"observe-{index}",
            action="observe",
            application_id="a" * 2048,
            remote_address=None,
            direction="outbound",
            protocol="any",
            remote_port=None,
            ttl_seconds=300,
            reason="r" * 256,
            evidence_ref=None,
            approval_ref=None,
        )
        for index in range(40)
    )
    with pytest.raises(ModelValidationError, match="byte limit"):
        NetworkPolicy(rules=rules)


def test_capability_report_does_not_claim_a_callout_gap_until_proof_exists():
    unproven = WfpCapabilityReport(
        platform_supported=True,
        bfe_state="running",
        engine_state="open",
        subscription_state="active",
        events_observed=False,
        observed_fields=(),
        required_fields=("remote_address", "protocol"),
        max_event_latency_ms=None,
        latency_budget_ms=100,
        callout_state="not_evaluated",
        last_error=None,
    )
    sufficient = replace(
        unproven,
        events_observed=True,
        observed_fields=("remote_address", "protocol"),
        max_event_latency_ms=50,
        callout_state="not_required",
    )
    gap = replace(
        sufficient,
        observed_fields=("protocol",),
        callout_state="required_unavailable",
    )

    assert unproven.proof_state == "unproven"
    assert sufficient.proof_state == "proven_sufficient"
    assert gap.proof_state == "proven_gap"
    with pytest.raises(ModelValidationError):
        replace(unproven, callout_state="required_unavailable")


def test_capability_report_distinguishes_permission_and_bfe_failures():
    denied = WfpCapabilityReport(
        platform_supported=True,
        bfe_state="running",
        engine_state="denied",
        subscription_state="not_started",
        events_observed=False,
        observed_fields=(),
        required_fields=("remote_address",),
        max_event_latency_ms=None,
        latency_budget_ms=100,
        callout_state="not_evaluated",
        last_error="access denied",
    )
    stopped = replace(denied, bfe_state="stopped", engine_state="unavailable")

    assert denied.health_state == "degraded"
    assert stopped.health_state == "unavailable"
    assert WfpCapabilityReport.from_dict(denied.to_dict()) == denied
    not_started = replace(denied, engine_state="open", subscription_state="not_started")
    assert not_started.health_state == "degraded"
