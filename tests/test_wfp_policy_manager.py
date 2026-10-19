import ipaddress
from uuid import UUID

import pytest

from cyber_os.network_telemetry.wfp_policy import (
    DEFAULT_MAX_TTL_SECONDS,
    Direction,
    WfpCleanupError,
    PolicyMutationDisabled,
    RuleNotFound,
    WfpPolicyManager,
    WfpPolicyError,
    WfpPolicyValidationError,
    WfpOwnershipError,
)


class FakeWfpApi:
    """Transactional fake. It never connects to the host WFP engine."""

    def __init__(self):
        self.calls = []
        self.sessions = {}
        self.filters = {}
        self._snapshots = {}
        self.fail_on = None

    def _call(self, name, *args):
        self.calls.append((name, *args))
        if self.fail_on == name or (
            isinstance(self.fail_on, set) and name in self.fail_on
        ):
            raise RuntimeError(f"injected {name} failure")

    def open_dynamic_session(self, session_key):
        self._call("open_dynamic_session", session_key)
        handle = object()
        self.sessions[handle] = {"session_key": session_key, "objects": set()}
        return handle

    def close_dynamic_session(self, session):
        self._call("close_dynamic_session", session)
        owned = self.sessions.pop(session, {"objects": set()})["objects"]
        for key in owned:
            self.filters.pop(key, None)
        self._snapshots.pop(session, None)

    def begin_transaction(self, session):
        self._call("begin_transaction", session)
        self._snapshots[session] = (
            dict(self.filters),
            set(self.sessions[session]["objects"]),
        )

    def commit_transaction(self, session):
        self._call("commit_transaction", session)
        self._snapshots.pop(session, None)

    def abort_transaction(self, session):
        self._call("abort_transaction", session)
        snapshot = self._snapshots.pop(session, None)
        if snapshot is not None:
            filters, objects = snapshot
            self.filters = filters
            self.sessions[session]["objects"] = objects

    def add_provider(self, session, provider_key, display_name):
        self._call("add_provider", session, provider_key, display_name)
        self.sessions[session]["objects"].add(provider_key)

    def add_sublayer(self, session, sublayer_key, provider_key, display_name):
        self._call("add_sublayer", session, sublayer_key, provider_key, display_name)
        self.sessions[session]["objects"].add(sublayer_key)

    def get_filter(self, session, filter_key):
        self._call("get_filter", session, filter_key)
        return self.filters.get(filter_key)

    def add_filter(self, session, filter_spec):
        self._call("add_filter", session, filter_spec)
        if filter_spec.filter_key in self.filters:
            raise RuntimeError("duplicate filter key")
        self.filters[filter_spec.filter_key] = filter_spec
        self.sessions[session]["objects"].add(filter_spec.filter_key)

    def delete_filter(self, session, filter_key):
        self._call("delete_filter", session, filter_key)
        self.filters.pop(filter_key, None)
        self.sessions[session]["objects"].discard(filter_key)


def manager(api=None, *, enabled=True, clock=lambda: 100.0, max_ttl=DEFAULT_MAX_TTL_SECONDS):
    api = api or FakeWfpApi()
    policy = WfpPolicyManager(
        api,
        policy_mutation_enabled=enabled,
        clock=clock,
        max_ttl_seconds=max_ttl,
    )
    return policy, api


def start(policy):
    policy.start()
    return policy


def test_policy_mutation_is_disabled_by_default_without_touching_wfp():
    policy, api = manager(enabled=False)
    policy.start()

    with pytest.raises(PolicyMutationDisabled):
        policy.block_application(
            app_id=b"opaque-wfp-app-id", protocol="TCP", ttl_seconds=60, reason="test"
        )

    assert api.calls == []


def test_mutation_gate_requires_a_real_boolean():
    api = FakeWfpApi()
    with pytest.raises(ValueError, match="explicit boolean"):
        WfpPolicyManager(api, policy_mutation_enabled="false")
    assert api.calls == []


def test_start_uses_dynamic_session_and_only_fixed_owned_provider_keys():
    policy, api = manager()
    policy.start()

    session = policy.session
    assert session in api.sessions
    assert api.calls[0][0] == "open_dynamic_session"
    assert [call[0] for call in api.calls] == [
        "open_dynamic_session",
        "begin_transaction",
        "add_provider",
        "add_sublayer",
        "commit_transaction",
    ]
    provider_call = next(call for call in api.calls if call[0] == "add_provider")
    sublayer_call = next(call for call in api.calls if call[0] == "add_sublayer")
    assert provider_call[2] == policy.PROVIDER_KEY
    assert sublayer_call[2] == policy.SUBLAYER_KEY
    assert sublayer_call[3] == policy.PROVIDER_KEY

    policy.stop()
    assert session not in api.sessions
    assert not api.filters


def test_application_block_is_exact_and_covers_both_ip_families():
    policy, api = manager()
    start(policy)
    app_id = b"opaque-app-id-from-fwpm-get-app-id"

    rule = policy.block_application(
        app_id=app_id,
        protocol="TCP",
        direction=Direction.OUTBOUND,
        ttl_seconds=120,
        reason="confirmed test verdict",
        rule_id="b9a98640-f11f-4fd3-b49c-ef201879a50e",
    )

    filters = [api.filters[key] for key in rule.filter_keys]
    assert {item.layer for item in filters} == {
        "ALE_AUTH_CONNECT_V4",
        "ALE_AUTH_CONNECT_V6",
    }
    for item in filters:
        assert item.action == "block"
        assert item.provider_key == policy.PROVIDER_KEY
        assert item.sublayer_key == policy.SUBLAYER_KEY
        assert item.condition_map == {"app_id": app_id, "protocol": 6}
    assert rule.expires_at == 220.0


@pytest.mark.parametrize(
    ("direction", "expected_layer"),
    [
        (Direction.OUTBOUND, "ALE_AUTH_CONNECT_V4"),
        (Direction.INBOUND, "ALE_AUTH_RECV_ACCEPT_V4"),
    ],
)
def test_endpoint_block_matches_only_exact_address_port_protocol_and_direction(
    direction, expected_layer
):
    policy, api = manager()
    start(policy)

    rule = policy.block_endpoint(
        remote_address="8.8.8.8",
        remote_port=53,
        protocol="UDP",
        direction=direction,
        ttl_seconds=30,
        reason="explicit user policy",
    )

    assert len(rule.filter_keys) == 1
    spec = api.filters[rule.filter_keys[0]]
    assert spec.layer == expected_layer
    assert spec.action == "block"
    assert spec.condition_map == {
        "remote_address": "8.8.8.8",
        "remote_prefix_length": 32,
        "remote_port": 53,
        "protocol": 17,
    }
    assert ipaddress.ip_address(spec.condition_map["remote_address"]).is_global


def test_ipv6_endpoint_is_canonical_and_uses_exact_128_bit_prefix():
    policy, api = manager()
    start(policy)

    rule = policy.block_endpoint(
        remote_address="2001:4860:4860:0:0:0:0:8888",
        remote_port=443,
        protocol="TCP",
        direction="outbound",
        ttl_seconds=60,
        reason="explicit policy",
    )

    spec = api.filters[rule.filter_keys[0]]
    assert spec.layer == "ALE_AUTH_CONNECT_V6"
    assert spec.condition_map["remote_address"] == "2001:4860:4860::8888"
    assert spec.condition_map["remote_prefix_length"] == 128


@pytest.mark.parametrize(
    "kwargs",
    [
        {"remote_address": "0.0.0.0"},
        {"remote_address": "127.0.0.1"},
        {"remote_address": "192.168.1.1"},
        {"remote_address": "224.0.0.1"},
        {"remote_address": "169.254.1.2"},
        {"remote_address": "not-an-ip"},
        {"remote_port": 0},
        {"remote_port": 65536},
        {"remote_port": True},
        {"protocol": "ICMP"},
        {"direction": "both"},
        {"ttl_seconds": 0},
        {"ttl_seconds": DEFAULT_MAX_TTL_SECONDS + 1},
        {"ttl_seconds": float("inf")},
        {"reason": "\nblock everything"},
    ],
)
def test_invalid_endpoint_rules_are_rejected_before_any_wfp_mutation(kwargs):
    policy, api = manager()
    start(policy)
    before = len(api.calls)
    values = {
        "remote_address": "8.8.8.8",
        "remote_port": 443,
        "protocol": "TCP",
        "direction": "outbound",
        "ttl_seconds": 60,
        "reason": "explicit policy",
    }
    values.update(kwargs)

    with pytest.raises(WfpPolicyValidationError):
        policy.block_endpoint(**values)

    assert len(api.calls) == before


@pytest.mark.parametrize("app_id", [b"", b"x" * 4097, "C:\\malware.exe", None])
def test_invalid_application_identity_is_rejected_before_wfp_mutation(app_id):
    policy, api = manager()
    start(policy)
    before = len(api.calls)

    with pytest.raises(WfpPolicyValidationError):
        policy.block_application(
            app_id=app_id, protocol="TCP", ttl_seconds=60, reason="test"
        )

    assert len(api.calls) == before


def test_rule_removal_reverses_only_its_exact_owned_filter_keys():
    policy, api = manager()
    start(policy)
    first = policy.block_application(
        app_id=b"app-one", protocol="TCP", ttl_seconds=60, reason="one"
    )
    second = policy.block_endpoint(
        remote_address="8.8.4.4",
        remote_port=443,
        protocol="TCP",
        direction="outbound",
        ttl_seconds=60,
        reason="two",
    )

    assert policy.remove_rule(first.rule_id) is True
    assert set(api.filters) == set(second.filter_keys)
    assert [call[2] for call in api.calls if call[0] == "delete_filter"] == list(
        first.filter_keys
    )
    assert policy.remove_rule(first.rule_id) is False
    with pytest.raises(RuleNotFound):
        policy.remove_rule("81f0df6c-0ffb-4d32-9a77-bdeab2e1eb87")


def test_filter_ownership_is_checked_before_deletion():
    policy, api = manager()
    start(policy)
    rule = policy.block_endpoint(
        remote_address="8.8.8.8",
        remote_port=443,
        protocol="TCP",
        direction="outbound",
        ttl_seconds=60,
        reason="test",
    )
    key = rule.filter_keys[0]
    actual = api.filters[key]
    # Simulate a foreign object collision rather than an object owned by this
    # dynamic session. Closing the manager's session must leave it untouched.
    api.sessions[policy.session]["objects"].discard(key)
    api.filters[key] = actual.__class__(
        **{**actual.__dict__, "provider_key": UUID("11111111-1111-1111-1111-111111111111")}
    )

    with pytest.raises(WfpOwnershipError):
        policy.remove_rule(rule.rule_id)

    assert not [call for call in api.calls if call[0] == "delete_filter"]
    assert key in api.filters


def test_expired_rules_are_removed_transactionally_and_reported():
    now = [100.0]
    policy, api = manager(clock=lambda: now[0])
    start(policy)
    rule = policy.block_endpoint(
        remote_address="1.1.1.1",
        remote_port=53,
        protocol="UDP",
        direction="outbound",
        ttl_seconds=10,
        reason="short test rule",
    )
    now[0] = 109.9
    assert policy.expire_due_rules() == ()
    now[0] = 110.0

    assert policy.expire_due_rules() == (rule.rule_id,)
    assert rule.filter_keys[0] not in api.filters
    assert not policy.rules


def test_failed_setup_aborts_and_closes_dynamic_session():
    api = FakeWfpApi()
    api.fail_on = "add_sublayer"
    policy, _ = manager(api)

    with pytest.raises(RuntimeError, match="injected add_sublayer failure"):
        policy.start()

    assert [call[0] for call in api.calls][-3:] == [
        "add_sublayer",
        "abort_transaction",
        "close_dynamic_session",
    ]
    assert not api.sessions
    assert not api.filters
    assert not policy.is_started


def test_filter_add_failure_aborts_and_closes_session_to_fail_open():
    policy, api = manager()
    start(policy)
    session = policy.session
    api.fail_on = "add_filter"

    with pytest.raises(RuntimeError, match="injected add_filter failure"):
        policy.block_application(
            app_id=b"opaque-app-id", protocol="UDP", ttl_seconds=60, reason="test"
        )

    assert session not in api.sessions
    assert not api.filters
    assert not policy.is_started
    assert [call[0] for call in api.calls][-3:] == [
        "abort_transaction",
        "close_dynamic_session",
        "add_filter",
    ] or "close_dynamic_session" in [call[0] for call in api.calls]


def test_failed_commit_aborts_and_closes_session_without_publishing_rule():
    policy, api = manager()
    start(policy)
    api.fail_on = "commit_transaction"

    with pytest.raises(RuntimeError, match="injected commit_transaction failure"):
        policy.block_endpoint(
            remote_address="8.8.8.8",
            remote_port=80,
            protocol="TCP",
            direction="outbound",
            ttl_seconds=60,
            reason="test",
        )

    assert not policy.rules
    assert not policy.is_started
    assert not api.sessions
    assert not api.filters
    assert "abort_transaction" in [call[0] for call in api.calls]


def test_failed_session_cleanup_blocks_restart_until_stop_retries_cleanup():
    policy, api = manager()
    start(policy)
    session = policy.session
    api.fail_on = "add_filter"

    # The add fails, then the fail-open session close also fails.
    api.fail_on = {"add_filter", "close_dynamic_session"}
    with pytest.raises(WfpCleanupError):
        policy.block_endpoint(
            remote_address="8.8.8.8",
            remote_port=443,
            protocol="TCP",
            direction="outbound",
            ttl_seconds=60,
            reason="test",
        )

    assert policy.is_degraded
    assert session in api.sessions
    open_calls = len([call for call in api.calls if call[0] == "open_dynamic_session"])
    with pytest.raises(WfpPolicyError):
        policy.start()
    assert len([call for call in api.calls if call[0] == "open_dynamic_session"]) == open_calls

    api.fail_on = None
    policy.stop()
    assert not api.sessions
    assert not policy.is_degraded


def test_stop_removes_filters_and_closes_session_even_if_delete_transaction_fails():
    policy, api = manager()
    start(policy)
    policy.block_endpoint(
        remote_address="8.8.8.8",
        remote_port=443,
        protocol="TCP",
        direction="outbound",
        ttl_seconds=60,
        reason="test",
    )
    session = policy.session
    api.fail_on = "delete_filter"

    with pytest.raises(RuntimeError, match="injected delete_filter failure"):
        policy.stop()

    assert session not in api.sessions
    assert not api.filters
    assert not policy.rules
    assert not policy.is_started


def test_unsupported_filter_key_cannot_be_supplied_by_callers():
    policy, api = manager()
    start(policy)
    before = len(api.calls)

    with pytest.raises(TypeError):
        policy.block_endpoint(
            remote_address="8.8.8.8",
            remote_port=443,
            protocol="TCP",
            direction="outbound",
            ttl_seconds=60,
            reason="test",
            filter_key=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        )

    assert len(api.calls) == before
