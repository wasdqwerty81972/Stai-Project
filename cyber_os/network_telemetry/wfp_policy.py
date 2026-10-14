"""Safe, fakeable policy orchestration for Windows Filtering Platform.

This module deliberately contains no native WFP binding. ``WfpApi`` is the
injection boundary for a future Windows adapter; tests use an in-memory fake,
and the manager never contacts BFE by itself. Runtime policy changes are
disabled unless the caller opts in explicitly.
"""

from __future__ import annotations

import ipaddress
import math
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Protocol as TypingProtocol
from uuid import UUID, uuid4, uuid5


DEFAULT_MAX_TTL_SECONDS = 24 * 60 * 60
MAX_APP_ID_BYTES = 4096
MAX_REASON_CHARS = 256
MIN_TTL_SECONDS = 1.0

# These are stable product-owned keys, not caller-supplied filter identifiers.
PROVIDER_KEY = UUID("5409a032-51c6-4fb7-a184-4962682fcd01")
SUBLAYER_KEY = UUID("eb4cc844-9533-48c5-886a-57a320c33002")
FILTER_NAMESPACE = UUID("761b9c6e-1c43-4d37-a4e5-8930f39b3e03")


class WfpPolicyError(RuntimeError):
    """Base class for policy lifecycle and enforcement errors."""


class PolicyMutationDisabled(WfpPolicyError):
    """Raised when an enforcement mutation was not explicitly enabled."""


class WfpPolicyValidationError(ValueError):
    """Raised when a requested policy is malformed or broader than allowed."""


class WfpOwnershipError(WfpPolicyError):
    """Raised when a filter key does not resolve to the exact owned filter."""


class RuleNotFound(WfpPolicyError):
    """Raised when reversal is requested for a rule this manager never owned."""


class WfpCleanupError(WfpPolicyError):
    """Raised when the dynamic session could not be closed during recovery."""


class Direction(str, Enum):
    OUTBOUND = "outbound"
    INBOUND = "inbound"


class NetworkProtocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"

    @property
    def ip_protocol(self) -> int:
        return 6 if self is NetworkProtocol.TCP else 17


@dataclass(frozen=True)
class WfpFilterSpec:
    """Semantic exact-match filter description passed to the native adapter.

    The adapter maps ``layer`` and ``conditions`` to the matching documented
    FWPM layer and typed FWPM_FILTER_CONDITION values. Endpoint address prefix
    lengths are always /32 or /128; CIDR and wildcard policies are not accepted.
    """

    filter_key: UUID
    provider_key: UUID
    sublayer_key: UUID
    rule_id: str
    layer: str
    action: str
    conditions: tuple[tuple[str, Any], ...]
    expires_at: float
    reason: str

    @property
    def condition_map(self) -> dict[str, Any]:
        return dict(self.conditions)


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    kind: str
    direction: Direction
    protocol: NetworkProtocol
    filter_keys: tuple[UUID, ...]
    expires_at: float
    reason: str


class WfpApi(TypingProtocol):
    """Injected API boundary; implementations must use only their given session.

    All methods either return successfully or raise. ``open_dynamic_session``
    must request ``FWPM_SESSION_FLAG_DYNAMIC``. ``get_filter`` returns the
    complete semantic spec for the exact GUID, or ``None``. No implementation
    is provided here, so importing or constructing this manager cannot touch
    the machine's live BFE state.
    """

    def open_dynamic_session(self, session_key: UUID) -> object: ...

    def close_dynamic_session(self, session: object) -> None: ...

    def begin_transaction(self, session: object) -> None: ...

    def commit_transaction(self, session: object) -> None: ...

    def abort_transaction(self, session: object) -> None: ...

    def add_provider(self, session: object, provider_key: UUID, display_name: str) -> None: ...

    def add_sublayer(
        self, session: object, sublayer_key: UUID, provider_key: UUID, display_name: str
    ) -> None: ...

    def get_filter(self, session: object, filter_key: UUID) -> WfpFilterSpec | None: ...

    def add_filter(self, session: object, filter_spec: WfpFilterSpec) -> None: ...

    def delete_filter(self, session: object, filter_key: UUID) -> None: ...


class WfpPolicyManager:
    """Manage exact, bounded WFP blocks through an injected API adapter.

    ``policy_mutation_enabled`` defaults to false. In that state ``start`` is
    inert and no API method is called. A caller must both opt in and provide a
    started dynamic session before a rule can be installed.
    """

    PROVIDER_KEY = PROVIDER_KEY
    SUBLAYER_KEY = SUBLAYER_KEY

    def __init__(
        self,
        api: WfpApi,
        *,
        policy_mutation_enabled: bool = False,
        clock: Callable[[], float] = time.monotonic,
        max_ttl_seconds: float = DEFAULT_MAX_TTL_SECONDS,
    ) -> None:
        if type(policy_mutation_enabled) is not bool:
            raise ValueError("policy_mutation_enabled must be an explicit boolean")
        if (
            isinstance(max_ttl_seconds, bool)
            or not isinstance(max_ttl_seconds, (int, float))
            or not math.isfinite(max_ttl_seconds)
            or max_ttl_seconds < MIN_TTL_SECONDS
        ):
            raise ValueError("max_ttl_seconds must be finite and at least one second")
        self._api = api
        self._mutation_enabled = policy_mutation_enabled
        self._clock = clock
        self._max_ttl_seconds = float(max_ttl_seconds)
        self._session: object | None = None
        self._started = False
        self._degraded = False
        self._rules: dict[str, tuple[PolicyRule, tuple[WfpFilterSpec, ...]]] = {}
        self._removed_rule_ids: set[str] = set()

    @property
    def session(self) -> object | None:
        return self._session

    @property
    def is_started(self) -> bool:
        return self._started and not self._degraded

    @property
    def is_degraded(self) -> bool:
        return self._degraded

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return tuple(entry[0] for entry in self._rules.values())

    def start(self) -> None:
        if self._started:
            return
        if self._session is not None:
            raise WfpPolicyError(
                "an earlier dynamic session still needs cleanup before restart"
            )
        if not self._mutation_enabled:
            # Explicitly inert in the default mode: even opening a BFE session
            # would make this manager's behavior depend on live system state.
            self._started = True
            return

        session = self._api.open_dynamic_session(uuid4())
        self._session = session
        try:
            self._run_transaction(
                session,
                lambda: (
                    self._api.add_provider(
                        session, self.PROVIDER_KEY, "SVS-Cyber network policy"
                    ),
                    self._api.add_sublayer(
                        session,
                        self.SUBLAYER_KEY,
                        self.PROVIDER_KEY,
                        "SVS-Cyber exact network rules",
                    ),
                ),
            )
        except Exception as exc:
            self._recover_dynamic_session(exc)
            raise
        self._started = True
        self._degraded = False

    def stop(self) -> None:
        session = self._session
        if session is None:
            self._started = False
            return

        primary_error: Exception | None = None
        try:
            specs = tuple(spec for _, group in self._rules.values() for spec in group)
            if specs:
                self._run_transaction(session, lambda: self._delete_exact_filters(session, specs))
        except Exception as exc:
            primary_error = exc

        try:
            self._api.close_dynamic_session(session)
        except Exception as cleanup_error:
            self._started = False
            self._degraded = True
            if primary_error is not None:
                raise WfpCleanupError(
                    "policy rollback failed and the dynamic WFP session could not be closed"
                ) from cleanup_error
            raise WfpCleanupError("the dynamic WFP session could not be closed") from cleanup_error

        self._session = None
        self._rules.clear()
        self._removed_rule_ids.clear()
        self._started = False
        self._degraded = False
        if primary_error is not None:
            raise primary_error

    def block_application(
        self,
        *,
        app_id: bytes,
        protocol: NetworkProtocol | str,
        ttl_seconds: float,
        reason: str,
        direction: Direction | str = Direction.OUTBOUND,
        rule_id: str | UUID | None = None,
    ) -> PolicyRule:
        self._require_mutation_session()
        parsed_app_id = self._validate_app_id(app_id)
        parsed_protocol = self._validate_protocol(protocol)
        parsed_direction = self._validate_direction(direction)
        parsed_ttl = self._validate_ttl(ttl_seconds)
        parsed_reason = self._validate_reason(reason)
        canonical_rule_id = self._validate_rule_id(rule_id)
        expires_at = self._clock() + parsed_ttl
        layers = self._authorization_layers(parsed_direction, None)
        specs = tuple(
            self._make_spec(
                rule_id=canonical_rule_id,
                layer=layer,
                conditions=(("app_id", parsed_app_id), ("protocol", parsed_protocol.ip_protocol)),
                expires_at=expires_at,
                reason=parsed_reason,
            )
            for layer in layers
        )
        rule = PolicyRule(
            rule_id=canonical_rule_id,
            kind="application",
            direction=parsed_direction,
            protocol=parsed_protocol,
            filter_keys=tuple(spec.filter_key for spec in specs),
            expires_at=expires_at,
            reason=parsed_reason,
        )
        self._add_rule(rule, specs)
        return rule

    def block_endpoint(
        self,
        *,
        remote_address: str,
        remote_port: int,
        protocol: NetworkProtocol | str,
        direction: Direction | str,
        ttl_seconds: float,
        reason: str,
        rule_id: str | UUID | None = None,
    ) -> PolicyRule:
        self._require_mutation_session()
        address = self._validate_remote_address(remote_address)
        port = self._validate_port(remote_port)
        parsed_protocol = self._validate_protocol(protocol)
        parsed_direction = self._validate_direction(direction)
        parsed_ttl = self._validate_ttl(ttl_seconds)
        parsed_reason = self._validate_reason(reason)
        canonical_rule_id = self._validate_rule_id(rule_id)
        expires_at = self._clock() + parsed_ttl
        layer = self._authorization_layers(parsed_direction, address.version)[0]
        prefix_length = address.max_prefixlen
        spec = self._make_spec(
            rule_id=canonical_rule_id,
            layer=layer,
            conditions=(
                ("remote_address", address.compressed),
                ("remote_prefix_length", prefix_length),
                ("remote_port", port),
                ("protocol", parsed_protocol.ip_protocol),
            ),
            expires_at=expires_at,
            reason=parsed_reason,
        )
        rule = PolicyRule(
            rule_id=canonical_rule_id,
            kind="endpoint",
            direction=parsed_direction,
            protocol=parsed_protocol,
            filter_keys=(spec.filter_key,),
            expires_at=expires_at,
            reason=parsed_reason,
        )
        self._add_rule(rule, (spec,))
        return rule

    def remove_rule(self, rule_id: str | UUID) -> bool:
        self._require_mutation_session()
        canonical_rule_id = self._validate_rule_id(rule_id)
        entry = self._rules.get(canonical_rule_id)
        if entry is None:
            if canonical_rule_id in self._removed_rule_ids:
                return False
            raise RuleNotFound(f"rule {canonical_rule_id} is not owned by this manager")
        rule, specs = entry
        self._delete_rules_transactionally(((rule, specs),))
        return True

    def expire_due_rules(self) -> tuple[str, ...]:
        self._require_mutation_session()
        now = self._clock()
        due = tuple(
            entry for entry in self._rules.values() if now >= entry[0].expires_at
        )
        if not due:
            return ()
        self._delete_rules_transactionally(due)
        return tuple(rule.rule_id for rule, _ in due)

    def _add_rule(self, rule: PolicyRule, specs: tuple[WfpFilterSpec, ...]) -> None:
        if rule.rule_id in self._rules or rule.rule_id in self._removed_rule_ids:
            raise WfpPolicyValidationError("rule_id has already been used")
        session = self._require_mutation_session()
        try:
            def add_all() -> None:
                for spec in specs:
                    current = self._api.get_filter(session, spec.filter_key)
                    if current is not None:
                        self._assert_exact_owned_filter(current, spec)
                        raise WfpOwnershipError("the deterministic filter key is already present")
                    self._api.add_filter(session, spec)

            self._run_transaction(session, add_all)
        except Exception as exc:
            self._recover_dynamic_session(exc)
            raise
        self._rules[rule.rule_id] = (rule, specs)

    def _delete_rules_transactionally(
        self, entries: tuple[tuple[PolicyRule, tuple[WfpFilterSpec, ...]], ...]
    ) -> None:
        session = self._require_mutation_session()
        specs = tuple(spec for _, group in entries for spec in group)
        try:
            self._run_transaction(session, lambda: self._delete_exact_filters(session, specs))
        except Exception as exc:
            self._recover_dynamic_session(exc)
            raise
        for rule, _ in entries:
            self._rules.pop(rule.rule_id, None)
            self._removed_rule_ids.add(rule.rule_id)

    def _delete_exact_filters(
        self, session: object, specs: tuple[WfpFilterSpec, ...]
    ) -> None:
        for expected in specs:
            current = self._api.get_filter(session, expected.filter_key)
            if current is None:
                continue
            self._assert_exact_owned_filter(current, expected)
            self._api.delete_filter(session, expected.filter_key)

    @staticmethod
    def _assert_exact_owned_filter(
        current: WfpFilterSpec, expected: WfpFilterSpec
    ) -> None:
        if (
            current.filter_key != expected.filter_key
            or current.provider_key != PROVIDER_KEY
            or current.sublayer_key != SUBLAYER_KEY
            or current != expected
        ):
            raise WfpOwnershipError(
                "refusing to modify a filter that does not exactly match the owned rule"
            )

    def _run_transaction(self, session: object, operation: Callable[[], Any]) -> None:
        self._api.begin_transaction(session)
        try:
            operation()
            self._api.commit_transaction(session)
        except Exception:
            try:
                self._api.abort_transaction(session)
            except Exception:
                # The caller closes this dynamic session to force cleanup.
                pass
            raise

    def _recover_dynamic_session(self, cause: Exception) -> None:
        session = self._session
        self._started = False
        if session is None:
            return
        try:
            self._api.close_dynamic_session(session)
        except Exception as cleanup_error:
            self._degraded = True
            raise WfpCleanupError(
                f"WFP operation failed ({cause}) and its dynamic session could not be closed"
            ) from cleanup_error
        self._session = None
        self._rules.clear()
        self._removed_rule_ids.clear()
        self._degraded = False

    def _require_mutation_session(self) -> object:
        if not self._mutation_enabled:
            raise PolicyMutationDisabled("runtime WFP policy mutation is disabled")
        if not self._started or self._session is None or self._degraded:
            raise WfpPolicyError("WFP policy manager is not ready")
        return self._session

    @staticmethod
    def _validate_app_id(value: Any) -> bytes:
        if not isinstance(value, bytes) or not 1 <= len(value) <= MAX_APP_ID_BYTES:
            raise WfpPolicyValidationError("app_id must be a bounded opaque WFP application ID")
        return bytes(value)

    @staticmethod
    def _validate_protocol(value: NetworkProtocol | str) -> NetworkProtocol:
        try:
            return value if isinstance(value, NetworkProtocol) else NetworkProtocol(str(value).upper())
        except ValueError as exc:
            raise WfpPolicyValidationError("only TCP or UDP is supported") from exc

    @staticmethod
    def _validate_direction(value: Direction | str) -> Direction:
        try:
            return value if isinstance(value, Direction) else Direction(str(value).lower())
        except ValueError as exc:
            raise WfpPolicyValidationError("direction must be inbound or outbound") from exc

    def _validate_ttl(self, value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise WfpPolicyValidationError("ttl_seconds must be a finite number")
        ttl = float(value)
        if not math.isfinite(ttl) or not MIN_TTL_SECONDS <= ttl <= self._max_ttl_seconds:
            raise WfpPolicyValidationError(
                f"ttl_seconds must be between {MIN_TTL_SECONDS:g} and "
                f"{self._max_ttl_seconds:g} seconds"
            )
        return ttl

    @staticmethod
    def _validate_reason(value: Any) -> str:
        if not isinstance(value, str):
            raise WfpPolicyValidationError("reason must be text")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise WfpPolicyValidationError("reason is empty, too long, or contains controls")
        reason = value.strip()
        if not reason or len(reason) > MAX_REASON_CHARS:
            raise WfpPolicyValidationError("reason is empty, too long, or contains controls")
        return reason

    @staticmethod
    def _validate_rule_id(value: str | UUID | None) -> str:
        if value is None:
            return str(uuid4())
        try:
            parsed = value if isinstance(value, UUID) else UUID(str(value))
        except (ValueError, TypeError, AttributeError) as exc:
            raise WfpPolicyValidationError("rule_id must be a UUID") from exc
        return str(parsed)

    @staticmethod
    def _validate_port(value: Any) -> int:
        if type(value) is not int or not 1 <= value <= 65535:
            raise WfpPolicyValidationError("remote_port must be an integer from 1 to 65535")
        return value

    @staticmethod
    def _validate_remote_address(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        if not isinstance(value, str) or "/" in value or "*" in value:
            raise WfpPolicyValidationError("remote_address must be one exact IP address")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise WfpPolicyValidationError("remote_address must be one exact IP address") from exc
        if (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
            or address.is_private
            or address.is_reserved
            or address == ipaddress.IPv4Address("255.255.255.255")
        ):
            raise WfpPolicyValidationError(
                "local, reserved, unspecified, multicast, link-local, and broadcast targets are protected"
            )
        return address

    @staticmethod
    def _authorization_layers(direction: Direction, ip_version: int | None) -> tuple[str, ...]:
        suffix = "CONNECT" if direction is Direction.OUTBOUND else "RECV_ACCEPT"
        if ip_version == 4:
            return (f"ALE_AUTH_{suffix}_V4",)
        if ip_version == 6:
            return (f"ALE_AUTH_{suffix}_V6",)
        return (f"ALE_AUTH_{suffix}_V4", f"ALE_AUTH_{suffix}_V6")

    @staticmethod
    def _make_spec(
        *,
        rule_id: str,
        layer: str,
        conditions: tuple[tuple[str, Any], ...],
        expires_at: float,
        reason: str,
    ) -> WfpFilterSpec:
        filter_key = uuid5(FILTER_NAMESPACE, f"{rule_id}:{layer}")
        return WfpFilterSpec(
            filter_key=filter_key,
            provider_key=PROVIDER_KEY,
            sublayer_key=SUBLAYER_KEY,
            rule_id=rule_id,
            layer=layer,
            action="block",
            conditions=conditions,
            expires_at=expires_at,
            reason=reason,
        )
