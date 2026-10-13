"""Bounded, metadata-only Windows network telemetry for the local service.

Socket snapshots are not packet capture. They can miss short-lived activity,
do not provide reliable direction or per-process byte counts, and do not expose
traffic payloads. The response keeps those coverage limits explicit.
"""

from __future__ import annotations

import hashlib
import json
import socket
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Mapping


class PsutilNetworkProvider:
    """Small adapter around psutil, imported only when the collector is used."""

    def __init__(self) -> None:
        try:
            import psutil
        except ImportError as exc:
            raise RuntimeError("psutil is unavailable") from exc
        self._psutil = psutil

    def connections(self) -> list[Any]:
        return self._psutil.net_connections(kind="inet")

    def interface_counters(self) -> Mapping[str, Mapping[str, int]]:
        counters = self._psutil.net_io_counters(pernic=True) or {}
        return {
            name: {
                "bytes_recv": int(value.bytes_recv),
                "bytes_sent": int(value.bytes_sent),
            }
            for name, value in counters.items()
        }

    def interfaces(self) -> list[dict[str, Any]]:
        addresses = self._psutil.net_if_addrs() or {}
        stats = self._psutil.net_if_stats() or {}
        result: list[dict[str, Any]] = []
        for name in sorted(set(addresses) | set(stats)):
            address_values = []
            for address in addresses.get(name, ()):
                raw = getattr(address, "address", None)
                if not raw:
                    continue
                address_values.append({
                    "address": str(raw).split("%", 1)[0],
                    "family": _family_name(getattr(address, "family", None)),
                })
            interface_stats = stats.get(name)
            result.append({
                "name": str(name),
                "is_up": bool(interface_stats.isup) if interface_stats else None,
                "addresses": address_values,
            })
        return result

    def process_identity(self, pid: int) -> dict[str, Any]:
        process = self._psutil.Process(pid)
        with process.oneshot():
            created = process.create_time()
            return {
                "name": process.name(),
                "executable_path": process.exe() or None,
                "create_time": float(created) if created is not None else None,
            }


def _family_name(family: Any) -> str:
    if family in (socket.AF_INET, "ipv4", "AF_INET"):
        return "ipv4"
    if family in (socket.AF_INET6, "ipv6", "AF_INET6"):
        return "ipv6"
    return "unknown"


def _endpoint(value: Any) -> tuple[str | None, int | None]:
    if value is None:
        return None, None
    address = getattr(value, "ip", None)
    port = getattr(value, "port", None)
    if address is None and isinstance(value, (tuple, list)) and len(value) >= 2:
        address, port = value[0], value[1]
    if address is None:
        return None, None
    try:
        normalized_port = int(port) if port is not None else None
    except (TypeError, ValueError):
        normalized_port = None
    return str(address).split("%", 1)[0], normalized_port


class NetworkTelemetryCollector:
    """Collect current sockets and interface counters with bounded state."""

    def __init__(
        self,
        *,
        provider: Any | None = None,
        clock: Callable[[], datetime] | None = None,
        max_connections: int = 5000,
    ) -> None:
        self._provider = provider
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_connections = max(1, min(int(max_connections), 20_000))
        self._lock = threading.Lock()
        self._active: dict[str, str] = {}
        self._previous_counters: dict[str, dict[str, int]] | None = None
        self._previous_counter_time: datetime | None = None

    def snapshot(self) -> dict[str, Any]:
        """Return real telemetry or an explicit unavailable response."""
        with self._lock:
            observed_at = self._clock().astimezone(timezone.utc)
            try:
                provider = self._get_provider()
            except Exception as exc:
                return self._unavailable(observed_at, "provider", exc)
            try:
                raw_connections = provider.connections()
            except Exception as exc:
                return self._unavailable(observed_at, "connections", exc)

            errors: list[str] = []
            degraded = False
            if raw_connections is None:
                return self._unavailable(
                    observed_at,
                    "connections",
                    RuntimeError("connection provider returned no result"),
                )

            try:
                counters = self._normalize_counters(provider.interface_counters())
                throughput = self._throughput(counters, observed_at)
            except Exception as exc:
                counters = None
                throughput = {
                    "download_bytes_per_second": None,
                    "upload_bytes_per_second": None,
                }
                errors.append(f"interface counters unavailable ({type(exc).__name__})")
                degraded = True

            try:
                interfaces = provider.interfaces()
                if interfaces is None:
                    raise RuntimeError("interface provider returned no result")
                interfaces = list(interfaces)
            except Exception as exc:
                interfaces = None
                errors.append(f"interface inventory unavailable ({type(exc).__name__})")
                degraded = True

            connection_rows = list(raw_connections)
            truncated = len(connection_rows) > self._max_connections
            if truncated:
                connection_rows = connection_rows[: self._max_connections]
                errors.append("connection snapshot exceeded the configured row limit")
                degraded = True

            current: dict[str, str] = {}
            process_cache: dict[int, dict[str, Any] | None] = {}
            process_failures: set[int] = set()
            normalized: list[dict[str, Any]] = []
            for row in connection_rows:
                protocol = self._protocol(row)
                if protocol is None:
                    continue
                pid = getattr(row, "pid", None)
                if not isinstance(pid, int) or pid <= 0:
                    pid = None
                process = None
                if pid is not None:
                    if pid not in process_cache:
                        try:
                            process_cache[pid] = provider.process_identity(pid)
                        except Exception:
                            process_cache[pid] = None
                            process_failures.add(pid)
                    process = process_cache[pid]
                if process is not None and not isinstance(process, Mapping):
                    process = None
                    if pid is not None:
                        process_failures.add(pid)

                local_address, local_port = _endpoint(getattr(row, "laddr", None))
                remote_address, remote_port = _endpoint(getattr(row, "raddr", None))
                if local_address is None:
                    continue
                created = process.get("create_time") if process else None
                process_identity = (
                    f"{pid}:{float(created):.6f}"
                    if pid is not None and isinstance(created, (int, float))
                    else None
                )
                identity = {
                    "pid": pid,
                    "process_identity": process_identity,
                    "protocol": protocol,
                    "family": _family_name(getattr(row, "family", None)),
                    "local_address": local_address,
                    "local_port": local_port,
                    "remote_address": remote_address,
                    "remote_port": remote_port,
                }
                identity_json = json.dumps(identity, sort_keys=True, separators=(",", ":"))
                connection_id = hashlib.sha256(identity_json.encode("utf-8")).hexdigest()[:24]
                previous_first_seen = self._active.get(connection_id)
                first_seen = previous_first_seen or observed_at.isoformat()
                state = str(getattr(row, "status", "") or "") if protocol == "tcp" else "bound"
                item = {
                    "connection_id": connection_id,
                    **identity,
                    "process_name": process.get("name") if process else None,
                    "executable_path": process.get("executable_path") if process else None,
                    "state": state,
                    "direction": "unknown",
                    "first_seen": first_seen,
                    "last_seen": observed_at.isoformat(),
                    "activity_source": "active_socket_snapshot",
                }
                current[connection_id] = first_seen
                normalized.append(item)

            new_connections = [
                {
                    "event_id": hashlib.sha256(
                        f"{connection['connection_id']}:{observed_at.isoformat()}".encode("utf-8")
                    ).hexdigest()[:24],
                    "timestamp": observed_at.isoformat(),
                    "event_type": "connection_first_observed",
                    "connection": connection,
                }
                for connection in normalized
                if connection["connection_id"] not in self._active
            ]
            self._active = current

            if process_failures:
                errors.append(f"process metadata unavailable for {len(process_failures)} process(es)")
                degraded = True
            return {
                "schema_version": 1,
                "state": "degraded" if degraded else "active",
                "observed_at": observed_at.isoformat(),
                "source": "psutil Windows socket and interface snapshots",
                "coverage": {
                    "connections": "active_socket_snapshot",
                    "process_attribution": "best_effort_pid_and_creation_time",
                    "direction": "unknown_from_snapshot",
                    "payload_capture": "not_collected",
                    "per_process_bytes": "unavailable",
                    "short_lived_connections": "may_be_missed_between_snapshots",
                    "dns_over_https_and_quic_domains": "not_visible_from_socket_snapshot",
                },
                "connections": normalized,
                "new_connections": new_connections,
                "interfaces": interfaces,
                "interface_counters": counters,
                "throughput": throughput,
                "truncated": truncated,
                "errors": errors,
            }

    def _get_provider(self) -> Any:
        if self._provider is None:
            self._provider = PsutilNetworkProvider()
        return self._provider

    @staticmethod
    def _protocol(row: Any) -> str | None:
        kind = str(getattr(row, "kind", "") or "").casefold()
        if kind.startswith("tcp"):
            return "tcp"
        if kind.startswith("udp"):
            return "udp"
        socket_type = getattr(row, "type", None)
        if socket_type == socket.SOCK_STREAM:
            return "tcp"
        if socket_type == socket.SOCK_DGRAM:
            return "udp"
        return None

    @staticmethod
    def _normalize_counters(values: Mapping[str, Mapping[str, int]]) -> dict[str, dict[str, int]]:
        if not isinstance(values, Mapping):
            raise TypeError("interface counters must be a mapping")
        result: dict[str, dict[str, int]] = {}
        for name, counters in values.items():
            if not isinstance(counters, Mapping):
                continue
            received, sent = counters.get("bytes_recv"), counters.get("bytes_sent")
            if isinstance(received, int) and isinstance(sent, int) and received >= 0 and sent >= 0:
                result[str(name)] = {"bytes_recv": received, "bytes_sent": sent}
        return result

    def _throughput(
        self,
        counters: dict[str, dict[str, int]],
        observed_at: datetime,
    ) -> dict[str, int | None]:
        result: dict[str, int | None] = {
            "download_bytes_per_second": None,
            "upload_bytes_per_second": None,
        }
        if self._previous_counters is not None and self._previous_counter_time is not None:
            elapsed = (observed_at - self._previous_counter_time).total_seconds()
            common_names = set(counters) & set(self._previous_counters)
            if elapsed > 0 and common_names:
                received_delta = 0
                sent_delta = 0
                counters_valid = True
                for name in common_names:
                    previous = self._previous_counters[name]
                    current = counters[name]
                    if current["bytes_recv"] < previous["bytes_recv"] or current["bytes_sent"] < previous["bytes_sent"]:
                        counters_valid = False
                        break
                    received_delta += current["bytes_recv"] - previous["bytes_recv"]
                    sent_delta += current["bytes_sent"] - previous["bytes_sent"]
                if counters_valid:
                    result["download_bytes_per_second"] = round(received_delta / elapsed)
                    result["upload_bytes_per_second"] = round(sent_delta / elapsed)
        self._previous_counters = counters
        self._previous_counter_time = observed_at
        return result

    @staticmethod
    def _unavailable(observed_at: datetime, source: str, error: Exception) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "state": "unavailable",
            "observed_at": observed_at.isoformat(),
            "source": "psutil Windows socket and interface snapshots",
            "coverage": {
                "connections": "unavailable",
                "process_attribution": "unavailable",
                "direction": "unknown_from_snapshot",
                "payload_capture": "not_collected",
                "per_process_bytes": "unavailable",
                "short_lived_connections": "may_be_missed_between_snapshots",
                "dns_over_https_and_quic_domains": "not_visible_from_socket_snapshot",
            },
            "connections": None,
            "new_connections": [],
            "interfaces": None,
            "interface_counters": None,
            "throughput": {
                "download_bytes_per_second": None,
                "upload_bytes_per_second": None,
            },
            "truncated": False,
            "errors": [f"{source} enumeration unavailable ({type(error).__name__})"],
        }
