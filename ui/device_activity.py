"""Read-only process and network telemetry with bounded executable analysis.

Entropy is a review signal, never proof of malware. Only authenticated high
confidence database matches can produce a known-threat classification.
"""

from __future__ import annotations

import copy
import math
import os
import socket
import stat
import threading
import time
from collections import Counter, OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from cyber_os.protection.models import RuleSet
from cyber_os.protection.rule_package import InvalidRulePackage, RulePackage, rule_set_fingerprint
from cyber_os.protection.scanner import scan_path
from ui.device_process_identity import process_identity, resolve_connection_owner


_ROOT = Path(__file__).resolve().parents[1]
_RESOURCES = _ROOT / "cyber_os" / "protection" / "resources"
_SIGNED_RULE_CANDIDATES = _ROOT / "windows_protection" / "installer" / "rules"
_MAX_SAMPLE_BYTES = 256 * 1024
_MAX_SCAN_BYTES = 64 * 1024 * 1024
_MAX_CACHE_ENTRIES = 2048
_MAX_PENDING_ANALYSES = 32
_SNAPSHOT_REFRESH_SECONDS = 10


def shannon_entropy(data: bytes) -> float | None:
    """Shannon byte entropy in bits/byte; empty files have no measured score."""
    if not data:
        return None
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in Counter(data).values())


def _assessment(classification: str, reason: str, **values: Any) -> dict[str, Any]:
    return {"classification": classification, "entropy": None, "reason": reason,
        "rule_id": None, "rule_version": None, "sha256": None, "sampled_bytes": 0, **values}


def _metadata(path: Path) -> tuple[int, int, int, int, int]:
    entry = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(entry.st_mode) or getattr(entry, "st_file_attributes", 0) & 0x400:
        raise OSError("Executable is not a regular file or is a reparse point")
    return (entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns, entry.st_ctime_ns)


def merge_protection_service_rules(
    snapshot: dict[str, Any], service_status: dict[str, Any] | None
) -> dict[str, Any]:
    """Use authenticated service rule metadata when user-mode files are ACL-protected."""
    if not isinstance(service_status, dict):
        return snapshot
    version = service_status.get("rules_version")
    trusted = service_status.get("rules_trusted")
    if trusted is False or not isinstance(version, str) or not version or version == "unknown":
        return snapshot
    count = service_status.get("rule_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        count = None
    service_fingerprint = service_status.get("rules_fingerprint")
    database = snapshot.get("database") if isinstance(snapshot.get("database"), dict) else {}
    exact_rules_match = (
        isinstance(service_fingerprint, str)
        and database.get("available") is True
        and database.get("fingerprint") == service_fingerprint
    )
    result = copy.deepcopy(snapshot)
    result["database"] = {
        "available": True,
        "version": version,
        "rule_count": count,
        "sha256_rule_count": service_status.get("sha256_rule_count"),
        "yara_rule_count": service_status.get("yara_rule_count"),
        "demo": version == "svs-eicar-demo-1",
        "analysis_available": exact_rules_match and database.get("analysis_available") is True,
        "active_in_protection_service": True,
        "fingerprint": service_fingerprint,
        "coverage": (
            database.get("coverage")
            if exact_rules_match
            else "The protection service reports this signed package as active; process-level rule matching is unavailable until this collector can verify the same rule contents."
        ),
    }
    if not exact_rules_match:
        reason = "The active signed package is loaded by the protection service, but this process collector cannot verify its rule contents; process-level rule matching is unavailable"
        result["errors"] = [
            error
            for error in result.get("errors", [])
            if not str(error).startswith("Threat database unavailable:")
        ]
        result["errors"].append(
            "Process-level rule matching unavailable: active service rules are not readable or verifiable by this collector"
        )
        for process in result.get("processes", []):
            assessment = process.get("assessment")
            if isinstance(assessment, dict):
                assessment.update(
                    classification="unavailable",
                    reason=reason,
                    rule_id=None,
                    rule_version=None,
                )
    return result


class DeviceActivityCollector:
    """Cache snapshots for two seconds; analyze at most two executables at once."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._refresh_lock = threading.Lock()
        self._refreshing = False
        self._snapshot: dict[str, Any] | None = None
        self._snapshot_time = 0.0
        self._rules: RuleSet | None = None
        self._database: dict[str, Any] = {}
        self._database_errors: list[str] = []
        self._protection_status: dict[str, Any] | None = None
        self._rule_analysis_unavailable_reason = (
            "Threat database unavailable; entropy alone cannot establish a threat"
        )
        self._rules_checked_at = float("-inf")
        self._rule_generation = 0
        self._rule_fingerprint: Any = None
        self._analysis: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()
        self._analysis_retry_at: dict[tuple[Any, ...], float] = {}
        self._pending: dict[tuple[Any, ...], Future] = {}
        self._executor: ThreadPoolExecutor | None = None
        self._cpu_samples: dict[tuple[int, Any], tuple[float, float]] = {}
        self._network_sample: tuple[float, int, int] | None = None

    def set_protection_status(self, status: dict[str, Any] | None) -> None:
        """Cache authenticated service metadata and reload rules if its identity changes."""
        current = status if isinstance(status, dict) else None
        fingerprint = current.get("rules_fingerprint") if current and current.get("rules_trusted") is True else None
        with self._lock:
            previous = self._protection_status or {}
            if previous.get("rules_fingerprint") != fingerprint:
                self._rules_checked_at = float("-inf")
                self._snapshot_time = 0.0
            self._protection_status = copy.deepcopy(current)

    def _load_database(self, now: float) -> None:
        if now - self._rules_checked_at < 30:
            return
        self._rules_checked_at = now
        roots = []
        configured = os.environ.get("STAI_PROTECTION_DATA_DIR")
        if configured:
            roots.append(Path(configured))
        roots.extend((Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "STAI" / "Protection",
            _ROOT / ".stai" / "protection-service"))
        selected = None
        for root in roots:
            manifest = root / "rules" / "manifest.json"
            signature = root / "rules" / "manifest.sig"
            try:
                present = manifest.exists() or signature.exists()
            except OSError:
                # Do not disguise an inaccessible installed database as a
                # successful scan against the bundled demonstration rules.
                present = True
            if present:
                selected = (manifest, signature, False)
                break
        if selected is None:
            selected = (_RESOURCES / "demo-manifest.json", _RESOURCES / "demo-manifest.sig", True)
        manifest, signature, demo = selected
        self._database_errors = []
        self._rule_analysis_unavailable_reason = (
            "Threat database unavailable; entropy alone cannot establish a threat"
        )
        service_status = self._protection_status or {}
        service_fingerprint = service_status.get("rules_fingerprint")
        try:
            public_key = (_RESOURCES / "trusted-rules.pub").read_bytes()
            rules = RulePackage.load(manifest, signature, public_key)
            # The installer may have copied the embedded demo into its data root.
            demo = demo or rules.version == "svs-eicar-demo-1"
        except (OSError, InvalidRulePackage) as exc:
            rules = None
            # ProgramData rules are ACL-protected for the LocalSystem service.
            # The user-mode collector can safely reuse its embedded demo only
            # when the service reports the exact same validated rule contents.
            if service_status.get("rules_trusted") is True and isinstance(service_fingerprint, str):
                try:
                    embedded = RulePackage.load(
                        _RESOURCES / "demo-manifest.json",
                        _RESOURCES / "demo-manifest.sig",
                        (_RESOURCES / "trusted-rules.pub").read_bytes(),
                    )
                    if rule_set_fingerprint(embedded) == service_fingerprint:
                        rules = embedded
                        demo = embedded.version == "svs-eicar-demo-1"
                except (OSError, InvalidRulePackage):
                    pass
                if rules is None:
                    # Installed rules are locked to SYSTEM. The repository's
                    # signed YARA packages can still be used when the running
                    # service authenticates the exact same version and
                    # fingerprint. The pipe metadata is the authority for which
                    # package is active; a merely valid bundled package is not
                    # enough to claim a process match.
                    try:
                        from cryptography.hazmat.primitives import serialization

                        for candidate_manifest in sorted(_SIGNED_RULE_CANDIDATES.glob("*/manifest.json")):
                            candidate_root = candidate_manifest.parent
                            candidate_key_path = candidate_root / "trusted-rules.pub.pem"
                            candidate_signature = candidate_root / "manifest.sig"
                            try:
                                candidate_public_key = serialization.load_pem_public_key(
                                    candidate_key_path.read_bytes()
                                ).public_bytes(
                                    serialization.Encoding.Raw,
                                    serialization.PublicFormat.Raw,
                                )
                                candidate_rules = RulePackage.load(
                                    candidate_manifest,
                                    candidate_signature,
                                    candidate_public_key,
                                )
                            except (OSError, ValueError, InvalidRulePackage):
                                continue
                            if (
                                candidate_rules.version == service_status.get("rules_version")
                                and rule_set_fingerprint(candidate_rules) == service_fingerprint
                            ):
                                rules = candidate_rules
                                demo = False
                                break
                    except (ImportError, OSError, ValueError):
                        pass
            if rules is None:
                self._rules = None
                version = service_status.get("rules_version")
                rule_count = service_status.get("rule_count")
                if (
                    service_status.get("rules_trusted") is True
                    and isinstance(service_fingerprint, str)
                    and isinstance(version, str)
                    and isinstance(rule_count, int)
                    and not isinstance(rule_count, bool)
                    and rule_count >= 0
                ):
                    fingerprint = (version, service_fingerprint)
                    self._database = {
                        "available": True,
                        "version": version,
                        "rule_count": rule_count,
                        "sha256_rule_count": service_status.get("sha256_rule_count", 0),
                        "yara_rule_count": service_status.get("yara_rule_count", 0),
                        "demo": version == "svs-eicar-demo-1",
                        "analysis_available": False,
                        "fingerprint": service_fingerprint,
                        "coverage": "The signed package is loaded by the protection service, but its protected rule contents are not readable by this process collector.",
                    }
                    self._rule_analysis_unavailable_reason = (
                        "Authenticated rules are loaded by the protection service, but this process collector cannot read their exact contents; process-level rule matching is unavailable"
                    )
                    self._database_errors.append(
                        "Process-level rule matching unavailable: authenticated rule contents are protected by the service"
                    )
                else:
                    fingerprint = None
                    self._database = {"available": False, "version": None, "rule_count": 0,
                        "demo": False, "analysis_available": False,
                        "coverage": "No authenticated threat database available"}
                    self._database_errors.append(f"Threat database unavailable: {exc}")
        if rules is not None:
            fingerprint = (rules.version, rules.rules)
            package_fingerprint = rule_set_fingerprint(rules)
            self._rules = rules
            self._database = {
                "available": True,
                "version": rules.version,
                "rule_count": len(rules.rules),
                "sha256_rule_count": sum(1 for rule in rules.rules if rule.kind == "sha256"),
                "yara_rule_count": sum(1 for rule in rules.rules if rule.kind == "yara"),
                "demo": demo,
                "analysis_available": True,
                "fingerprint": package_fingerprint,
                "coverage": "EICAR test file only; demo database" if demo else "Authenticated SHA-256 and YARA rules; no match is not proof of safety",
            }
        if fingerprint != self._rule_fingerprint:
            self._rule_generation += 1
            self._rule_fingerprint = fingerprint
            self._analysis.clear()
            self._analysis_retry_at.clear()

    @staticmethod
    def _analyze_executable(
        path: Path,
        rules: RuleSet | None,
        unavailable_reason: str = "Threat database unavailable; entropy alone cannot establish a threat",
    ) -> dict[str, Any]:
        measured: dict[str, Any] = {}
        try:
            before = _metadata(path)
            with path.open("rb") as stream:
                if _metadata(path) != before:
                    raise OSError("Executable changed before entropy sampling")
                sample = stream.read(_MAX_SAMPLE_BYTES)
                entry = os.fstat(stream.fileno())
                handle_metadata = (entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns, entry.st_ctime_ns)
                if handle_metadata != before:
                    raise OSError("Executable changed during entropy sampling")
            if _metadata(path) != before:
                raise OSError("Executable changed during entropy sampling")
            measured = {"entropy": shannon_entropy(sample), "sampled_bytes": len(sample)}
            if rules is None:
                if measured["entropy"] is not None and measured["entropy"] >= 7.2:
                    return _assessment("needs_review", f"High sampled entropy; {unavailable_reason}. Packing or compression may explain this score; entropy alone does not establish malicious behavior", **measured)
                return _assessment("unavailable", unavailable_reason, **measured)
            verdict = scan_path(path, rules, max_file_bytes=_MAX_SCAN_BYTES,
                file_timeout_seconds=3.0, yara_timeout_seconds=1)
            if _metadata(path) != before:
                return _assessment("unavailable", "Executable changed during analysis")
            measured.update(rule_id=verdict.rule_id, rule_version=verdict.rule_version, sha256=verdict.sha256)
            if verdict.status == "unknown":
                return _assessment("unavailable", verdict.reason, **measured)
            if verdict.action == "block" and verdict.status == "detected":
                return _assessment("known_threat", verdict.reason, **measured)
            if verdict.status == "detected":
                return _assessment("needs_review", verdict.reason, **measured)
            if measured["entropy"] is not None and measured["entropy"] >= 7.2:
                return _assessment("needs_review", "High sampled entropy may indicate packing or compression; it does not establish malicious behavior. No signed rule matched", **measured)
            return _assessment("no_known_match", "No signed rule matched; this is not proof that the process is safe", **measured)
        except (OSError, ValueError) as exc:
            return _assessment("unavailable", f"Executable analysis unavailable: {exc}")

    def _executable_assessment(self, executable: str | None) -> dict[str, Any]:
        if not executable:
            return _assessment("unavailable", "Executable path inaccessible or not supplied by the operating system")
        path = Path(executable)
        try:
            key = (str(path).casefold(), *_metadata(path), self._rule_generation)
        except OSError as exc:
            return _assessment("unavailable", f"Executable metadata unavailable: {exc}")
        if key in self._analysis:
            if (self._analysis[key].get("classification") == "unavailable"
                    and time.monotonic() >= self._analysis_retry_at.get(key, float("inf"))):
                del self._analysis[key]
                self._analysis_retry_at.pop(key, None)
            else:
                self._analysis.move_to_end(key)
                return dict(self._analysis[key])
        if key not in self._pending and len(self._pending) < _MAX_PENDING_ANALYSES:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="device-executable")
            self._pending[key] = self._executor.submit(
                self._analyze_executable, path, self._rules, self._rule_analysis_unavailable_reason
            )
        return _assessment("pending", "Executable entropy and authenticated database analysis are queued")

    def _collect_finished(self) -> None:
        for key, future in list(self._pending.items()):
            if not future.done():
                continue
            del self._pending[key]
            if key[-1] != self._rule_generation:
                continue
            try:
                assessment = future.result()
            except Exception as exc:
                assessment = _assessment("unavailable", f"Executable analysis failed: {exc}")
            self._analysis[key] = assessment
            if assessment.get("classification") == "unavailable":
                self._analysis_retry_at[key] = time.monotonic() + 30
            else:
                self._analysis_retry_at.pop(key, None)
        while len(self._analysis) > _MAX_CACHE_ENTRIES:
            expired_key, _ = self._analysis.popitem(last=False)
            self._analysis_retry_at.pop(expired_key, None)

    def cached_snapshot(self) -> dict[str, Any]:
        """Return immediately; collect the slow Windows process list in background."""
        now = time.monotonic()
        with self._refresh_lock:
            if (not self._refreshing and
                    (self._snapshot is None or now - self._snapshot_time >= _SNAPSHOT_REFRESH_SECONDS)):
                self._refreshing = True
                threading.Thread(target=self._refresh_snapshot, name="device-activity-refresh", daemon=True).start()

            snapshot = self._snapshot
            if snapshot is None:
                snapshot = {
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "processes": [], "connections": [],
                    "network": {"download_bytes_sec": None, "upload_bytes_sec": None,
                        "bytes_received": None, "bytes_sent": None},
                    "database": {"available": False, "version": None, "rule_count": 0,
                        "demo": False, "coverage": "Collecting process and network inventory"},
                    "errors": [], "cpu_count": psutil.cpu_count() or 1,
                }
            result = copy.deepcopy(snapshot)
            result["collecting"] = self._refreshing
            return result

    def _refresh_snapshot(self) -> None:
        try:
            self.snapshot()
        except Exception as exc:
            with self._lock:
                if self._snapshot is None:
                    self._snapshot = {
                        "observed_at": datetime.now(timezone.utc).isoformat(),
                        "processes": [], "connections": [],
                        "network": {"download_bytes_sec": None, "upload_bytes_sec": None,
                            "bytes_received": None, "bytes_sent": None},
                        "database": {"available": False, "version": None, "rule_count": 0,
                            "demo": False, "coverage": "Device inventory unavailable"},
                        "errors": [f"Device inventory unavailable: {exc}"], "cpu_count": psutil.cpu_count() or 1,
                    }
                    self._snapshot_time = time.monotonic()
        finally:
            with self._refresh_lock:
                self._refreshing = False

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            now = time.monotonic()
            if self._snapshot is not None and now - self._snapshot_time < 2:
                return copy.deepcopy(self._snapshot)
            self._load_database(now)
            self._collect_finished()
            errors = list(self._database_errors)
            cpu_count = psutil.cpu_count() or 1
            rows = []
            samples = {}
            inventory = {}
            attrs = ["pid", "name", "username", "exe", "status", "memory_info", "create_time"]
            try:
                for process in psutil.process_iter(attrs=attrs, ad_value=None):
                    info = process.info
                    pid = process.pid
                    visibility = []
                    for field in ("name", "username", "exe", "memory_info", "status", "create_time"):
                        if info.get(field) is None:
                            visibility.append(f"{field} inaccessible or unavailable")
                    cpu_percent = None
                    identity = (pid, info.get("create_time"))
                    stable_identity = process_identity(pid, info.get("create_time"))
                    try:
                        usage = process.cpu_times()
                        total = usage.user + usage.system
                        if stable_identity is not None:
                            samples[identity] = (now, total)
                        previous = self._cpu_samples.get(identity) if stable_identity is not None else None
                        if previous and now > previous[0]:
                            cpu_percent = min(100.0, max(0.0, (total - previous[1]) / (now - previous[0]) * 100 / cpu_count))
                    except (psutil.Error, OSError, AttributeError):
                        visibility.append("CPU usage inaccessible or unavailable")
                    memory = info.get("memory_info")
                    name = info.get("name") or f"Process {pid}"
                    inventory[pid] = {"name": name, "create_time": info.get("create_time")}
                    rows.append({"pid": pid, "name": name, "username": info.get("username"),
                        "create_time": info.get("create_time"), "process_identity": stable_identity,
                        "exe": info.get("exe"), "cpu_percent": cpu_percent,
                        "memory_bytes": memory.rss if memory is not None else None,
                        "status": info.get("status") or "unknown", "visibility_errors": visibility,
                        "assessment": self._executable_assessment(info.get("exe"))})
            except (psutil.Error, OSError) as exc:
                errors.append(f"Process enumeration incomplete: {exc}")
            self._cpu_samples = samples
            connections = []
            verified_owners = {}
            try:
                for connection in psutil.net_connections(kind="inet"):
                    if connection.pid not in verified_owners:
                        verified_owners[connection.pid] = resolve_connection_owner(connection.pid, inventory)
                    connections.append({"pid": connection.pid,
                        **verified_owners[connection.pid],
                        "family": "IPv6" if connection.family == socket.AF_INET6 else "IPv4",
                        "protocol": "TCP" if connection.type == socket.SOCK_STREAM else "UDP",
                        "local_address": self._endpoint(connection.laddr),
                        "remote_address": self._endpoint(connection.raddr), "state": connection.status})
            except (psutil.Error, OSError) as exc:
                errors.append(f"Network connections unavailable: {exc}")
            network = {"download_bytes_sec": None, "upload_bytes_sec": None,
                "bytes_received": None, "bytes_sent": None}
            try:
                counters = psutil.net_io_counters()
                if counters is None:
                    raise OSError("No network interface counters available")
                received, sent = counters.bytes_recv, counters.bytes_sent
                network.update(bytes_received=received, bytes_sent=sent)
                previous = self._network_sample
                if previous and now > previous[0] and received >= previous[1] and sent >= previous[2]:
                    network.update(download_bytes_sec=(received - previous[1]) / (now - previous[0]),
                        upload_bytes_sec=(sent - previous[2]) / (now - previous[0]))
                self._network_sample = (now, received, sent)
            except (psutil.Error, OSError) as exc:
                errors.append(f"Network traffic unavailable: {exc}")
            rows.sort(key=lambda row: row["pid"])
            self._snapshot = {"observed_at": datetime.now(timezone.utc).isoformat(),
                "processes": rows, "connections": connections, "network": network,
                "database": dict(self._database), "errors": errors, "cpu_count": cpu_count}
            self._snapshot_time = time.monotonic()
            return copy.deepcopy(self._snapshot)

    @staticmethod
    def _endpoint(address: Any) -> str:
        if not address:
            return ""
        host, port = address[0], address[1]
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


_collector: DeviceActivityCollector | None = None
_collector_lock = threading.Lock()


def get_device_activity(protection_status: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return current telemetry without any import-time workers or collection."""
    global _collector
    with _collector_lock:
        if _collector is None:
            _collector = DeviceActivityCollector()
        collector = _collector
    collector.set_protection_status(protection_status)
    return merge_protection_service_rules(collector.cached_snapshot(), protection_status)
