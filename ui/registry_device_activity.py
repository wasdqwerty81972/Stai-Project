"""Dashboard projection of the startup process monitor and its analysis evidence."""

from __future__ import annotations

import copy
import threading
from datetime import datetime, timezone
from typing import Any, Callable

import psutil


def _empty_network() -> dict[str, Any]:
    return {"download_bytes_sec": None, "upload_bytes_sec": None,
            "bytes_received": None, "bytes_sent": None}


def _endpoint(host: Any, port: Any) -> str:
    if not host:
        return ""
    if port is None:
        return str(host)
    return f"[{host}]:{port}" if ":" in str(host) else f"{host}:{port}"


class RegistryDeviceActivityCollector:
    """Warm one shared projection at startup; UI reads never enumerate or scan."""

    def __init__(self, provider_getter: Callable, apply_evidence: Callable,
                 rule_metadata_getter: Callable, *, interval: float = 5.0) -> None:
        self._provider_getter = provider_getter
        self._apply_evidence = apply_evidence
        self._rule_metadata_getter = rule_metadata_getter
        self._interval = max(1.0, interval)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self.ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._status: dict[str, Any] = {}
        self._snapshot: dict[str, Any] = {
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "processes": [], "connections": [], "network": _empty_network(),
            "database": {"available": False, "analysis_available": False, "demo": False,
                         "version": None, "rule_count": None, "coverage": "Collecting device inventory"},
            "errors": [], "cpu_count": psutil.cpu_count() or 1,
        }

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.ready.clear()
        self._thread = threading.Thread(target=self._run, name="device-activity-cache", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=3)

    def _run(self) -> None:
        while not self._stop.is_set():
            self.refresh()
            self._stop.wait(self._interval)

    def set_protection_status(self, status: dict[str, Any] | None) -> None:
        if isinstance(status, dict):
            with self._lock:
                self._status = copy.deepcopy(status)

    @property
    def rule_generation(self) -> Any:
        with self._lock:
            return (self._status.get("rules_fingerprint"), self._status.get("rules_version"),
                    self._status.get("rules_trusted"))

    @staticmethod
    def _assessment(process: dict[str, Any], database: dict[str, Any]) -> dict[str, Any]:
        score = process.get("entropy_score")
        classification, reason = "pending", "Executable analysis is queued in the background"
        current_rules = database["analysis_available"] and process.get("scan_rule_version") == database["version"]
        scan_status = process.get("scan_status")
        if current_rules and scan_status == "detected":
            classification = "known_threat" if process.get("scan_action") == "block" else "needs_review"
            reason = "Authenticated protection service rule matched this executable"
        elif current_rules and scan_status == "clean":
            classification, reason = "no_known_match", "No authenticated rule matched; this is not proof of safety"
        elif process.get("entropy_state") in {"unavailable", "queue_full"} or process.get("auto_scan_status") == "failed":
            classification, reason = "unavailable", str(process.get("scan_error") or process.get("entropy_error") or "Executable analysis is unavailable")
        elif not database["analysis_available"] or scan_status == "unknown":
            classification, reason = "unavailable", "Authenticated process rule matching is unavailable"
        if score is not None and score >= process.get("entropy_threshold", 7.2) and classification in {"no_known_match", "unavailable"}:
            classification, reason = "needs_review", "High sampled file entropy may indicate packing or compression; entropy alone does not establish malware"
        return {"classification": classification, "reason": reason, "entropy": score,
                "rule_id": process.get("scan_rule_id") if current_rules else None,
                "rule_version": process.get("scan_rule_version") if current_rules else None,
                "sha256": process.get("scan_sha256"),
                "sampled_bytes": process.get("entropy_sampled_bytes", 0)}

    def refresh(self) -> None:
        try:
            errors = []
            try:
                self.set_protection_status(self._rule_metadata_getter())
            except Exception as exc:
                # Keep inventory usable but do not retain stale trust after a
                # failed service lookup.
                self.set_protection_status({})
                errors.append(f"Rule metadata unavailable: {exc}")
            provider, source, source_error = self._provider_getter()
            snapshot = provider.snapshot()
            connections = provider.connections()
            network_snapshot = provider.network_snapshot() if hasattr(provider, "network_snapshot") else {}
            with self._lock:
                status = dict(self._status)
            trusted = status.get("rules_trusted") is True and source == "protection_service"
            database = {"available": trusted, "analysis_available": trusted,
                        "active_in_protection_service": trusted, "version": status.get("rules_version"),
                        "fingerprint": status.get("rules_fingerprint"), "rule_count": status.get("rule_count"),
                        "sha256_rule_count": status.get("sha256_rule_count"),
                        "yara_rule_count": status.get("yara_rule_count"),
                        "demo": status.get("rules_version") == "svs-eicar-demo-1",
                        "coverage": "Authenticated service rule matches; no match is not proof of safety" if trusted else "Authenticated rule matching unavailable"}
            rows = []
            for raw in snapshot.get("processes", []):
                process = self._apply_evidence(raw)
                rows.append({**process, "process_identity": process.get("instance_id"),
                             "username": process.get("username"), "exe": process.get("exe"),
                             "cpu_percent": process.get("cpu_percent"), "memory_bytes": process.get("memory_bytes"),
                             "status": process.get("status", "unknown"),
                             "assessment": self._assessment(process, database)})
            sockets = [{**connection, "process_identity": connection.get("instance_id"),
                        "local_address": _endpoint(connection.get("local_address"), connection.get("local_port")),
                        "remote_address": _endpoint(connection.get("remote_address"), connection.get("remote_port"))}
                       for connection in connections]
            if source_error:
                errors.append(str(source_error))
            if snapshot.get("health", {}).get("last_error"):
                errors.append(str(snapshot["health"]["last_error"]))
            errors.extend(network_snapshot.get("errors", []))
            result = {"observed_at": snapshot.get("observed_at") or datetime.now(timezone.utc).isoformat(),
                      "processes": rows, "connections": sockets,
                      "network": network_snapshot.get("network", _empty_network()),
                      "database": database, "errors": errors, "cpu_count": psutil.cpu_count() or 1,
                      "source": source, "stale": False}
            with self._lock:
                self._snapshot = result
        except Exception as exc:
            with self._lock:
                self._snapshot = {**self._snapshot, "stale": True,
                                  "errors": [f"Device inventory refresh failed: {exc}"]}
        finally:
            self.ready.set()

    def cached_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {**copy.deepcopy(self._snapshot), "collecting": not self.ready.is_set()}
