"""Bounded analysis-evidence overlay for service-owned process records."""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any, Callable


class ProcessAnalysisState:
    """Adapt the existing analysis worker to either service or local telemetry."""

    def __init__(self, provider_getter: Callable[[], tuple[Any, str, str | None]], limit: int = 4096) -> None:
        self._provider_getter = provider_getter
        self._limit = max(32, int(limit))
        self._base: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._evidence: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._lock = threading.RLock()

    def remember(self, process: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(process, dict):
            return process
        instance_id = process.get("instance_id")
        if not isinstance(instance_id, str) or not instance_id:
            return process
        with self._lock:
            prior = self._base.get(instance_id, {})
            merged = {**prior, **process, **self._evidence.get(instance_id, {})}
            self._base[instance_id] = merged
            self._base.move_to_end(instance_id)
            self._trim()
            return dict(merged)

    def get_process_details(self, instance_id: str) -> dict[str, Any] | None:
        provider, source, _error = self._provider_getter()
        try:
            process = provider.get_process_details(instance_id)
        except Exception:
            if source != "protection_service":
                raise
            process = None
        if process is None:
            with self._lock:
                cached = self._base.get(instance_id)
                return dict(cached) if cached is not None else None
        return self.remember(process)

    def get_process(self, instance_id: str) -> dict[str, Any] | None:
        return self.get_process_details(instance_id)

    def update_process_fields(self, instance_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        provider, source, _error = self._provider_getter()
        if source != "protection_service":
            process = provider.update_process_fields(instance_id, fields)
            if isinstance(process, dict):
                return self.remember(process)
        with self._lock:
            current = self._base.get(instance_id)
            self._evidence[instance_id] = {**self._evidence.get(instance_id, {}), **fields}
            self._evidence.move_to_end(instance_id)
            if current is None:
                return None
            updated = {**current, **fields}
            self._base[instance_id] = updated
            self._base.move_to_end(instance_id)
            self._trim()
            return dict(updated)

    def apply(self, process: dict[str, Any]) -> dict[str, Any]:
        instance_id = process.get("instance_id") if isinstance(process, dict) else None
        if not isinstance(instance_id, str):
            return process
        with self._lock:
            merged = {**process, **self._evidence.get(instance_id, {})}
            self._base[instance_id] = merged
            self._base.move_to_end(instance_id)
            self._trim()
            return dict(merged)

    def _trim(self) -> None:
        while len(self._base) > self._limit:
            self._base.popitem(last=False)
        while len(self._evidence) > self._limit:
            self._evidence.popitem(last=False)
