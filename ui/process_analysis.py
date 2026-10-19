"""Asynchronous executable entropy triage and automatic rule-scanner handoff."""

from __future__ import annotations

import os
import queue
import stat
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable

from ui.process_entropy import executable_entropy


class ProcessAnalysisWorker:
    """Analyze new process images off the metrics loop and scan high entropy files."""

    def __init__(
        self,
        registry_getter: Callable[[], Any],
        scan_executable: Callable[[str], dict[str, Any]],
        *,
        threshold: float = 7.2,
        sample_bytes: int = 256 * 1024,
        queue_limit: int = 512,
    ) -> None:
        if not 0.0 <= float(threshold) <= 8.0:
            raise ValueError("Entropy threshold must be between 0 and 8 bits per byte")
        self._registry_getter = registry_getter
        self._scan_executable = scan_executable
        self.threshold = float(threshold)
        self.sample_bytes = max(1, int(sample_bytes))
        self._queue: queue.Queue[str] = queue.Queue(maxsize=max(1, queue_limit))
        self._pending: set[str] = set()
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._seen_limit = max(1024, queue_limit * 8)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def enqueue(self, process: dict[str, Any]) -> bool:
        instance_id = process.get("instance_id") if isinstance(process, dict) else None
        if not isinstance(instance_id, str) or not instance_id:
            return False
        with self._lock:
            if instance_id in self._seen:
                self._seen.move_to_end(instance_id)
                return True
            self._seen[instance_id] = None
            while len(self._seen) > self._seen_limit:
                self._seen.popitem(last=False)
            try:
                self._queue.put_nowait(instance_id)
            except queue.Full:
                self._seen.pop(instance_id, None)
                registry = self._registry_getter()
                try:
                    registry.update_process_fields(instance_id, {
                        "entropy_state": "queue_full",
                        "auto_scan_status": "not_queued",
                    })
                except Exception:
                    pass
                return False
            self._pending.add(instance_id)
        return True

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="svs-process-analysis", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)
        self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                instance_id = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                self.analyze(instance_id)
            except Exception as exc:
                try:
                    self._registry_getter().update_process_fields(instance_id, {
                        "entropy_state": "unavailable",
                        "entropy_error": str(exc),
                        "auto_scan_status": "failed",
                    })
                except Exception:
                    pass
            finally:
                with self._lock:
                    self._pending.discard(instance_id)
                self._queue.task_done()

    def analyze(self, instance_id: str) -> dict[str, Any] | None:
        registry = self._registry_getter()
        process = registry.get_process_details(instance_id)
        if process is None:
            return None
        raw_path = process.get("exe")
        if not isinstance(raw_path, str) or not raw_path:
            return registry.update_process_fields(instance_id, {
                "entropy_score": None,
                "entropy_state": "unavailable",
                "entropy_source": "executable file",
                "auto_scan_status": "not_triggered",
            })
        try:
            original = Path(raw_path)
            entry = original.stat(follow_symlinks=False)
            if not stat.S_ISREG(entry.st_mode) or getattr(entry, "st_file_attributes", 0) & 0x400:
                raise OSError("Executable is not a regular file")
            target = original.resolve(strict=True)
            score = executable_entropy(target, sample_bytes=self.sample_bytes)
        except (OSError, ValueError) as exc:
            return registry.update_process_fields(instance_id, {
                "entropy_score": None,
                "entropy_state": "unavailable",
                "entropy_source": "executable file",
                "entropy_error": str(exc),
                "auto_scan_status": "not_triggered",
            })

        high_entropy = score >= self.threshold
        result = registry.update_process_fields(instance_id, {
            "entropy_score": score,
            "entropy_state": "available",
            "entropy_source": "sampled executable file bytes",
            "entropy_threshold": self.threshold,
            "auto_scan_status": "queued" if high_entropy else "not_triggered",
        })
        if not high_entropy:
            return result

        registry.update_process_fields(instance_id, {"auto_scan_status": "scanning"})
        try:
            scan = self._scan_executable(instance_id)
        except Exception as exc:
            detail = getattr(exc, "detail", None)
            registry.update_process_fields(instance_id, {
                "auto_scan_status": "failed",
                "scan_error": str(detail or exc),
            })
            return registry.get_process(instance_id)
        return registry.update_process_fields(instance_id, {
            "auto_scan_status": "completed",
            "scan_status": scan.get("status"),
            "scan_action": scan.get("action"),
            "scan_rule_id": scan.get("rule_id"),
            "scan_sha256": scan.get("sha256"),
            "scan_quarantine": scan.get("quarantine"),
            "scan_error": None,
        })


def configured_entropy_threshold() -> float:
    value = os.getenv("SVS_PROCESS_ENTROPY_SCAN_THRESHOLD", "7.2")
    try:
        threshold = float(value)
    except ValueError as exc:
        raise ValueError("SVS_PROCESS_ENTROPY_SCAN_THRESHOLD must be a number from 0 to 8") from exc
    if not 0.0 <= threshold <= 8.0:
        raise ValueError("SVS_PROCESS_ENTROPY_SCAN_THRESHOLD must be between 0 and 8")
    return threshold
