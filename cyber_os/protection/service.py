"""Protection service coordinating scanning, quarantine, and filter communication."""

from __future__ import annotations

import hashlib
import logging
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Literal, Optional

from .models import DetectionRule, RuleSet, ScanVerdict
from .quarantine import QuarantineItem, QuarantineResult, list_quarantine_items, quarantine_file, restore_quarantine
from .scanner import scan_path
from .store import DetectionRecord, ProtectionStatus, ProtectionStore, ScanJob, WindowsSecurityStatus


SCAN_ROOTS_QUICK = [
    Path.home() / "Downloads",
    Path.home() / "Desktop",
    Path(Path.home(), "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
]

SCAN_ROOTS_SYSTEM = [Path("C:\\")]
LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ProtectionConfig:
    quarantine_root: Path
    rules: RuleSet
    store: ProtectionStore
    yara_timeout_seconds: int = 5
    quick_scan_roots: list[Path] | None = None


class ScanScope:
    QUICK = "quick"
    SYSTEM = "system"


class ProtectionService:
    """
    High-level protection service coordinating all protection operations.

    This service is designed to be instantiated once and shared across
    API handlers, Tauri commands, and the filter client.
    """

    def __init__(
        self,
        config: ProtectionConfig,
        *,
        on_detection: Callable[[str], Any] | None = None,
    ) -> None:
        self._config = config
        self._on_detection = on_detection
        self._scan_thread: Optional[threading.Thread] = None
        self._cancel_scan = threading.Event()
        self._scan_lock = threading.Lock()
        self._current_job_id: Optional[str] = None

    @property
    def rules(self) -> RuleSet:
        return self._config.rules

    @property
    def store(self) -> ProtectionStore:
        return self._config.store

    @property
    def quarantine_root(self) -> Path:
        return self._config.quarantine_root

    def scan_file(self, path: Path) -> ScanVerdict:
        """Scan a file and immediately quarantine signed high-confidence blocks."""
        verdict, detection_id = self.scan_file_for_filter(path)
        if (
            verdict.status == "detected"
            and verdict.action == "block"
            and detection_id is not None
        ):
            result = self.quarantine_scanned_detection(detection_id, Path(path), verdict)
            if not result.success:
                LOGGER.warning(
                    "high-confidence detection remains flagged but quarantine failed (%s)",
                    result.error or "unknown error",
                )
        return verdict

    def scan_file_for_filter(self, path: Path) -> tuple[ScanVerdict, str | None]:
        """Scan and return the durable detection ID for filter correlation."""
        verdict = scan_path(path, self._config.rules, yara_timeout_seconds=self._config.yara_timeout_seconds)
        detection_id: str | None = None

        if verdict.status == "detected":
            detection_id = str(uuid.uuid4())
            file_type = None
            size_bytes = None
            try:
                stat = path.stat()
                size_bytes = stat.st_size
                if path.suffix:
                    file_type = path.suffix.lower()
            except OSError:
                pass

            record = DetectionRecord(
                detection_id=detection_id,
                sha256=verdict.sha256 or "",
                rule_id=verdict.rule_id or "unknown",
                rule_version=verdict.rule_version,
                action=verdict.action,
                confidence="high" if verdict.action == "block" else "low",
                severity="critical" if verdict.action == "block" else "medium",
                file_type=file_type,
                size_bytes=size_bytes,
                file_path=str(path),
                created_at=datetime.now().isoformat(),
                triage_enqueued=False,
            )
            self._config.store.record_detection(record)
            if self._on_detection is not None:
                try:
                    self._on_detection(detection_id)
                except Exception:
                    # Level 2 is advisory and must never affect the Level 1 verdict.
                    LOGGER.exception("failed to enqueue protection detection for triage")

        return verdict, detection_id

    def scan_file_for_sensor(self, path: Path) -> tuple[ScanVerdict, str]:
        """Scan a transient sensor path without sending the file to Level 2 AI."""
        target = Path(path)
        verdict = scan_path(
            target,
            self._config.rules,
            yara_timeout_seconds=self._config.yara_timeout_seconds,
        )
        if verdict.status == "clean":
            return verdict, "clean"
        if verdict.status != "detected" or verdict.action != "block" or not verdict.sha256:
            return verdict, "unknown"

        detection_id = str(uuid.uuid4())
        file_type = target.suffix.lower() if target.suffix else None
        try:
            stat_result = target.stat()
            size_bytes = stat_result.st_size
        except OSError:
            size_bytes = None
        self._config.store.record_detection(DetectionRecord(
            detection_id=detection_id,
            sha256=verdict.sha256,
            rule_id=verdict.rule_id or "unknown",
            rule_version=verdict.rule_version,
            action="block",
            confidence="high",
            severity="critical",
            file_type=file_type,
            size_bytes=size_bytes,
            file_path=str(target),
            created_at=datetime.now().isoformat(),
            triage_enqueued=False,
        ))
        quarantined = self.quarantine_scanned_detection(detection_id, target, verdict)
        if quarantined.success:
            return verdict, "contained"
        LOGGER.warning("sensor-triggered detection remains flagged; quarantine failed")
        return verdict, "failed"

    def quarantine_scanned_detection(
        self,
        detection_id: str,
        file_path: Path,
        verdict: ScanVerdict,
    ) -> QuarantineResult:
        """Quarantine an existing high-confidence block detection without rescanning."""
        if verdict.status != "detected" or verdict.action != "block" or not verdict.sha256:
            return QuarantineResult(success=False, error="verdict is not a verified block detection")
        detection = self._config.store.get_detection(detection_id)
        if (
            detection is None
            or detection.action != "block"
            or detection.confidence != "high"
            or not detection.file_path
            or detection.sha256 != verdict.sha256
            or detection.rule_id != verdict.rule_id
            or detection.rule_version != verdict.rule_version
        ):
            return QuarantineResult(success=False, error="high-confidence block detection not found")
        source = Path(file_path)
        try:
            if Path(detection.file_path).resolve() != source.resolve():
                return QuarantineResult(success=False, error="detection path does not match scanned file")
        except OSError:
            return QuarantineResult(success=False, error="scanned file path is unavailable")
        return quarantine_file(
            self._config.store,
            detection_id,
            source,
            self._config.quarantine_root,
            verdict,
        )

    def start_scan(self, scope: Literal["quick", "system"]) -> ScanJob:
        """Start a background scan job."""
        with self._scan_lock:
            if self._scan_thread and self._scan_thread.is_alive():
                raise RuntimeError("scan already in progress")

            job_id = str(uuid.uuid4())
            configured_roots = (
                self._config.quick_scan_roots
                if scope == "quick" and self._config.quick_scan_roots is not None
                else SCAN_ROOTS_QUICK if scope == "quick" else SCAN_ROOTS_SYSTEM
            )
            roots = self._normalize_scan_roots(configured_roots)
            snapshot = [str(root) for root in roots]
            job = self._config.store.create_scan_job(job_id, scope, root_snapshot=snapshot)
            self._config.store.update_scan_job(job_id, state="running")

            self._cancel_scan.clear()
            self._current_job_id = job_id
            self._scan_thread = threading.Thread(
                target=self._run_scan,
                args=(job_id, scope, roots),
                daemon=True,
            )
            self._scan_thread.start()

            return job

    def cancel_scan(self, job_id: str) -> bool:
        """Cancel a running scan job."""
        with self._scan_lock:
            if self._current_job_id != job_id:
                return False
            if not self._scan_thread or not self._scan_thread.is_alive():
                return False

            self._cancel_scan.set()
            return True

    @staticmethod
    def _normalize_scan_roots(roots: list[Path]) -> list[Path]:
        normalized: list[Path] = []
        seen: set[str] = set()
        for candidate in roots:
            root = Path(candidate).expanduser().resolve(strict=False)
            text = str(root)
            if text.startswith("\\\\"):
                continue
            key = str(root).casefold() if root.drive else str(root)
            if key not in seen:
                normalized.append(root)
                seen.add(key)
        return normalized

    def _run_scan(
        self,
        job_id: str,
        scope: Literal["quick", "system"],
        roots: list[Path] | None = None,
    ) -> None:
        try:
            roots = roots if roots is not None else self._normalize_scan_roots(
                SCAN_ROOTS_QUICK if scope == "quick" else SCAN_ROOTS_SYSTEM
            )
            accessible_roots = [r for r in roots if r.exists()]

            if not accessible_roots:
                self._config.store.update_scan_job(
                    job_id, state="failed", error_message="no accessible scan roots"
                )
                return

            # Count total files first (for progress)
            total_files = 0
            for root in accessible_roots:
                try:
                    for _ in self._iter_files(root):
                        total_files += 1
                except OSError:
                    pass

            self._config.store.update_scan_job(job_id, files_total=total_files)

            files_scanned = 0
            detections = 0
            errors = 0

            for root in accessible_roots:
                if self._cancel_scan.is_set():
                    self._config.store.update_scan_job(job_id, state="cancelled")
                    return

                try:
                    for file_path in self._iter_files(root):
                        if self._cancel_scan.is_set():
                            self._config.store.update_scan_job(job_id, state="cancelled")
                            return

                        try:
                            verdict = self.scan_file(file_path)
                            files_scanned += 1
                            if verdict.status == "detected":
                                detections += 1
                        except Exception:
                            errors += 1
                            files_scanned += 1

                        # Update progress every 10 files
                        if files_scanned % 10 == 0:
                            self._config.store.update_scan_job(
                                job_id, files_scanned=files_scanned, detections=detections, errors=errors
                            )
                except OSError:
                    errors += 1

            final_state = "cancelled" if self._cancel_scan.is_set() else "completed"
            self._config.store.update_scan_job(
                job_id,
                state=final_state,
                files_scanned=files_scanned,
                detections=detections,
                errors=errors,
            )

        except Exception as e:
            self._config.store.update_scan_job(job_id, state="failed", error_message=str(e))
        finally:
            with self._scan_lock:
                self._current_job_id = None

    def _iter_files(self, root: Path) -> Iterator[Path]:
        """Iterate files under root, skipping reparse points and quarantine dir."""
        try:
            for entry in root.rglob("*"):
                if self._cancel_scan.is_set():
                    return
                if not entry.is_file():
                    continue
                # Skip quarantine directory
                if self._is_under_quarantine(entry):
                    continue
                # Skip reparse points (symlinks, junctions)
                try:
                    st = entry.stat()
                    if hasattr(st, "st_file_attributes") and st.st_file_attributes & 0x400:
                        continue
                except OSError:
                    continue
                yield entry
        except OSError:
            return

    def _is_under_quarantine(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self._config.quarantine_root.resolve())
            return True
        except ValueError:
            return False

    def quarantine_detection(self, detection_id: str) -> QuarantineResult:
        """Quarantine a file by detection ID."""
        # Find the detection record
        detections = self._config.store.list_threats(limit=1000)
        detection = next((d for d in detections if d.detection_id == detection_id), None)

        if not detection:
            return QuarantineResult(success=False, error="detection not found")

        if not detection.file_path:
            return QuarantineResult(success=False, error="detection has no file path")

        # Re-scan to get current verdict
        verdict = scan_path(
            Path(detection.file_path),
            self._config.rules,
            yara_timeout_seconds=self._config.yara_timeout_seconds,
        )
        if verdict.status != "detected":
            return QuarantineResult(success=False, error="file no longer matches detection")

        return quarantine_file(
            self._config.store,
            detection_id,
            Path(detection.file_path),
            self._config.quarantine_root,
            verdict,
        )

    def restore_quarantine(self, item_id: str) -> QuarantineResult:
        """Restore a quarantined file."""
        return restore_quarantine(
            self._config.store,
            item_id,
            self._config.quarantine_root,
            self._config.rules,
        )

    def list_quarantine(self) -> list[QuarantineItem]:
        return list_quarantine_items(self._config.store)

    def get_status(
        self,
        driver_state: Literal["running", "stopped", "error", "unknown"] = "unknown",
        service_state: Literal["running", "stopped", "error", "unknown"] = "running",
        windows_security: Optional[WindowsSecurityStatus] = None,
        sensor_coverage: Optional[dict[str, Any]] = None,
        last_error: Optional[str] = None,
    ) -> ProtectionStatus:
        return self._config.store.get_status(
            driver_state=driver_state,
            service_state=service_state,
            rules_version=self._config.rules.version,
            windows_security=windows_security,
            sensor_coverage=sensor_coverage,
            last_error=last_error,
        )


from datetime import datetime
