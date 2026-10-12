"""Protection service coordinating scanning, quarantine, and filter communication."""

from __future__ import annotations

import hashlib
import logging
import os
import stat
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator, Literal, Optional

from .models import DetectionRule, RuleSet, ScanProfile, ScanVerdict
from .quarantine import QuarantineItem, QuarantineResult, list_quarantine_items, quarantine_file, restore_quarantine
from .scanner import scan_path
from .store import DetectionRecord, ProtectionStatus, ProtectionStore, ScanJob, WindowsSecurityStatus
from .windows_profile import KnownFolderResolver, KNOWN_FOLDER_IDS


SCAN_ROOTS_SYSTEM = [Path("C:\\")]
LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ProtectionConfig:
    quarantine_root: Path
    rules: RuleSet
    store: ProtectionStore
    yara_timeout_seconds: int = 5
    profile_resolver: Any | None = None


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
        self._profile_resolver = self._config.profile_resolver or KnownFolderResolver()

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
        """Scan a single file and record detection if found."""
        verdict, _detection_id = self.scan_file_for_filter(path)
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

    def refresh_scan_profile(self, owner_sid: str, token_handle: object) -> ScanProfile:
        """Resolve all enrolled known folders, then atomically publish them."""
        roots = self._profile_resolver.resolve(token_handle)
        if tuple(folder_id for folder_id, _path in roots) != KNOWN_FOLDER_IDS:
            raise RuntimeError("known-folder resolver returned an incomplete profile")
        return self._config.store.replace_scan_profile(
            owner_sid,
            roots,
            datetime.now().astimezone().isoformat(),
        )

    def start_scan(
        self,
        scope: Literal["quick", "system"],
        *,
        roots: tuple[tuple[str, str], ...] | None = None,
        source: Literal["interactive", "schedule"] = "interactive",
    ) -> ScanJob:
        """Start a background scan job."""
        if scope == "quick" and roots is None:
            raise RuntimeError("Quick Scan requires a successfully resolved user profile")
        if scope == "quick" and roots is not None:
            if tuple(folder_id for folder_id, _path in roots) != KNOWN_FOLDER_IDS:
                raise RuntimeError("Quick Scan roots must come from the enrolled user profile")
        with self._scan_lock:
            if self._scan_thread and self._scan_thread.is_alive():
                raise RuntimeError("scan already in progress")

            job_id = str(uuid.uuid4())
            job = self._config.store.create_scan_job_with_roots(
                job_id,
                scope,
                roots or (),
                source=source,
            )
            self._config.store.update_scan_job(job_id, state="running")

            self._cancel_scan.clear()
            self._current_job_id = job_id
            self._scan_thread = threading.Thread(
                target=self._run_scan,
                args=(job_id, scope),
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

    def _run_scan(self, job_id: str, scope: Literal["quick", "system"]) -> None:
        try:
            if scope == "quick":
                root_specs = self._config.store.get_scan_job_roots(job_id)
            else:
                root_specs = tuple((f"system-{index}", str(root)) for index, root in enumerate(SCAN_ROOTS_SYSTEM))

            accessible_roots: list[tuple[str, Path]] = []
            errors = 0
            for folder_id, raw_root in root_specs:
                root = Path(raw_root)
                try:
                    usable = root.exists() and root.is_dir()
                except OSError:
                    usable = False
                if usable:
                    accessible_roots.append((folder_id, root))
                    self._config.store.update_scan_job_root(job_id, folder_id, "pending")
                else:
                    errors += 1
                    self._config.store.update_scan_job_root(
                        job_id,
                        folder_id,
                        "skipped",
                        error="scan folder is missing or inaccessible",
                    )

            if not accessible_roots:
                self._config.store.update_scan_job(
                    job_id,
                    state="failed",
                    errors=errors,
                    error_message="no usable scan roots; profile folders are inaccessible",
                )
                return

            # Count total files first (for progress)
            total_files = 0
            for _folder_id, root in accessible_roots:
                try:
                    for _ in self._iter_files(root):
                        total_files += 1
                except OSError:
                    pass

            self._config.store.update_scan_job(job_id, files_total=total_files)

            files_scanned = 0
            detections = 0

            for folder_id, root in accessible_roots:
                if self._cancel_scan.is_set():
                    self._config.store.update_scan_job(job_id, state="cancelled")
                    return

                self._config.store.update_scan_job_root(job_id, folder_id, "scanning")
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
                    self._config.store.update_scan_job_root(
                        job_id, folder_id, "skipped", error="scan folder became inaccessible"
                    )
                else:
                    self._config.store.update_scan_job_root(job_id, folder_id, "scanned")

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
        def is_reparse_point(path: Path) -> bool:
            try:
                details = path.lstat()
            except OSError:
                return True
            return path.is_symlink() or bool(getattr(details, "st_file_attributes", 0) & 0x400)

        def on_walk_error(error: OSError) -> None:
            LOGGER.debug("skipping inaccessible scan path %s", error.filename or "unknown")

        try:
            for current, directories, files in os.walk(root, topdown=True, followlinks=False, onerror=on_walk_error):
                if self._cancel_scan.is_set():
                    return
                current_path = Path(current)
                directories[:] = [
                    name for name in directories
                    if not is_reparse_point(current_path / name)
                    and not self._is_under_quarantine(current_path / name)
                ]
                for name in files:
                    entry = current_path / name
                    if self._cancel_scan.is_set():
                        return
                    if is_reparse_point(entry) or self._is_under_quarantine(entry):
                        continue
                    if entry.is_file():
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


