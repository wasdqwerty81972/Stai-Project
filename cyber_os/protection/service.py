"""Protection service coordinating scanning, quarantine, and filter communication."""

from __future__ import annotations

import hashlib
import logging
import os
import stat
import threading
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator, Literal, Optional

from .models import DetectionRule, RuleSet, ScanVerdict, ThreatIntelEvidence
from .quarantine import QuarantineItem, QuarantineResult, list_quarantine_items, quarantine_file, restore_quarantine
from .scanner import SCANNER_ENGINE_VERSION, scan_path
from .store import DetectionRecord, ProtectionStatus, ProtectionStore, ScanJob, ThreatIntelStore, WindowsSecurityStatus


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
    threat_intel_store: ThreatIntelStore | None = None


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
        self._intel_status_lock = threading.Lock()
        self._intel_status_cache: tuple[float, dict[str, Any]] | None = None

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
        verdict = self._attach_intel_evidence(verdict)
        detection_id: str | None = None

        if verdict.status == "detected" or verdict.intel_evidence is not None:
            detection_id = str(uuid.uuid4())
            file_type = None
            size_bytes = None
            try:
                # Do not bind this to "stat": that shadows the stat module
                # imported at the top of this file and relied on by _iter_files.
                stat_result = path.stat()
                size_bytes = stat_result.st_size
                if path.suffix:
                    file_type = path.suffix.lower()
            except OSError:
                pass

            record = DetectionRecord(
                detection_id=detection_id,
                sha256=verdict.sha256 or "",
                rule_id=verdict.rule_id or "threat-intel-advisory",
                rule_version=verdict.rule_version if verdict.status == "detected" else verdict.intel_evidence.feed_version,
                action=verdict.action,
                confidence="high" if verdict.action == "block" else "low",
                severity="critical" if verdict.action == "block" else verdict.intel_evidence.severity if verdict.intel_evidence else "medium",
                file_type=file_type,
                size_bytes=size_bytes,
                file_path=str(path),
                created_at=datetime.now().isoformat(),
                triage_enqueued=False,
                intel_evidence=verdict.intel_evidence,
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
        verdict = self._attach_intel_evidence(verdict)
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

    def _attach_intel_evidence(self, verdict: ScanVerdict) -> ScanVerdict:
        """Attach exact SHA-256 evidence; P2A intelligence remains advisory."""
        intel = self._config.threat_intel_store
        if intel is None or verdict.sha256 is None:
            return verdict
        try:
            decision = intel.block_decision("sha256", verdict.sha256)
        except Exception:
            LOGGER.exception("threat-intelligence lookup failed; preserving scanner verdict")
            with self._intel_status_lock:
                self._intel_status_cache = None
            return verdict
        record = decision.record
        if record is None:
            return verdict
        evidence = ThreatIntelEvidence(
            indicator_type="sha256",
            indicator_value=record.indicator_value.lower(),
            source=record.source,
            verification=record.verification,
            confidence=record.confidence,
            severity=record.severity,
            feed_version=record.feed_version,
            first_seen=record.first_seen,
            last_seen=record.last_seen,
            freshness=record.freshness(),
            corroborations=record.corroborations,
            block_eligible=decision.block,
            decision_reason=decision.reason[:256],
        )
        # Eligibility is evidence only until signed/staged feed activation.
        return replace(verdict, intel_evidence=evidence)

    def threat_intel_status(self) -> dict[str, Any]:
        """Report local database integrity and eligibility without trust claims."""
        now = time.monotonic()
        with self._intel_status_lock:
            if self._intel_status_cache and now - self._intel_status_cache[0] < 60:
                return dict(self._intel_status_cache[1])
            intel = self._config.threat_intel_store
            if intel is None:
                status = {"state": "unavailable", "integrity_ok": False, "block_eligible_records": 0, "activation": "inactive"}
            else:
                try:
                    integrity = intel.verify_integrity()
                    if not integrity.get("ok"):
                        status = {"state": "degraded", "integrity_ok": False, "block_eligible_records": 0, "activation": "inactive"}
                    else:
                        status = {
                            "state": "advisory",
                            "integrity_ok": True,
                            "block_eligible_records": intel.count_block_eligible_hashes(),
                            "activation": "inactive",
                        }
                except Exception:
                    LOGGER.exception("unable to read threat-intelligence database health")
                    status = {"state": "unavailable", "integrity_ok": False, "block_eligible_records": 0, "activation": "inactive"}
            self._intel_status_cache = (now, status)
            return dict(status)

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
                raise RuntimeError("A scan is already running. Open Scans to view its progress or cancel it before starting another scan.")

            job_id = str(uuid.uuid4())
            configured_roots = (
                self._config.quick_scan_roots
                if scope == "quick" and self._config.quick_scan_roots is not None
                else SCAN_ROOTS_QUICK if scope == "quick" else SCAN_ROOTS_SYSTEM
            )
            roots = self._normalize_scan_roots(configured_roots)
            snapshot = [str(root) for root in roots]
            job = self._config.store.create_scan_job(
                job_id,
                scope,
                root_snapshot=snapshot,
                engine_version=SCANNER_ENGINE_VERSION,
                rules_version=self._config.rules.version,
            )
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

    def get_active_scan(self) -> ScanJob | None:
        """Return the persisted job while its background scan is running."""
        with self._scan_lock:
            job_id = self._current_job_id
            worker = self._scan_thread
            if not job_id or worker is None or not worker.is_alive():
                return None
            return self._config.store.get_scan_job(job_id)

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
        started = time.monotonic()
        files_discovered = 0
        files_scanned = 0
        files_skipped = 0
        detections = 0
        errors = 0
        unknown_verdicts = 0

        def report_error(_error: OSError) -> None:
            nonlocal errors
            errors += 1

        def report_skip() -> None:
            nonlocal files_skipped
            files_skipped += 1

        def persist_progress(
            *,
            state: Literal["pending", "running", "completed", "partial", "cancelled", "failed"] | None = None,
            error_message: str | None = None,
        ) -> None:
            self._config.store.update_scan_job(
                job_id,
                state=state,
                files_total=files_discovered,
                files_scanned=files_scanned,
                files_skipped=files_skipped,
                unknown_verdicts=unknown_verdicts,
                detections=detections,
                errors=errors,
                duration_ms=max(0, round((time.monotonic() - started) * 1000)),
                error_message=error_message,
            )

        try:
            roots = roots if roots is not None else self._normalize_scan_roots(
                SCAN_ROOTS_QUICK if scope == "quick" else SCAN_ROOTS_SYSTEM
            )
            if not roots:
                persist_progress(state="failed", error_message="no enrolled scan roots are available")
                return
            for root in roots:
                if self._cancel_scan.is_set():
                    persist_progress(state="cancelled")
                    return

                for file_path in self._iter_files(root, on_error=report_error, on_skip=report_skip):
                    if self._cancel_scan.is_set():
                        persist_progress(state="cancelled")
                        return
                    files_discovered += 1
                    try:
                        verdict = self.scan_file(file_path)
                    except Exception:
                        # Count AND log: a silently swallowed scan error made a
                        # scan that failed on every file look merely "partial".
                        errors += 1
                        LOGGER.exception("scan failed for %s", file_path)
                    else:
                        files_scanned += 1
                        if verdict.status == "detected":
                            detections += 1
                        elif verdict.status == "unknown":
                            unknown_verdicts += 1
                    if files_discovered % 10 == 0:
                        persist_progress(state="running")

            if self._cancel_scan.is_set():
                final_state = "cancelled"
            elif files_discovered == 0 and errors > 0:
                final_state = "failed"
            elif errors or files_skipped or unknown_verdicts:
                final_state = "partial"
            else:
                final_state = "completed"
            persist_progress(state=final_state)

        except Exception as e:
            persist_progress(state="failed", error_message=str(e))
        finally:
            with self._scan_lock:
                self._current_job_id = None

    def _iter_files(
        self,
        root: Path,
        *,
        on_error: Callable[[OSError], None] | None = None,
        on_skip: Callable[[], None] | None = None,
    ) -> Iterator[Path]:
        """Walk one root without following links and report failures/skips."""
        pending = [Path(root)]
        while pending and not self._cancel_scan.is_set():
            current = pending.pop()
            try:
                current_stat = current.stat(follow_symlinks=False)
            except OSError as exc:
                if on_error is not None:
                    on_error(exc)
                continue
            if getattr(current_stat, "st_file_attributes", 0) & 0x400 or current.is_symlink():
                if on_skip is not None:
                    on_skip()
                continue
            if self._is_under_quarantine(current):
                if on_skip is not None:
                    on_skip()
                continue
            if stat.S_ISREG(current_stat.st_mode):
                yield current
                continue
            if not stat.S_ISDIR(current_stat.st_mode):
                if on_skip is not None:
                    on_skip()
                continue
            try:
                with os.scandir(current) as scan_entries:
                    for entry in scan_entries:
                        if self._cancel_scan.is_set():
                            return
                        path = Path(entry.path)
                        try:
                            entry_stat = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            if on_error is not None:
                                on_error(exc)
                            continue
                        if getattr(entry_stat, "st_file_attributes", 0) & 0x400 or entry.is_symlink():
                            if on_skip is not None:
                                on_skip()
                            continue
                        if self._is_under_quarantine(path):
                            if on_skip is not None:
                                on_skip()
                            continue
                        if stat.S_ISDIR(entry_stat.st_mode):
                            pending.append(path)
                        elif stat.S_ISREG(entry_stat.st_mode):
                            yield path
                        elif on_skip is not None:
                            on_skip()
            except OSError as exc:
                if on_error is not None:
                    on_error(exc)

    def _is_under_quarantine(self, path: Path) -> bool:
        try:
            path.resolve().relative_to(self._config.quarantine_root.resolve())
            return True
        except ValueError:
            return False

    def quarantine_detection(self, detection_id: str) -> QuarantineResult:
        """Quarantine a file by detection ID."""
        # Look the detection up directly. A paged list_threats() scan silently
        # failed to find any detection outside the first page, so older
        # detections became permanently unquarantinable.
        detection = self._config.store.get_detection(detection_id)

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
        # Both states default to "unknown". A caller that has not actually
        # probed the service must never be handed a "running" claim it did
        # not verify -- reporting protection that was never checked is worse
        # than reporting nothing. ProtectionStore.get_status already defaults
        # to "unknown"; this layer previously overrode it with "running".
        service_state: Literal["running", "stopped", "error", "unknown"] = "unknown",
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
