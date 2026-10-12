"""Atomic quarantine operations with SHA-256 verification."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Optional

from .models import ScanVerdict
from .store import ProtectionStore, QuarantineItem


CHUNK_SIZE = 1024 * 1024
QUARANTINE_SUFFIX = ".stai_quarantine"


@dataclass(slots=True)
class QuarantineResult:
    success: bool
    item: QuarantineItem | None = None
    error: str | None = None


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _digest_stream(stream) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(CHUNK_SIZE):
        digest.update(chunk)
    return digest.hexdigest()


def _make_quarantine_dir(quarantine_root: Path) -> Path:
    quarantine_root.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        try:
            import subprocess
            subprocess.run(
                ["icacls", str(quarantine_root), "/inheritance:r"],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                ["icacls", str(quarantine_root), "/grant:r", f"{os.getlogin()}:(R,W)"],
                check=False,
                capture_output=True,
            )
            subprocess.run(
                ["icacls", str(quarantine_root), "/remove:g", "Users"],
                check=False,
                capture_output=True,
            )
        except Exception:
            pass
    return quarantine_root


def _atomic_move(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    os.replace(src, dst)


def quarantine_file(
    store: ProtectionStore,
    detection_id: str,
    file_path: Path,
    quarantine_root: Path,
    verdict: ScanVerdict,
) -> QuarantineResult:
    source = Path(file_path).resolve()
    if not source.exists() or not source.is_file():
        return QuarantineResult(success=False, error="source file not found or not a regular file")

    try:
        current_hash = _digest_file(source)
    except OSError as e:
        return QuarantineResult(success=False, error=f"cannot read source file: {e}")

    if verdict.sha256 and current_hash != verdict.sha256:
        return QuarantineResult(
            success=False, error=f"hash mismatch: expected {verdict.sha256}, got {current_hash}"
        )

    _make_quarantine_dir(quarantine_root)

    item_id = str(uuid.uuid4())
    quarantined_name = f"{item_id}{QUARANTINE_SUFFIX}"
    quarantined_path = quarantine_root / quarantined_name

    try:
        _atomic_move(source, quarantined_path)
    except OSError as e:
        return QuarantineResult(success=False, error=f"move failed: {e}")

    try:
        post_move_hash = _digest_file(quarantined_path)
    except OSError as e:
        try:
            _atomic_move(quarantined_path, source)
        except OSError:
            pass
        return QuarantineResult(success=False, error=f"post-move verification failed: {e}")

    if post_move_hash != current_hash:
        try:
            _atomic_move(quarantined_path, source)
        except OSError:
            pass
        return QuarantineResult(success=False, error="hash changed during quarantine move")

    item = QuarantineItem(
        item_id=item_id,
        original_path=str(source),
        quarantined_path=str(quarantined_path),
        sha256=current_hash,
        rule_id=verdict.rule_id or "unknown",
        rule_version=verdict.rule_version,
        action_result="moved",
        detection_id=detection_id,
        created_at=datetime.now().isoformat(),
        restored_at=None,
        restore_result=None,
    )

    try:
        with store._transaction() as conn:
            conn.execute(
                """
                INSERT INTO quarantine_items
                (item_id, original_path, quarantined_path, sha256, rule_id, rule_version,
                 action_result, detection_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.item_id,
                    item.original_path,
                    item.quarantined_path,
                    item.sha256,
                    item.rule_id,
                    item.rule_version,
                    item.action_result,
                    item.detection_id,
                    item.created_at,
                ),
            )
    except Exception as e:
        try:
            _atomic_move(quarantined_path, source)
        except OSError:
            pass
        return QuarantineResult(success=False, error=f"database error: {e}")

    return QuarantineResult(success=True, item=item)


def restore_quarantine(
    store: ProtectionStore,
    item_id: str,
    quarantine_root: Path,
    rules: Optional[Any] = None,
) -> QuarantineResult:
    item: Optional[QuarantineItem] = None
    with store._get_conn() as conn:
        cursor = conn.execute("SELECT * FROM quarantine_items WHERE item_id = ?", (item_id,))
        row = cursor.fetchone()
        if not row:
            return QuarantineResult(success=False, error="quarantine item not found")
        if row["restore_result"] is not None:
            return QuarantineResult(success=False, error=f"already {row['restore_result']}")

    quarantined_path = Path(row["quarantined_path"])
    original_path = Path(row["original_path"])

    if not quarantined_path.exists():
        with store._transaction() as conn:
            conn.execute(
                "UPDATE quarantine_items SET restore_result = 'failed' WHERE item_id = ?",
                (item_id,),
            )
        return QuarantineResult(success=False, error="quarantined file missing")

    try:
        current_hash = _digest_file(quarantined_path)
    except OSError as e:
        return QuarantineResult(success=False, error=f"cannot read quarantined file: {e}")

    if current_hash != row["sha256"]:
        with store._transaction() as conn:
            conn.execute(
                "UPDATE quarantine_items SET restore_result = 'refused' WHERE item_id = ?",
                (item_id,),
            )
        return QuarantineResult(success=False, error="quarantined file hash mismatch - possible tampering")

    if rules is not None:
        from .scanner import scan_path
        verdict = scan_path(quarantined_path, rules)
        if verdict.status == "detected" and verdict.action == "block":
            with store._transaction() as conn:
                conn.execute(
                    "UPDATE quarantine_items SET restore_result = 'refused' WHERE item_id = ?",
                    (item_id,),
                )
            return QuarantineResult(
                success=False,
                error=f"restore refused: file still matches block rule {verdict.rule_id}",
            )

    original_path.parent.mkdir(parents=True, exist_ok=True)

    if original_path.exists():
        try:
            existing_hash = _digest_file(original_path)
            if existing_hash == current_hash:
                quarantined_path.unlink(missing_ok=True)
                with store._transaction() as conn:
                    conn.execute(
                        """
                        UPDATE quarantine_items
                        SET restore_result = 'restored', restored_at = ?
                        WHERE item_id = ?
                        """,
                        (datetime.now().isoformat(), item_id),
                    )
                return QuarantineResult(success=True, item=QuarantineItem(
                    item_id=row["item_id"],
                    original_path=row["original_path"],
                    quarantined_path=row["quarantined_path"],
                    sha256=row["sha256"],
                    rule_id=row["rule_id"],
                    rule_version=row["rule_version"],
                    action_result=row["action_result"],
                    detection_id=row["detection_id"],
                    created_at=row["created_at"],
                    restored_at=datetime.now().isoformat(),
                    restore_result="restored",
                ))
            else:
                return QuarantineResult(
                    success=False,
                    error="original location has different file - manual resolution required",
                )
        except OSError:
            pass

    try:
        _atomic_move(quarantined_path, original_path)
    except OSError as e:
        return QuarantineResult(success=False, error=f"restore move failed: {e}")

    try:
        restored_hash = _digest_file(original_path)
    except OSError as e:
        return QuarantineResult(success=False, error=f"post-restore verification failed: {e}")

    if restored_hash != current_hash:
        return QuarantineResult(success=False, error="hash mismatch after restore")

    with store._transaction() as conn:
        conn.execute(
            """
            UPDATE quarantine_items
            SET restore_result = 'restored', restored_at = ?
            WHERE item_id = ?
            """,
            (datetime.now().isoformat(), item_id),
        )

    restored_item = QuarantineItem(
        item_id=row["item_id"],
        original_path=row["original_path"],
        quarantined_path=row["quarantined_path"],
        sha256=row["sha256"],
        rule_id=row["rule_id"],
        rule_version=row["rule_version"],
        action_result=row["action_result"],
        detection_id=row["detection_id"],
        created_at=row["created_at"],
        restored_at=datetime.now().isoformat(),
        restore_result="restored",
    )

    return QuarantineResult(success=True, item=restored_item)


def list_quarantine_items(store: ProtectionStore) -> list[QuarantineItem]:
    items = []
    with store._get_conn() as conn:
        cursor = conn.execute("SELECT * FROM quarantine_items ORDER BY created_at DESC")
        for row in cursor.fetchall():
            items.append(QuarantineItem(
                item_id=row["item_id"],
                original_path=row["original_path"],
                quarantined_path=row["quarantined_path"],
                sha256=row["sha256"],
                rule_id=row["rule_id"],
                rule_version=row["rule_version"],
                action_result=row["action_result"],
                detection_id=row["detection_id"],
                created_at=row["created_at"],
                restored_at=row["restored_at"],
                restore_result=row["restore_result"],
            ))
    return items