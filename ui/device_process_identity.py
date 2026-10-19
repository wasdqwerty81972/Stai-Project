"""Conservative process identities for non-atomic user-mode socket snapshots."""

from __future__ import annotations

import math
from typing import Any, Callable

import psutil


def process_identity(pid: int, create_time: float | None) -> str | None:
    """Use PID plus exact creation time; a PID alone cannot identify a process."""
    if isinstance(create_time, bool) or not isinstance(create_time, (int, float)):
        return None
    created = float(create_time)
    if not math.isfinite(created) or created < 0:
        return None
    return f"{pid}:{created.hex()}"


def resolve_connection_owner(
    pid: int | None,
    inventory: dict[int, dict[str, Any]],
    *,
    process_factory: Callable[[int], Any] | None = None,
) -> dict[str, Any]:
    """Validate ownership against a fresh creation-time read, without trusting reuse.

    This verifies agreement across snapshots, not an atomic kernel event. A
    process can exit immediately after the verification read.
    """
    unknown = {"process_name": "Unknown owner", "process_create_time": None,
        "process_identity": None, "ownership_status": "unmapped"}
    if pid is None or pid not in inventory:
        return unknown
    entry = inventory[pid]
    expected_time = entry.get("create_time")
    identity = process_identity(pid, expected_time)
    if identity is None:
        return {**unknown, "ownership_status": "unavailable"}
    try:
        current_time = (process_factory or psutil.Process)(pid).create_time()
    except (psutil.Error, OSError):
        return {**unknown, "ownership_status": "unavailable"}
    if process_identity(pid, current_time) is None:
        return {**unknown, "ownership_status": "unavailable"}
    if current_time != expected_time:
        return {**unknown, "ownership_status": "pid_reused"}
    return {"process_name": entry.get("name") or f"Process {pid}",
        "process_create_time": expected_time, "process_identity": identity,
        "ownership_status": "verified_snapshot"}
