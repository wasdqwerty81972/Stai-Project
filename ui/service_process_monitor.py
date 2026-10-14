"""Process-monitor adapter for telemetry owned by the Windows service."""

from __future__ import annotations

from typing import Any


class ServiceProcessMonitor:
    """Expose the authenticated service pipe as the registry-shaped API source."""

    def __init__(self, pipe_client: Any | None = None) -> None:
        if pipe_client is None:
            from cyber_os.protection import windows_pipe_client as pipe_client
        self._pipe = pipe_client
        self._last_event_resync = False

    def snapshot(self) -> dict[str, Any]:
        for attempt in range(2):
            processes: list[dict[str, Any]] = []
            offset = 0
            sequence: int | None = None
            observed_at = None
            health: dict[str, Any] = {}
            total = 0
            while True:
                page = self._pipe.get_process_snapshot_page(
                    offset=offset, limit=250, sequence=sequence, timeout=2.0
                )
                if page["resync_required"]:
                    break
                if sequence is None:
                    sequence = page["sequence"]
                    observed_at = page.get("observed_at")
                    health = page.get("health", {})
                    total = page.get("total", 0)
                elif page["sequence"] != sequence:
                    break
                processes.extend(page["processes"])
                next_offset = page.get("next_offset")
                if next_offset is None:
                    return {
                        "sequence": sequence or 0,
                        "observed_at": observed_at,
                        "processes": processes,
                        "health": {**health, "source": "protection_service"},
                        "total": total,
                    }
                offset = next_offset
            if attempt == 1:
                raise RuntimeError("service process snapshot changed during pagination")
        raise RuntimeError("service process snapshot is unavailable")

    def health(self) -> dict[str, Any]:
        return {**self._pipe.get_process_monitor_status(timeout=2.0), "source": "protection_service"}

    def get_process_details(self, instance_id: str) -> dict[str, Any] | None:
        try:
            return self._pipe.get_process_details(instance_id, timeout=2.0)
        except LookupError:
            return None
        except RuntimeError as exc:
            if str(exc) == "process instance not found":
                return None
            raise

    def get_process(self, instance_id: str) -> dict[str, Any] | None:
        return self.get_process_details(instance_id)

    def connections(self) -> list[dict[str, Any]]:
        return self._pipe.get_process_connections(timeout=2.0)["connections"]

    def set_sampling_profile(self, profile: str) -> None:
        self._pipe.set_process_monitor_profile(profile, timeout=2.0)

    def read_events(self, after_sequence: int) -> dict[str, Any]:
        result = self._pipe.get_process_events(
            after_sequence=after_sequence, limit=500, timeout=2.0
        )
        self._last_event_resync = result["resync_required"]
        return result

    def drain_events(self, after_sequence: int) -> list[dict[str, Any]]:
        result = self.read_events(after_sequence)
        return result["events"]
