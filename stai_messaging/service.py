"""Application-lifecycle owner for optional communications adapters."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from collections import deque
from pathlib import Path
from typing import Any

from .adapters.discord import DiscordChannelAdapter
from .adapters.telegram import TelegramChannelAdapter
from .gateway import CredentialStore, Gateway, IdentityStore


class AdapterManager:
    PLATFORMS = ("discord", "telegram")

    def __init__(self, chat_client: Any, data_dir: str | os.PathLike[str]) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.identities = IdentityStore(self.data_dir / "communications_pairings.json")
        self.credentials = CredentialStore()
        self.gateway = Gateway(chat_client, self.identities)
        self._settings_path = self.data_dir / "communications_settings.json"
        self._settings = self._load_settings()
        self._delivery_path = self.data_dir / "communications_deliveries.json"
        self._deliveries = self._load_deliveries()
        self._queue: asyncio.Queue | None = None
        self._worker_task: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queued_event_ids: set[str] = set()
        self._adapters: dict[tuple[str, str], Any] = {}
        self._statuses: dict[tuple[str, str], dict[str, str]] = {}
        self._lock = asyncio.Lock()
        self._retry_task: asyncio.Task | None = None
        self._stopping = False

    def _load_settings(self) -> dict[str, Any]:
        defaults = {
            "enabled": {platform: False for platform in self.PLATFORMS},
            "notifications": {"enabled": False, "event_types": [], "destinations": []},
        }
        try:
            value = json.loads(self._settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return defaults
        enabled = value.get("enabled", {}) if isinstance(value, dict) else {}
        defaults["enabled"].update({key: bool(enabled.get(key, False)) for key in self.PLATFORMS})
        notification_settings = value.get("notifications", {}) if isinstance(value, dict) else {}
        if isinstance(notification_settings, dict):
            defaults["notifications"].update(notification_settings)
        configured_event_types = defaults["notifications"].get("event_types", [])
        if not isinstance(configured_event_types, list):
            configured_event_types = []
        defaults["notifications"]["event_types"] = [
            item for item in configured_event_types
            if isinstance(item, str) and item in {"incident_created", "finding_created", "approval_requested", "agent_error", "investigation_completed"}
        ]
        configured_destinations = defaults["notifications"].get("destinations", [])
        if not isinstance(configured_destinations, list):
            configured_destinations = []
        defaults["notifications"]["destinations"] = [
            item for item in configured_destinations if isinstance(item, str)
        ]
        return defaults

    def _load_deliveries(self) -> deque[dict[str, Any]]:
        try:
            values = json.loads(self._delivery_path.read_text(encoding="utf-8"))
            return deque((item for item in values if isinstance(item, dict)), maxlen=200)
        except (OSError, ValueError):
            return deque(maxlen=200)

    def _save_deliveries(self) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".communications-deliveries-", suffix=".tmp", dir=self.data_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(list(self._deliveries), handle, ensure_ascii=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._delivery_path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _save_settings(self) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".communications-settings-", suffix=".tmp", dir=self.data_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._settings, handle, ensure_ascii=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._settings_path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    async def start(self) -> None:
        self._stopping = False
        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=256)
        self._worker_task = asyncio.create_task(self._deliver_notifications(), name="svs-messaging-notifications")
        await asyncio.gather(*(self._start_account(platform, "default") for platform in self.PLATFORMS))
        self._retry_task = asyncio.create_task(self._retry_failed(), name="svs-messaging-retry")
        self._requeue_pending()

    async def stop(self) -> None:
        self._stopping = True
        if self._worker_task is not None:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        if self._retry_task is not None:
            self._retry_task.cancel()
            try:
                await self._retry_task
            except asyncio.CancelledError:
                pass
        async with self._lock:
            adapters = list(self._adapters.items())
            self._adapters.clear()
        for key, adapter in adapters:
            try:
                await adapter.stop()
                self._statuses[key] = {"status": "Disconnected", "error": ""}
            except Exception as exc:
                self._statuses[key] = {"status": "Error", "error": type(exc).__name__}

    async def _start_account(self, platform: str, account_id: str) -> None:
        key = (platform, account_id)
        if not self._settings["enabled"].get(platform, False):
            async with self._lock:
                disabled_adapter = self._adapters.pop(key, None)
            if disabled_adapter is not None:
                try:
                    await disabled_adapter.stop()
                except Exception:
                    pass
            self._statuses[key] = {"status": "Disconnected", "error": ""}
            return
        token = self.credentials.get(platform, account_id)
        if not token:
            status = "Authentication Required" if self.credentials.available() else "Configuration Invalid"
            self._statuses[key] = {"status": status, "error": "" if status == "Authentication Required" else "OS credential vault unavailable"}
            return
        async with self._lock:
            existing = self._adapters.get(key)
        if existing is not None:
            try:
                await existing.stop()
            except Exception:
                pass
            async with self._lock:
                self._adapters.pop(key, None)
        adapter_cls = DiscordChannelAdapter if platform == "discord" else TelegramChannelAdapter
        adapter = adapter_cls(token, self.gateway, self.identities, account_id=account_id)
        self._statuses[key] = {"status": "Connecting", "error": ""}
        async with self._lock:
            self._adapters[key] = adapter
        try:
            await adapter.start()
            self._statuses[key] = {"status": adapter.status, "error": ""}
        except asyncio.CancelledError:
            try:
                await adapter.stop()
            finally:
                async with self._lock:
                    self._adapters.pop(key, None)
                self._statuses[key] = {"status": "Disconnected", "error": ""}
            raise
        except Exception as exc:
            try:
                await adapter.stop()
            except Exception:
                pass
            async with self._lock:
                self._adapters.pop(key, None)
            status = adapter.status if adapter.status != "Disconnected" else "Error"
            self._statuses[key] = {"status": status, "error": type(exc).__name__}

    async def set_enabled(self, enabled: dict[str, bool]) -> dict[str, Any]:
        if set(enabled) - set(self.PLATFORMS):
            raise ValueError("unsupported communications platform")
        self._settings["enabled"].update({name: bool(enabled[name]) for name in enabled})
        self._save_settings()
        for platform in self.PLATFORMS:
            await self._start_account(platform, "default")
        return self.public_settings()

    async def set_credential(self, platform: str, account_id: str, token: str) -> None:
        if platform not in self.PLATFORMS:
            raise ValueError("unsupported communications platform")
        if account_id != "default":
            raise ValueError("only the default account is currently configurable")
        self.credentials.set(platform, account_id, token)
        if self._settings["enabled"].get(platform, False):
            await self._start_account(platform, account_id)
        else:
            self._statuses[(platform, account_id)] = {"status": "Disconnected", "error": ""}

    async def delete_credential(self, platform: str, account_id: str) -> None:
        if platform not in self.PLATFORMS:
            raise ValueError("unsupported communications platform")
        key = (platform, account_id)
        async with self._lock:
            adapter = self._adapters.pop(key, None)
        if adapter is not None:
            await adapter.stop()
        self.credentials.delete(platform, account_id)
        self._statuses[key] = {"status": "Authentication Required", "error": ""}

    def public_settings(self) -> dict[str, Any]:
        return {
            "enabled": dict(self._settings["enabled"]),
            "notifications": {
                "enabled": bool(self._settings["notifications"].get("enabled")),
                "event_types": list(self._settings["notifications"].get("event_types", [])),
                "destinations": list(self._settings["notifications"].get("destinations", [])),
            },
        }

    def status(self) -> dict[str, Any]:
        platforms = {}
        for platform in self.PLATFORMS:
            key = (platform, "default")
            info = self._statuses.get(key)
            if info is None:
                info = {"status": "Disconnected", "error": ""}
            adapter = self._adapters.get(key)
            if adapter is not None:
                info = {"status": adapter.status, "error": adapter.last_error}
            platforms[platform] = {"account_id": "default", **info}
        return {"settings": self.public_settings(), "platforms": platforms}

    def configure_notifications(self, value: dict[str, Any]) -> dict[str, Any]:
        allowed_types = {"incident_created", "finding_created", "approval_requested", "agent_error", "investigation_completed"}
        event_types = value.get("event_types", [])
        destinations = value.get("destinations", [])
        if not isinstance(event_types, list) or any(not isinstance(item, str) or item not in allowed_types for item in event_types):
            raise ValueError("unsupported notification event type")
        if not isinstance(destinations, list) or any(not isinstance(item, str) for item in destinations):
            raise ValueError("destinations must be a list of paired identity keys")
        paired = {
            self.destination_key(item)
            for item in self.identities.list_pairings()
        }
        if set(destinations) - paired:
            raise ValueError("notification destinations must be paired accounts")
        self._settings["notifications"] = {
            "enabled": bool(value.get("enabled", False)),
            "event_types": list(dict.fromkeys(event_types)),
            "destinations": list(dict.fromkeys(destinations)),
        }
        self._save_settings()
        self._requeue_pending()
        return self.public_settings()

    @staticmethod
    def destination_key(identity: dict[str, Any]) -> str:
        return ":".join((identity.get("channel", ""), identity.get("account_id", ""), identity.get("sender_id", "")))

    def paired_destinations(self) -> list[dict[str, str]]:
        return [
            {
                "key": self.destination_key(identity),
                "channel": str(identity.get("channel", "")),
                "account_id": str(identity.get("account_id", "")),
                "sender_id": str(identity.get("sender_id", "")),
                "role": str(identity.get("role", "viewer")),
            }
            for identity in self.identities.list_pairings()
        ]

    @staticmethod
    def _delivery_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
        return (str(record.get("event_id", "")), str(record.get("platform", "")),
                str(record.get("account_id", "")), str(record.get("sender_id", "")))

    def _find_delivery(self, event_id: str, identity: dict[str, Any]) -> dict[str, Any] | None:
        expected = (event_id, identity.get("channel", ""), identity.get("account_id", ""), identity.get("sender_id", ""))
        return next((item for item in reversed(self._deliveries) if self._delivery_key(item) == expected), None)

    def _event_is_delivered(self, event_id: str) -> bool:
        notifications = self._settings.get("notifications", {})
        targets = set(notifications.get("destinations", []))
        identities = [item for item in self.identities.list_pairings() if self.destination_key(item) in targets]
        return bool(identities) and all(
            (record := self._find_delivery(event_id, identity)) is not None and record.get("status") == "delivered"
            for identity in identities
        )

    def _requeue_pending(self) -> None:
        if (
            self._loop is None or self._queue is None
            or not self._settings.get("notifications", {}).get("enabled")
        ):
            return
        eligible_types = set(self._settings.get("notifications", {}).get("event_types", []))
        now = time.time()
        pending_events = set()
        for record in self._deliveries:
            try:
                recent = now - float(record.get("timestamp", 0)) <= 24 * 60 * 60
            except (TypeError, ValueError):
                recent = False
            if record.get("status") in {"pending", "offline", "failed"} and record.get("event_type") in eligible_types and recent:
                pending_events.add((str(record.get("event_id", "")), str(record.get("event_type", ""))))
        for event_id, event_type in pending_events:
            if event_id and not self._event_is_delivered(event_id):
                self._queue_event(event_id, event_type)

    def enqueue_event(self, event: Any) -> None:
        settings = self._settings.get("notifications", {})
        event_type = getattr(event, "type", "")
        event_id = getattr(event, "event_id", "")
        if (
            not settings.get("enabled")
            or event_type not in settings.get("event_types", [])
            or not settings.get("destinations")
            or not event_id
            or self._loop is None
            or self._queue is None
        ):
            return
        if event_id in self._queued_event_ids or self._event_is_delivered(event_id):
            return
        self._queued_event_ids.add(event_id)
        self._loop.call_soon_threadsafe(self._queue_event, event_id, event_type)

    def _queue_event(self, event_id: str, event_type: str) -> None:
        if self._queue is None:
            return
        try:
            self._queue.put_nowait((event_id, event_type))
        except asyncio.QueueFull:
            self._queued_event_ids.discard(event_id)
            selected = set(self._settings["notifications"].get("destinations", []))
            for identity in self.identities.list_pairings():
                if self.destination_key(identity) not in selected:
                    continue
                self._store_delivery({
                    "event_id": event_id,
                    "platform": identity["channel"],
                    "account_id": identity["account_id"],
                    "sender_id": identity["sender_id"],
                    "event_type": event_type,
                    "status": "failed",
                    "error": "QueueFull",
                    "timestamp": time.time(),
                })

    def _store_delivery(self, record: dict[str, Any]) -> None:
        existing = next((item for item in reversed(self._deliveries) if self._delivery_key(item) == self._delivery_key(record)), None)
        if existing is None:
            self._deliveries.append(record)
        else:
            existing.update(record)
        self._save_deliveries()

    async def _deliver_notifications(self) -> None:
        labels = {
            "incident_created": "A security incident was created",
            "finding_created": "A security finding is ready",
            "approval_requested": "A security action is waiting for review in the local SVS-Cyber UI",
            "agent_error": "The agent reported an execution error",
            "investigation_completed": "An investigation completed",
        }
        while True:
            event_id, event_type = await self._queue.get()
            try:
                if not self._settings.get("notifications", {}).get("enabled"):
                    continue
                targets = set(self._settings["notifications"].get("destinations", []))
                text = f"SVS-Cyber alert: {labels[event_type]}. Open the local application for details."
                for identity in self.identities.list_pairings():
                    key = self.destination_key(identity)
                    if key not in targets or identity.get("role") not in {"viewer", "analyst"}:
                        continue
                    platform, account_id = identity["channel"], identity["account_id"]
                    adapter = self._adapters.get((platform, account_id))
                    destination = identity.get("destination_id")
                    record = {"event_id": event_id, "platform": platform, "account_id": account_id,
                              "sender_id": identity["sender_id"], "event_type": event_type,
                              "status": "pending", "timestamp": time.time()}
                    existing = self._find_delivery(event_id, identity)
                    if existing is not None and existing.get("status") == "delivered":
                        continue
                    self._store_delivery(record)
                    if adapter is None or not destination:
                        record["status"] = "offline"
                    else:
                        try:
                            from .contracts import OutboundReply
                            for attempt in range(3):
                                try:
                                    await adapter.send_message(OutboundReply(platform, destination, text))
                                    record["status"] = "delivered"
                                    break
                                except Exception:
                                    if attempt == 2:
                                        record["status"] = "failed"
                                    else:
                                        await asyncio.sleep(0.5 * (2 ** attempt))
                        except Exception:
                            record["status"] = "failed"
                    self._store_delivery(record)
            except Exception as exc:
                self._store_delivery({
                    "event_id": event_id,
                    "event_type": event_type,
                    "status": "failed",
                    "error": type(exc).__name__,
                    "timestamp": time.time(),
                })
            finally:
                self._queue.task_done()
                self._queued_event_ids.discard(event_id)

    def delivery_history(self) -> list[dict[str, Any]]:
        return [dict(item) for item in list(self._deliveries)[-50:]]

    async def _retry_failed(self) -> None:
        while not self._stopping:
            await asyncio.sleep(30)
            for platform in self.PLATFORMS:
                key = (platform, "default")
                status = self._statuses.get(key, {}).get("status")
                if status in {"Error", "Rate Limited", "Connecting"} and self._settings["enabled"].get(platform):
                    await self._start_account(platform, "default")
            self._requeue_pending()


_manager: AdapterManager | None = None


def set_manager(manager: AdapterManager | None) -> None:
    global _manager
    _manager = manager


def get_manager() -> AdapterManager | None:
    return _manager
