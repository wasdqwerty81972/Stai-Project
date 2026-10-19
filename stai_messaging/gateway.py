"""Authorization, isolated sessions, and async routing for channel messages."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import tempfile
import threading
import time
import uuid
from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from .contracts import InboundMessage, OutboundReply

ROLES = frozenset({"viewer", "analyst"})


def session_id_for(inbound: InboundMessage) -> str:
    """Return a stable session unique to account, sender, destination, and thread."""
    scope = inbound.thread_id or ""
    parts = (inbound.channel, inbound.account_id, inbound.sender_id, inbound.destination_id or "", scope)
    # The opaque ids are platform supplied. Length-prefixing avoids delimiter collisions.
    return "remote:" + ":".join(f"{len(str(part))}-{part}" for part in parts)


class IdentityStore:
    """Small atomic JSON store for pairings and pending pairing requests.

    Secrets are deliberately kept out of this file; it contains platform identity
    ids and roles only. A caller may inject ``path`` for tests and deployments.
    """

    def __init__(self, path: str | os.PathLike[str], pairing_ttl: int = 600) -> None:
        self.path = Path(path)
        self.pairing_ttl = max(1, int(pairing_ttl))
        self._lock = threading.RLock()
        self._data: dict[str, Any] = {"paired": {}, "pending": {}, "dedupe": {}}
        self._load()

    @staticmethod
    def _identity_key(channel: str, account_id: str, sender_id: str) -> str:
        return json.dumps([channel, account_id, sender_id], ensure_ascii=True, separators=(",", ":"))

    def _load(self) -> None:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                self._data = {
                    "paired": {
                        key: item for key, item in (value.get("paired", {}) if isinstance(value.get("paired", {}), dict) else {}).items()
                        if isinstance(key, str) and isinstance(item, dict)
                    },
                    "pending": {
                        key: item for key, item in (value.get("pending", {}) if isinstance(value.get("pending", {}), dict) else {}).items()
                        if isinstance(key, str) and isinstance(item, dict)
                    },
                    "dedupe": {
                        key: item for key, item in (value.get("dedupe", {}) if isinstance(value.get("dedupe", {}), dict) else {}).items()
                        if isinstance(key, str) and isinstance(item, str)
                    },
                }
        except (OSError, ValueError):
            return

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".communications-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._data, handle, ensure_ascii=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def request_pairing(self, inbound: InboundMessage, now: Optional[datetime] = None) -> str:
        now = now or datetime.now(timezone.utc)
        request_id = uuid.uuid4().hex
        with self._lock:
            self._expire_locked(now)
            for key, existing in self._data["pending"].items():
                if (
                    existing.get("channel") == inbound.channel
                    and existing.get("account_id") == inbound.account_id
                    and existing.get("sender_id") == inbound.sender_id
                ):
                    return key
            if len(self._data["pending"]) >= 500:
                oldest = min(
                    self._data["pending"],
                    key=lambda item: self._data["pending"][item].get("requested_at", ""),
                )
                self._data["pending"].pop(oldest, None)
            self._data["pending"][request_id] = {
                "request_id": request_id,
                "channel": inbound.channel,
                "account_id": inbound.account_id,
                "sender_id": inbound.sender_id,
                "destination_id": inbound.destination_id,
                "requested_at": now.isoformat(),
                "expires_at": (now + timedelta(seconds=self.pairing_ttl)).isoformat(),
            }
            self._save()
        return request_id

    def _expire_locked(self, now: datetime) -> None:
        pending = self._data["pending"]
        for key, item in list(pending.items()):
            try:
                expired = datetime.fromisoformat(item["expires_at"]) <= now
            except (KeyError, TypeError, ValueError):
                expired = True
            if expired:
                pending.pop(key, None)

    def pending_requests(self, now: Optional[datetime] = None) -> list[dict[str, Any]]:
        with self._lock:
            self._expire_locked(now or datetime.now(timezone.utc))
            self._save()
            return [dict(item) for item in self._data["pending"].values()]

    def approve_pairing(self, request_id: str, role: str = "viewer", now: Optional[datetime] = None) -> bool:
        if not isinstance(role, str) or role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(sorted(ROLES))}")
        now = now or datetime.now(timezone.utc)
        with self._lock:
            self._expire_locked(now)
            request = self._data["pending"].pop(request_id, None)
            if request is None:
                self._save()
                return False
            key = self._identity_key(request["channel"], request["account_id"], request["sender_id"])
            self._data["paired"][key] = {
                "channel": request["channel"],
                "account_id": request["account_id"],
                "sender_id": request["sender_id"],
                "destination_id": request.get("destination_id"),
                "role": role,
                "approved_at": now.isoformat(),
            }
            self._save()
            return True

    def role_for(self, channel: str, account_id: str, sender_id: str) -> Optional[str]:
        with self._lock:
            record = self._data["paired"].get(self._identity_key(channel, account_id, sender_id))
            role = record.get("role") if isinstance(record, dict) else None
            return role if isinstance(role, str) and role in ROLES else None

    def revoke(self, channel: str, account_id: str, sender_id: str) -> bool:
        with self._lock:
            removed = self._data["paired"].pop(self._identity_key(channel, account_id, sender_id), None)
            if removed is not None:
                self._save()
            return removed is not None

    def list_pairings(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._data["paired"].values()]

    def claim_message(self, message_key: str, now: Optional[datetime] = None, ttl_seconds: int = 3600, limit: int = 8192) -> bool:
        """Persist an inbound idempotency claim so platform retries survive restarts."""
        now = now or datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=max(1, ttl_seconds))
        with self._lock:
            ledger = self._data["dedupe"]
            for key, raw_timestamp in list(ledger.items()):
                try:
                    if datetime.fromisoformat(raw_timestamp) <= cutoff:
                        ledger.pop(key, None)
                except (TypeError, ValueError):
                    ledger.pop(key, None)
            if message_key in ledger:
                return False
            ledger[message_key] = now.isoformat()
            while len(ledger) > max(1, limit):
                oldest = min(ledger, key=ledger.get)
                ledger.pop(oldest, None)
            self._save()
            return True


class Gateway:
    """Async single ingress for paired platform messages.

    Agent I/O runs in a worker thread; sends are awaited independently. Duplicate
    platform message ids are ignored, and in-flight work is capped.
    """

    def __init__(
        self,
        chat_client: Any,
        identities: IdentityStore,
        *,
        max_concurrency: int = 4,
        dedupe_limit: int = 8192,
        dedupe_ttl: float = 3600,
        messages_per_minute: int = 30,
    ) -> None:
        self.chat_client = chat_client
        self.identities = identities
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))
        self._dedupe_limit = max(1, dedupe_limit)
        self._dedupe_ttl = max(1.0, dedupe_ttl)
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._rates: dict[str, deque[float]] = {}
        self._messages_per_minute = max(1, messages_per_minute)
        self._seen_lock = threading.Lock()
        self.delivery_errors: list[dict[str, str]] = []

    @staticmethod
    def _message_key(inbound: InboundMessage) -> Optional[str]:
        if not inbound.message_id:
            return None
        return "\x1f".join((inbound.channel, inbound.account_id, inbound.destination_id or "", inbound.message_id))

    def _claim(self, inbound: InboundMessage) -> bool:
        key = self._message_key(inbound)
        if key is None:
            return True
        now = time.monotonic()
        with self._seen_lock:
            while self._seen and next(iter(self._seen.values())) <= now - self._dedupe_ttl:
                self._seen.popitem(last=False)
            if key in self._seen:
                return False
            self._seen[key] = now
            while len(self._seen) > self._dedupe_limit:
                self._seen.popitem(last=False)
            return True

    def _rate_allowed(self, inbound: InboundMessage) -> bool:
        key = "\x1f".join((inbound.channel, inbound.account_id, inbound.sender_id))
        now = time.monotonic()
        with self._seen_lock:
            timestamps = self._rates.setdefault(key, deque())
            while timestamps and timestamps[0] <= now - 60:
                timestamps.popleft()
            if len(timestamps) >= self._messages_per_minute:
                return False
            timestamps.append(now)
            if len(self._rates) > self._dedupe_limit:
                for stale in list(self._rates)[: len(self._rates) - self._dedupe_limit]:
                    self._rates.pop(stale, None)
            return True

    async def handle(self, inbound: InboundMessage, adapter: Any) -> Optional[OutboundReply]:
        role = self.identities.role_for(inbound.channel, inbound.account_id, inbound.sender_id)
        if role is None:
            return None
        persistent_key = self._message_key(inbound)
        if persistent_key and not await asyncio.to_thread(
            self.identities.claim_message,
            persistent_key,
            None,
            int(self._dedupe_ttl),
            self._dedupe_limit,
        ):
            return None
        if not self._claim(inbound) or not self._rate_allowed(inbound):
            return None
        if not inbound.text.strip():
            return None
        if inbound.attachments:
            return None
        normalized = inbound.text.strip().lower()
        if role == "viewer":
            if normalized not in {"/status", "/help"}:
                return None
            reply_text = (
                "SVS-Cyber gateway is online. Use /status or /help. "
                "Ask an administrator to grant analyst access for agent conversations."
                if normalized == "/status"
                else "Commands: /status, /help. Pairing is managed in SVS-Cyber settings."
            )
            reply = OutboundReply(inbound.channel, inbound.thread_id or inbound.destination_id, reply_text, inbound.message_id)
            sender = getattr(adapter, "send_message", None)
            result = sender(reply) if sender is not None else adapter.send(reply)
            if inspect.isawaitable(result):
                await result
            return reply
        async with self._semaphore:
            session_id = session_id_for(inbound)
            try:
                reply_text = await asyncio.to_thread(self.chat_client.chat, inbound.text, session_id)
            except Exception as exc:
                self.delivery_errors.append({"channel": inbound.channel, "error": type(exc).__name__})
                self.delivery_errors[:] = self.delivery_errors[-100:]
                reply_text = "SVS-Cyber could not complete that request. Check the local application for agent status."
            reply = OutboundReply(
                channel=inbound.channel,
                thread_id=inbound.thread_id or inbound.destination_id,
                text=str(reply_text),
                in_reply_to=inbound.message_id,
            )
            try:
                sender = getattr(adapter, "send_message", None)
                if sender is not None:
                    result = sender(reply)
                else:
                    result = adapter.send(reply)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                self.delivery_errors.append({"channel": inbound.channel, "error": type(exc).__name__})
                self.delivery_errors[:] = self.delivery_errors[-100:]
                return reply
            return reply


class CredentialStore:
    """OS keyring wrapper that never falls back to plaintext token storage."""

    SERVICE_NAME = "svs-cyber-communications"

    @staticmethod
    def available() -> bool:
        try:
            import keyring
            backend = keyring.get_keyring()
            return float(getattr(backend, "priority", 0)) > 0
        except Exception:
            return False

    def set(self, platform: str, account_id: str, token: str) -> None:
        try:
            import keyring
        except ImportError as exc:
            raise RuntimeError("Install the communications dependencies to use secure credential storage") from exc
        if not self.available():
            raise RuntimeError("No secure operating-system credential vault is available")
        if not token.strip():
            raise ValueError("credential cannot be empty")
        keyring.set_password(self.SERVICE_NAME, f"{platform}:{account_id}", token.strip())

    def get(self, platform: str, account_id: str = "default") -> Optional[str]:
        try:
            import keyring
            return keyring.get_password(self.SERVICE_NAME, f"{platform}:{account_id}")
        except Exception:
            return None

    def delete(self, platform: str, account_id: str = "default") -> None:
        try:
            import keyring
        except ImportError:
            return
        try:
            keyring.delete_password(self.SERVICE_NAME, f"{platform}:{account_id}")
        except Exception:
            pass
