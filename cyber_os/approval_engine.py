"""
cyber_os/approval_engine.py — Policy Boundaries & Argv Prefix Approval Grants

Enforces strict authorization boundaries for defensive cybersecurity operations.
Supports session-scoped argv prefix approval rules while preventing shell escape
injections (pipes, command chaining, backticks, redirection, environment expansions).

Adapted from mature agent approval grant architecture for SVS-Cyber.

Safety Principles:
- Read-only diagnostic tools can be auto-approved per policy.
- Modifying, destructive, or kernel-intervention operations require explicit human approval.
- An analyst can grant a reusable argv prefix rule for safe command repetition within a session.
- Prefix rules containing shell control characters (; | & < > ` $ % ( ) { } \n \r) are strictly rejected.
"""

from __future__ import annotations

import shlex
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

# Characters that enable shell chaining, subshells, redirection, or variable expansion
DISALLOWED_PREFIX_CHARACTERS: Set[str] = {
    ";",
    "|",
    "&",
    "<",
    ">",
    "`",
    "$",
    "%",
    "^",
    "*",
    "?",
    "[",
    "]",
    "(",
    ")",
    "{",
    "}",
    "\n",
    "\r",
    "\0",
}


class ApprovalDecision(str, Enum):
    AUTO_APPROVED = "auto_approved"
    GRANTED = "granted"
    SESSION_PREFIX_MATCH = "session_prefix_match"
    PENDING = "pending"
    DENIED = "denied"
    TIMED_OUT = "timed_out"


@dataclass
class PrefixGrant:
    prefix_tokens: List[str]
    session_id: str
    granted_at: str
    action_type: str = "terminal_command"


class ApprovalEngine:
    """Manages active approval requests, persistent session prefix grants, and safety audits."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # session_id -> list of PrefixGrant
        self._session_grants: Dict[str, List[PrefixGrant]] = {}
        # request_id -> (threading.Event, Dict result)
        self._pending_requests: Dict[str, Tuple[threading.Event, Dict[str, Any]]] = {}

    def is_prefix_rule_safe(self, prefix_rule: List[str]) -> Tuple[bool, str]:
        """Validates that a proposed prefix rule contains no shell injection vectors."""
        if not prefix_rule:
            return False, "Prefix rule cannot be empty."
        if len(prefix_rule) > 16:
            return False, "Prefix rule exceeds maximum token length (16)."

        for token in prefix_rule:
            if not token or len(token) > 256:
                return False, "Invalid token length in prefix rule."
            for char in token:
                if char in DISALLOWED_PREFIX_CHARACTERS:
                    return False, f"Prefix rule contains disallowed shell control character: {char!r}"

        return True, "Valid"

    def tokenize_command(self, command: str) -> List[str]:
        """Splits a command line safely into argv tokens."""
        try:
            # POSIX=False preserves Windows-style quotes and paths
            return shlex.split(command, posix=False)
        except Exception:
            return command.strip().split()

    def check_session_grant(self, session_id: str, command: str) -> bool:
        """Checks whether an executed command matches any pre-approved prefix rule for this session."""
        tokens = self.tokenize_command(command)
        if not tokens:
            return False

        with self._lock:
            grants = self._session_grants.get(session_id, [])
            for grant in grants:
                prefix = grant.prefix_tokens
                if len(tokens) >= len(prefix):
                    if tokens[:len(prefix)] == prefix:
                        return True
        return False

    def register_prefix_grant(self, session_id: str, prefix_rule: List[str]) -> Tuple[bool, str]:
        """Registers an analyst-approved prefix rule for the current session."""
        is_safe, reason = self.is_prefix_rule_safe(prefix_rule)
        if not is_safe:
            return False, reason

        grant = PrefixGrant(
            prefix_tokens=list(prefix_rule),
            session_id=session_id,
            granted_at=datetime.now(timezone.utc).isoformat(),
        )

        with self._lock:
            if session_id not in self._session_grants:
                self._session_grants[session_id] = []
            self._session_grants[session_id].append(grant)

        return True, f"Prefix grant registered for {prefix_rule}"

    def clear_session_grants(self, session_id: str) -> None:
        """Clears all granted prefix rules when an investigation session concludes."""
        with self._lock:
            self._session_grants.pop(session_id, None)

    def resolve_approval_request(
        self,
        request_id: str,
        approved: bool,
        prefix_rule: Optional[List[str]] = None,
        session_id: str = "default",
    ) -> bool:
        """Resolves a pending UI approval request and registers a prefix grant if requested."""
        if approved and prefix_rule:
            self.register_prefix_grant(session_id, prefix_rule)

        with self._lock:
            if request_id in self._pending_requests:
                event, result = self._pending_requests[request_id]
                result["approved"] = approved
                result["resolved_at"] = datetime.now(timezone.utc).isoformat()
                event.set()
                return True
        return False

    def wait_for_human_approval(
        self,
        request_id: str,
        timeout: float = 300.0,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Blocks worker thread until human approval is received via event or timeout fires."""
        event = threading.Event()
        result: Dict[str, Any] = {"approved": False, "timeout": False}

        with self._lock:
            self._pending_requests[request_id] = (event, result)

        finished = event.wait(timeout=timeout)

        with self._lock:
            self._pending_requests.pop(request_id, None)

        if not finished:
            result["timeout"] = True
            result["approved"] = False

        return result["approved"], result

    def has_shell_injection(self, command: str) -> bool:
        """Checks if a command contains shell injection characters (| ; & < > ` $ () {} etc)."""
        for char in DISALLOWED_PREFIX_CHARACTERS:
            if char in command:
                return True
        return False

    def add_grant(self, prefix: str | List[str], session_id: str = "default") -> Tuple[bool, str]:
        """Convenience method to register a prefix grant from string or token list."""
        tokens = prefix if isinstance(prefix, list) else self.tokenize_command(prefix)
        return self.register_prefix_grant(session_id, tokens)

    def is_approved(self, command: str, session_id: str = "default") -> bool:
        """Convenience method to check if a command is approved for the session."""
        return self.check_session_grant(session_id, command)
